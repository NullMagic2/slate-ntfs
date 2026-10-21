/*
 * Module: kernel.tests.hard_link_deletion
 * Purpose: Verify surviving hard links and last-close deletion on a private mount.
 * Created: 2026-10-21
 * Architecture: Exercises real VFS callbacks; retained witness links let Windows
 * independently verify identity, link counts and contents after clean unmount.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    ALIAS_COUNT = 24,
    ALIAS_PADDING = 160,
    RESIDENT_BYTES = 64,
    PAYLOAD_BYTES = 8192,
    DIRECTORY_MODE = 0770,
    FILE_MODE = 0660,
    WITNESS_LINKS = 3,
    PARENT_COUNT = 2,
};
static const unsigned char payload_byte = 'H';
static const char *const witness_names[WITNESS_LINKS] = {
    "keep-a.bin", "keep-b.bin", "keep-c.bin",
};

static void require(bool success, const char *operation)
{
    if (!success) {
        fprintf(stderr, "D04 failure: %s: %s\n", operation, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void join(char *result, const char *parent, const char *name)
{
    int length = snprintf(result, PATH_MAX, "%s/%s", parent, name);

    require(length >= 0 && length < PATH_MAX, "path length");
}

static int create_payload(const char *path, size_t length)
{
    unsigned char payload[PAYLOAD_BYTES];
    int file = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, FILE_MODE);

    require(file >= 0, "exclusive create");
    memset(payload, payload_byte, length);
    require(write(file, payload, length) == (ssize_t)length, "payload write");
    require(fsync(file) == 0, "payload fsync");
    return file;
}

static void check_file(int file, size_t length, nlink_t links, ino_t identity)
{
    unsigned char payload[PAYLOAD_BYTES];
    struct stat status;

    require(fstat(file, &status) == 0, "fstat");
    require(status.st_ino == identity, "hard-link inode identity");
    require(status.st_nlink == links, "hard-link count");
    require(status.st_size == (off_t)length, "surviving data size");
    require(pread(file, payload, length, 0) == (ssize_t)length, "surviving data read");
    for (size_t index = 0; index < length; index++)
        require(payload[index] == payload_byte, "surviving data contents");
}

static void deletion_case(const char *root, const char *case_name, size_t length)
{
    char folder[PATH_MAX], first[PATH_MAX], second[PATH_MAX], original[PATH_MAX];
    char aliases[ALIAS_COUNT][PATH_MAX];
    struct stat status;

    join(folder, root, case_name);
    require(mkdir(folder, DIRECTORY_MODE) == 0, "case directory");
    join(first, folder, "first");
    join(second, folder, "second");
    require(mkdir(first, DIRECTORY_MODE) == 0, "first parent");
    require(mkdir(second, DIRECTORY_MODE) == 0, "second parent");
    join(original, first, "original.bin");
    int held = create_payload(original, length);

    require(fstat(held, &status) == 0, "initial identity");
    ino_t identity = status.st_ino;
    for (size_t index = 0; index < ALIAS_COUNT; index++) {
        char name[NAME_MAX + 1];
        char padding[ALIAS_PADDING + 1];

        memset(padding, 'x', ALIAS_PADDING);
        padding[ALIAS_PADDING] = '\0';
        snprintf(name, sizeof(name), "link-%02zu-%s", index, padding);
        join(aliases[index], index % PARENT_COUNT ? first : second, name);
        require(link(original, aliases[index]) == 0, "cross-parent hard link");
    }
    require(unlink(original) == 0, "remove original name first");
    check_file(held, length, ALIAS_COUNT, identity);
    require(access(original, F_OK) == -1 && errno == ENOENT, "original name absent");
    for (size_t index = 0; index < ALIAS_COUNT; index++) {
        int alias = open(aliases[index], O_RDONLY | O_CLOEXEC);

        require(alias >= 0, "surviving alias open");
        check_file(alias, length, ALIAS_COUNT - index, identity);
        require(close(alias) == 0, "close surviving alias");
        require(unlink(aliases[index]) == 0, "remove alias");
        require(access(aliases[index], F_OK) == -1 && errno == ENOENT, "deleted alias absent");
        check_file(held, length, ALIAS_COUNT - index - 1, identity);
    }
    require(close(held) == 0, "last close");
    require(rmdir(first) == 0, "empty first parent");
    require(rmdir(second) == 0, "empty second parent");
    require(rmdir(folder) == 0, "empty case directory");
}

static void retain_witness(const char *root)
{
    char original[PATH_MAX], path[PATH_MAX];
    struct stat status;

    join(original, root, witness_names[0]);
    int file = create_payload(original, PAYLOAD_BYTES);

    require(fstat(file, &status) == 0, "witness identity");
    for (size_t index = 1; index < WITNESS_LINKS; index++) {
        join(path, root, witness_names[index]);
        require(link(original, path) == 0, "retained witness link");
    }
    check_file(file, PAYLOAD_BYTES, WITNESS_LINKS, status.st_ino);
    require(close(file) == 0, "witness close");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s NEW_DIRECTORY_ON_DISPOSABLE_MOUNT\n", argv[0]);
        return EXIT_FAILURE;
    }
    require(mkdir(argv[1], DIRECTORY_MODE) == 0, "exclusive test directory");
    deletion_case(argv[1], "resident-deleted", RESIDENT_BYTES);
    deletion_case(argv[1], "nonresident-deleted", PAYLOAD_BYTES);
    retain_witness(argv[1]);
    sync();
    puts("D04_HARD_LINK_DELETION_PASS");
    return EXIT_SUCCESS;
}
