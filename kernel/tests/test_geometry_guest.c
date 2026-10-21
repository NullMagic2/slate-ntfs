/*
 * Module: kernel.tests.geometry_guest
 * Purpose: Check mounted deletion, preserved contents and allocation reuse.
 * Created: 2026-10-21
 * Architecture: Runs only against private geometry fixtures in the test guest.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <unistd.h>

static const size_t test_files = 256;
static const size_t payload_bytes = 64;
static const size_t witness_bytes = 8192;
static const size_t free_space_divisor = 2;
static const uid_t test_uid = 1000;
static const gid_t test_gid = 1000;

static void check(int success, const char *operation)
{
    if (!success) {
        fprintf(stderr, "D28_FAIL:%s:%s\n", operation, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void witness(int root, const char *name, unsigned char expected)
{
    int fd = openat(root, name, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        return;
    }
    check(fd >= 0, "open-witness");
    unsigned char *bytes = malloc(witness_bytes);
    check(bytes != NULL, "allocate-witness");
    check(read(fd, bytes, witness_bytes) == (ssize_t)witness_bytes, "read-witness");
    for (size_t index = 0; index < witness_bytes; index++) {
        check(bytes[index] == expected, "witness-content");
    }
    check(close(fd) == 0, "close-witness");
    free(bytes);
}

/* Collect names before unlinking so directory cursor changes cannot hide a child. */
static void remove_directory(int root, const char *name)
{
    int fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        return;
    }
    check(fd >= 0, "open-directory");
    DIR *directory = fdopendir(fd);
    check(directory != NULL, "enumerate-directory");
    char **names = NULL;
    size_t count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
            continue;
        }
        char **next = realloc(names, (count + 1) * sizeof(*names));
        check(next != NULL, "allocate-names");
        names = next;
        names[count] = strdup(entry->d_name);
        check(names[count] != NULL, "copy-name");
        count++;
    }
    check(errno == 0, "read-directory");
    for (size_t index = 0; index < count; index++) {
        check(unlinkat(fd, names[index], 0) == 0, "unlink-child");
        free(names[index]);
    }
    free(names);
    check(fsync(fd) == 0, "sync-empty-directory");
    check(closedir(directory) == 0, "close-directory");
    check(unlinkat(root, name, AT_REMOVEDIR) == 0, "remove-directory");
    printf("D28_REMOVED:%s:%zu\n", name, count);
}

int main(int argc, char **argv)
{
    check(argc == 2, "arguments");
    check(setgid(test_gid) == 0 && setuid(test_uid) == 0, "credentials");
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(root >= 0, "open-root");
    witness(root, "scattered-witness.bin", 'S');
    witness(root, "geometry-witness.bin", 'G');
    remove_directory(root, "scattered-directory");
    remove_directory(root, "geometry-directory");
    remove_directory(root, "scattered-allocation");
    int removed = unlinkat(root, "full-filler.bin", 0);
    check(removed == 0 || errno == ENOENT, "remove-full-filler");
    check(mkdirat(root, "mounted-geometry", S_IRWXU) == 0, "create-directory");
    int parent = openat(root, "mounted-geometry", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(parent >= 0, "open-created-directory");
    struct statvfs space;
    check(fstatvfs(root, &space) == 0, "free-space");
    size_t data_files = space.f_bavail / free_space_divisor;
    if (data_files > test_files) {
        data_files = test_files;
    }
    unsigned char *payload = malloc(payload_bytes);
    check(payload != NULL, "allocate-payload");
    memset(payload, 'M', payload_bytes);
    for (size_t index = 0; index < test_files; index++) {
        char *name = NULL;
        check(asprintf(&name, "mounted-%04zu-long-name-for-index-growth-and-deletion", index) >= 0, "format-name");
        int fd = openat(parent, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
        check(fd >= 0, "create-file");
        if (index < data_files) {
            check(write(fd, payload, payload_bytes) == (ssize_t)payload_bytes, "write-file");
        }
        check(close(fd) == 0, "close-file");
        free(name);
    }
    free(payload);
    check(fsync(parent) == 0, "sync-created-directory");
    check(close(parent) == 0, "close-created-directory");
    remove_directory(root, "mounted-geometry");
    witness(root, "scattered-witness.bin", 'S');
    witness(root, "geometry-witness.bin", 'G');
    check(fsync(root) == 0, "sync-root");
    check(close(root) == 0, "close-root");
    printf("D28_CREATED:%zu:DATA:%zu\n", test_files, data_files);
    puts("D28_GUEST_PASS");
    return EXIT_SUCCESS;
}
