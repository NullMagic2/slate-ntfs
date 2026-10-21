/*
 * Module: kernel.tests.legacy_name_deletion
 * Purpose: Check real VFS mutations of unescaped legacy names on a private image.
 * Created: 2026-10-21
 * Architecture: Consumes the legacy_names writer fixture, checks lookup identity
 * and contents, and leaves only legal witness links for independent Windows checks.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char case_prefix[] = "d06-case-";
static const char legacy_data[] = "legacy filename payload";
static const char canonical_data[] = "canonical filename payload";
enum { EXPECTED_CASES = 15, EXTRA_LINKS = 32, FILE_MODE = 0660, BUFFER_BYTES = 128 };

static void require(bool condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "D06 failure: %s: %s\n", operation, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void join(char *result, const char *parent, const char *name)
{
    int size = snprintf(result, PATH_MAX, "%s/%s", parent, name);

    require(size >= 0 && size < PATH_MAX, "path length");
}

static void contents(const char *path, const char *expected)
{
    char buffer[BUFFER_BYTES];
    int file = open(path, O_RDONLY | O_CLOEXEC);

    require(file >= 0, "open named file");
    ssize_t size = read(file, buffer, sizeof(buffer));

    require(size == (ssize_t)strlen(expected) && !memcmp(buffer, expected, size), "named file contents");
    require(close(file) == 0, "close named file");
}

static void child_path(const char *folder, char *path, const char *expected)
{
    DIR *directory = opendir(folder);
    struct dirent *entry;
    size_t count = 0;

    require(directory != NULL, "open legacy parent");
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        require(count++ == 0, "single legacy child");
        if (expected)
            require(!strcmp(entry->d_name, expected), "stored case-only spelling");
        join(path, folder, entry->d_name);
    }
    require(closedir(directory) == 0 && count == 1, "legacy enumeration");
}

static void legacy_case(const char *folder, size_t ordinal)
{
    char path[PATH_MAX], renamed[PATH_MAX], normalized[PATH_MAX];

    child_path(folder, path, NULL);
    contents(path, legacy_data);
    if (ordinal % 2) {
        join(renamed, folder, "Normalized");
        join(normalized, folder, "normalized");
        require(rename(path, renamed) == 0, "rename legacy source");
        contents(renamed, legacy_data);
        require(rename(renamed, normalized) == 0, "case-only rename");
        child_path(folder, path, "normalized");
        contents(normalized, legacy_data);
        require(unlink(normalized) == 0, "unlink normalized file");
    } else {
        require(unlink(path) == 0, "unlink legacy file");
    }
    require(rmdir(folder) == 0, "remove empty legacy parent");
}

static void collisions(const char *root)
{
    char folder[PATH_MAX], path[PATH_MAX], renamed[PATH_MAX], replacement[PATH_MAX];

    join(folder, root, "d06-collision");
    join(path, folder, "same?name");
    join(renamed, folder, "canonical-renamed");
    join(replacement, folder, "replacement-source");
    contents(path, canonical_data);
    require(rename(path, renamed) == 0, "canonical spelling wins collision");
    contents(path, legacy_data);
    require(syscall(SYS_renameat2, AT_FDCWD, path, AT_FDCWD, renamed, RENAME_EXCHANGE) == 0, "exchange legacy name");
    contents(path, canonical_data);
    contents(renamed, legacy_data);
    int file = open(replacement, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, FILE_MODE);

    require(file >= 0, "create replacement source");
    require(write(file, canonical_data, strlen(canonical_data)) == (ssize_t)strlen(canonical_data), "replacement contents");
    require(close(file) == 0, "replacement close");
    require(rename(replacement, path) == 0, "replace legacy target");
    contents(path, canonical_data);
    contents(renamed, legacy_data);
    require(unlink(path) == 0 && unlink(renamed) == 0, "collision cleanup");
    require(rmdir(folder) == 0, "collision parent cleanup");
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s DISPOSABLE_LEGACY_FIXTURE_MOUNT\n", argv[0]);
        return EXIT_FAILURE;
    }
    DIR *directory = opendir(argv[1]);
    struct dirent *entry;
    size_t count = 0;
    char folders[EXPECTED_CASES][PATH_MAX];

    require(directory != NULL, "open fixture root");
    while ((entry = readdir(directory))) {
        if (!strncmp(entry->d_name, case_prefix, sizeof(case_prefix) - 1)) {
            require(count < EXPECTED_CASES, "fixture directory count");
            join(folders[count++], argv[1], entry->d_name);
        }
    }
    require(closedir(directory) == 0 && count == EXPECTED_CASES, "all fixture cases enumerated");
    for (size_t index = 0; index < count; index++)
        legacy_case(folders[index], index);
    collisions(argv[1]);
    char seed[PATH_MAX];
    struct stat status;

    join(seed, argv[1], "d06-seed");
    contents(seed, legacy_data);
    require(stat(seed, &status) == 0 && status.st_nlink == EXTRA_LINKS + 1, "surviving extension-family links");
    sync();
    puts("D06_LEGACY_NAME_DELETION_PASS");
    return EXIT_SUCCESS;
}
