/*
 * Module: kernel.tests.shutdown_guest
 * Purpose: Exercise open-orphan logout and failed writes in an isolated VM.
 * Created: 2026-10-21
 * Architecture: The shutdown VM runner owns mounts and power transitions;
 * this process checks the real mounted syscalls and their error results.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    PATH_BYTES = 4096,
    BLOCK_BYTES = 4096,
    SURVIVOR_BLOCKS = 2,
    VICTIM_BLOCKS = 32,
    DELETION_FILES = 64,
    DISCONNECT_ATTEMPTS = 400,
    POLL_MICROSECONDS = 100000,
};

static volatile sig_atomic_t running = 1;

static void fail(const char *operation)
{
    perror(operation);
    exit(EXIT_FAILURE);
}

static void stop(int signal_number)
{
    (void)signal_number;
    running = 0;
}

static void path(char *out, const char *root, const char *name)
{
    if (snprintf(out, PATH_BYTES, "%s/%s", root, name) >= PATH_BYTES) {
        errno = ENAMETOOLONG;
        fail("fixture path");
    }
}

static void create(const char *name, unsigned int blocks, unsigned char value)
{
    unsigned char data[BLOCK_BYTES];
    int fd = open(name, O_CREAT | O_TRUNC | O_WRONLY, 0600);

    if (fd < 0)
        fail("create fixture");
    memset(data, value, sizeof(data));
    for (unsigned int block = 0; block < blocks; block++) {
        if (write(fd, data, sizeof(data)) != sizeof(data))
            fail("write fixture");
    }
    if (fsync(fd) || close(fd))
        fail("persist fixture");
}

static void hold(const char *root)
{
    char name[PATH_BYTES];
    char temporary[PATH_BYTES];
    unsigned char byte;
    int fd;

    path(name, root, "survivor.bin");
    create(name, SURVIVOR_BLOCKS, 'D');
    path(name, root, "victim.bin");
    create(name, VICTIM_BLOCKS, 'V');
    fd = open(name, O_RDONLY);
    if (fd < 0 || unlink(name))
        fail("unlink open victim");
    for (unsigned int index = 0; index < DELETION_FILES; index++) {
        char leaf[BLOCK_BYTES];

        snprintf(leaf, sizeof(leaf), "pending-%u", index);
        path(temporary, root, leaf);
        create(temporary, 1, 'P');
        if (unlink(temporary))
            fail("queue deletion");
    }
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    create("/run/d26/ready", 0, 0);
    puts("D26_SESSION_READY");
    fflush(stdout);
    while (running) {
        if (pread(fd, &byte, sizeof(byte), 0) != sizeof(byte) || byte != 'V')
            fail("read unlinked handle");
        usleep(POLL_MICROSECONDS);
    }
    if (close(fd))
        fail("close victim");
    unlink("/run/d26/ready");
    puts("D26_SESSION_CLOSED");
}

static void expect_io_error(int result, const char *operation)
{
    if (result >= 0 || errno != EIO) {
        fprintf(stderr, "%s: expected EIO, got result=%d errno=%d\n", operation, result, errno);
        exit(EXIT_FAILURE);
    }
}

static void unplug(const char *root)
{
    char name[PATH_BYTES];
    int fd;
    int error = 0;

    path(name, root, "survivor.bin");
    fd = open(name, O_RDWR);
    if (fd < 0 || fsync(fd))
        fail("open durable survivor");
    puts("D26_UNPLUG_READY");
    fflush(stdout);
    for (unsigned int attempt = 0; attempt < DISCONNECT_ATTEMPTS; attempt++) {
        if (pwrite(fd, "D", 1, 0) != 1 || fsync(fd)) {
            error = errno;
            break;
        }
        usleep(POLL_MICROSECONDS);
    }
    if (error != EIO) {
        errno = error;
        fail("disconnect did not report EIO");
    }
    expect_io_error(pwrite(fd, "D", 1, 0), "write after failure");
    expect_io_error(fsync(fd), "fsync after failure");
    path(name, root, "must-not-exist");
    expect_io_error(open(name, O_CREAT | O_WRONLY, 0600), "create after failure");
    close(fd);
    puts("D26_IO_REFUSAL_PASS");
}

static void exercise(const char *root)
{
    char source[PATH_BYTES];
    char target[PATH_BYTES];
    int fd = open(root, O_TMPFILE | O_RDWR, 0600);

    path(target, root, "published-temporary");
    if (fd < 0 || write(fd, "T", 1) != 1 || fsync(fd) ||
        linkat(fd, "", AT_FDCWD, target, AT_EMPTY_PATH) || close(fd))
        fail("publish temporary file");
    path(source, root, "replacement-source");
    path(target, root, "replacement-target");
    create(source, 1, 'S');
    create(target, 1, 'R');
    fd = open(target, O_RDONLY);
    if (fd < 0 || rename(source, target) || close(fd))
        fail("replace open destination");
    puts("D26_TEMPORARY_AND_REPLACEMENT_PASS");
}

static void verify_file(const char *root, const char *leaf, size_t size, unsigned char value)
{
    char name[PATH_BYTES];
    unsigned char data[BLOCK_BYTES];
    int fd;

    path(name, root, leaf);
    fd = open(name, O_RDONLY);
    if (fd < 0)
        fail("open surviving file");
    while (size) {
        size_t count = size < sizeof(data) ? size : sizeof(data);

        if (read(fd, data, count) != (ssize_t)count)
            fail("read surviving file");
        for (size_t offset = 0; offset < count; offset++) {
            if (data[offset] != value) {
                errno = EIO;
                fail("surviving content changed");
            }
        }
        size -= count;
    }
    if (read(fd, data, 1) != 0 || close(fd))
        fail("surviving file length");
}

static void verify(const char *root)
{
    char name[PATH_BYTES];

    verify_file(root, "survivor.bin", SURVIVOR_BLOCKS * BLOCK_BYTES, 'D');
    verify_file(root, "published-temporary", 1, 'T');
    verify_file(root, "replacement-target", BLOCK_BYTES, 'S');
    path(name, root, "victim.bin");
    errno = 0;
    if (!access(name, F_OK) || errno != ENOENT)
        fail("deleted victim remains");
    path(name, root, "after-recovery");
    create(name, 1, 'A');
    if (unlink(name))
        fail("delete after recovery");
    puts("D26_SURVIVORS_AND_REUSE_PASS");
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s hold|unplug|exercise|verify MOUNTPOINT\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (!strcmp(argv[1], "hold"))
        hold(argv[2]);
    else if (!strcmp(argv[1], "unplug"))
        unplug(argv[2]);
    else if (!strcmp(argv[1], "exercise"))
        exercise(argv[2]);
    else if (!strcmp(argv[1], "verify"))
        verify(argv[2]);
    else
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
