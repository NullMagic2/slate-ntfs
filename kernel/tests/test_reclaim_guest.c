/*
 * Module: kernel.tests.reclaim_guest
 * Purpose: Measure concurrent namespace work during bounded orphan reclamation.
 * Created: 2026-10-21
 * Architecture: The private VM runner supplies a complex deletion fixture;
 * real mounted syscalls and trace markers verify progress and surviving bytes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>

enum {
    PATH_BYTES = 4096,
    BLOCK_BYTES = 4096,
    CREATOR_THREADS = 2,
    CREATOR_ITERATIONS = 128,
    LEDGER_BLOCKS = 64,
    LOOKUP_SAMPLES = 2048,
    LOOKUP_PAUSE_US = 2000,
    DIRECTORY_SYNC_INTERVAL = 8,
    PERCENTILE_99 = 99,
    PERCENTILE_SCALE = 100,
    TRACE_LINE_BYTES = 256,
    FILE_MODE = 0600,
    DIRECTORY_MODE = 0700,
    SECONDS_NS = 1000000000,
    MINIMUM_LOAD_SECONDS = 8,
};
static const uint64_t operation_limit_ns = 2ULL * SECONDS_NS;
static const char target_name[] = "compressed-capacity-source";
static const unsigned char witness_value = 'Q';
static const char *root;
static pthread_barrier_t start;
static atomic_bool finished;
static atomic_uint creators_done;
static atomic_bool ledger_done;
static uint64_t samples[LOOKUP_SAMPLES];
static unsigned int sample_count;
static uint64_t lookup_count;
static uint64_t max_lookup_ns;
static int marker;

static void require(bool success, const char *operation)
{
    if (!success) {
        fprintf(stderr, "D27_FAILED %s: %s\n", operation, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static uint64_t now(void)
{
    struct timespec time;

    require(!clock_gettime(CLOCK_MONOTONIC, &time), "monotonic clock");
    return (uint64_t)time.tv_sec * SECONDS_NS + time.tv_nsec;
}

static void join(char *out, const char *name)
{
    int length = snprintf(out, PATH_BYTES, "%s/%s", root, name);

    require(length >= 0 && length < PATH_BYTES, "test path");
}

static void trace(const char *name, uint64_t value)
{
    char line[TRACE_LINE_BYTES];
    int length = snprintf(line, sizeof(line), "D27_%s value=%" PRIu64 "\n", name, value);

    require(length > 0 && (size_t)length < sizeof(line), "trace marker length");
    require(write(marker, line, length) == length, "trace marker");
}

static void write_block(int fd, unsigned char value, off_t offset)
{
    unsigned char bytes[BLOCK_BYTES];

    memset(bytes, value, sizeof(bytes));
    require(pwrite(fd, bytes, sizeof(bytes), offset) == sizeof(bytes), "write block");
}

static void check_block(int fd, unsigned char value, off_t offset)
{
    unsigned char bytes[BLOCK_BYTES];

    require(pread(fd, bytes, sizeof(bytes), offset) == sizeof(bytes), "read block");
    for (size_t index = 0; index < sizeof(bytes); index++)
        require(bytes[index] == value, "block content");
}

static void *creator(void *argument)
{
    unsigned int number = (uintptr_t)argument;
    char name[PATH_BYTES];
    char directory[PATH_BYTES];
    int directory_fd;

    snprintf(name, sizeof(name), "d27-worker-%u", number);
    join(directory, name);
    require(!mkdir(directory, DIRECTORY_MODE), "create worker directory");
    directory_fd = open(directory, O_RDONLY | O_DIRECTORY);
    require(directory_fd >= 0, "open worker directory");
    pthread_barrier_wait(&start);
    for (unsigned int index = 0; index < CREATOR_ITERATIONS; index++) {
        unsigned char value = 'a' + number;
        int fd = openat(directory_fd, "source", O_CREAT | O_EXCL | O_RDWR, FILE_MODE);

        require(fd >= 0, "concurrent create");
        write_block(fd, value, 0);
        require(!fsync(fd), "concurrent fsync");
        require(!renameat(directory_fd, "source", directory_fd, "destination"), "concurrent rename");
        require(!unlinkat(directory_fd, "destination", 0), "concurrent unlink open file");
        check_block(fd, value, 0);
        require(!close(fd), "concurrent last close");
        if (index % DIRECTORY_SYNC_INTERVAL == 0) {
            require(!fsync(directory_fd), "concurrent directory fsync");
            trace("CREATOR_FSYNC", index);
        }
    }
    require(!fsync(directory_fd) && !close(directory_fd), "finish worker directory");
    require(!rmdir(directory), "remove worker directory");
    atomic_fetch_add(&creators_done, 1);
    return NULL;
}

static void *ledger(void *argument)
{
    char name[PATH_BYTES];
    int fd;

    (void)argument;
    join(name, "d27-ledger.bin");
    fd = open(name, O_CREAT | O_EXCL | O_RDWR, FILE_MODE);
    require(fd >= 0, "create durable ledger");
    pthread_barrier_wait(&start);
    for (unsigned int index = 0; index < LEDGER_BLOCKS; index++) {
        write_block(fd, index, (off_t)index * BLOCK_BYTES);
        require(!fsync(fd), "ledger fsync");
        check_block(fd, index, (off_t)index * BLOCK_BYTES);
        if (index % DIRECTORY_SYNC_INTERVAL == 0)
            trace("LEDGER_FSYNC", index);
    }
    require(!close(fd), "close durable ledger");
    atomic_store(&ledger_done, true);
    return NULL;
}

static void *reader(void *argument)
{
    char name[PATH_BYTES];
    char missing[PATH_BYTES];
    struct stat info;
    int fd;

    (void)argument;
    join(name, "d27-witness.bin");
    fd = open(name, O_RDONLY);
    require(fd >= 0, "open immutable witness");
    pthread_barrier_wait(&start);
    while (!atomic_load(&finished)) {
        uint64_t before = now();
        uint64_t elapsed;

        snprintf(missing, sizeof(missing), "d27-missing-%" PRIu64, lookup_count);
        join(name, missing);
        errno = 0;
        require(lstat(name, &info) < 0 && errno == ENOENT, "uncached unrelated lookup");
        check_block(fd, witness_value, 0);
        elapsed = now() - before;
        if (sample_count < LOOKUP_SAMPLES) {
            samples[sample_count++] = elapsed;
            trace("LOOKUP", elapsed);
        }
        if (elapsed > max_lookup_ns)
            max_lookup_ns = elapsed;
        lookup_count++;
        usleep(LOOKUP_PAUSE_US);
    }
    require(!close(fd), "close witness reader");
    return NULL;
}

static int compare(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;

    return (a > b) - (a < b);
}

int main(int argc, char **argv)
{
    pthread_t creators[CREATOR_THREADS];
    pthread_t ledger_thread;
    pthread_t reader_thread;
    char name[PATH_BYTES];
    struct statfs initial;
    struct statfs final;
    uint64_t began;
    uint64_t deletion_ns;
    int fd;

    require(argc == 2, "mountpoint argument");
    root = argv[1];
    marker = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    require(marker >= 0, "open trace markers");
    join(name, "d27-witness.bin");
    fd = open(name, O_CREAT | O_EXCL | O_WRONLY, FILE_MODE);
    require(fd >= 0, "create witness");
    write_block(fd, witness_value, 0);
    require(!fsync(fd) && !close(fd), "persist witness");
    require(!statfs(root, &initial), "initial allocation");
    require(!pthread_barrier_init(&start, NULL, CREATOR_THREADS + 3), "start barrier");
    for (uintptr_t index = 0; index < CREATOR_THREADS; index++)
        require(!pthread_create(&creators[index], NULL, creator, (void *)index), "start creator");
    require(!pthread_create(&ledger_thread, NULL, ledger, NULL), "start ledger");
    require(!pthread_create(&reader_thread, NULL, reader, NULL), "start reader");
    pthread_barrier_wait(&start);
    began = now();
    trace("DELETE_BEGIN", began);
    join(name, target_name);
    fd = open(name, O_RDONLY);
    require(fd >= 0, "open complex target");
    require(!unlink(name), "unlink complex target");
    require(!close(fd), "last close complex target");
    deletion_ns = now() - began;
    trace("CLOSE_DONE", deletion_ns);
    for (unsigned int index = 0; index < CREATOR_THREADS; index++)
        require(!pthread_join(creators[index], NULL), "join creator");
    require(!pthread_join(ledger_thread, NULL), "join ledger");
    while (now() - began < (uint64_t)MINIMUM_LOAD_SECONDS * SECONDS_NS)
        usleep(LOOKUP_PAUSE_US);
    atomic_store(&finished, true);
    require(!pthread_join(reader_thread, NULL), "join reader");
    require(atomic_load(&creators_done) == CREATOR_THREADS && atomic_load(&ledger_done), "worker completion");
    require(lookup_count && sample_count, "lookup progress");
    require(max_lookup_ns < operation_limit_ns && deletion_ns < operation_limit_ns, "bounded foreground latency");
    require(!statfs(root, &final), "final allocation");
    qsort(samples, sample_count, sizeof(samples[0]), compare);
    printf("D27_METRICS {\"lookups\":%" PRIu64 ",\"sample_count\":%u,\"lookup_p50_ns\":%" PRIu64
           ",\"lookup_p99_ns\":%" PRIu64 ",\"lookup_max_ns\":%" PRIu64
           ",\"last_close_ns\":%" PRIu64 ",\"worker_deletions\":%u,\"fsync_blocks\":%u"
           ",\"free_before\":%llu,\"free_after_load\":%llu}\n",
           lookup_count, sample_count, samples[sample_count / 2],
           samples[(sample_count - 1) * PERCENTILE_99 / PERCENTILE_SCALE],
           max_lookup_ns, deletion_ns, CREATOR_THREADS * CREATOR_ITERATIONS, LEDGER_BLOCKS,
           (unsigned long long)initial.f_bfree, (unsigned long long)final.f_bfree);
    trace("LOAD_DONE", lookup_count);
    require(!close(marker), "close trace marker");
    puts("D27_WORKLOAD_PASS");
    return EXIT_SUCCESS;
}
