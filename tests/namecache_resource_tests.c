#include <sys/types.h>
#include <sys/queue.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdarg.h>
#include <setjmp.h>

LIST_HEAD(klist, fixture_knote);
typedef void *kauth_cred_t;
typedef void *mount_t;
static struct { struct { uint64_t slide; } kernelConstant; } gSystemInfo;
static uint64_t symbol_nchashtbl, symbol_nchashmask;
#define ksymbol(name) ((uint64_t)&symbol_##name)
#define UNSIGN_PTR(value) (value)

static const char *scenario;
static bool descriptors[4096];
static unsigned next_descriptor = 10, live_descriptors, tail_files, bad_lifetimes, diagnostic_reads;
static unsigned unconditional_prints, reads, unlink_calls, writes, directory_fd, file_fd;
static unsigned writer_locks, writer_unlocks, lock_depth, vnode_refs, vnode_reles;
static bool counter_publish_refused_once;
static int tail_fd = -1;
static char tail_name[PATH_MAX];
static jmp_buf escape;
static unsigned escaped;
static uint64_t symbol_namecache_rw_lock, symbol_lck_rw_lock_exclusive, symbol_lck_rw_done;
static uint64_t symbol_vnode_ref_ext, symbol_vnode_rele_ext;

static int fixture_open(const char *path, int flags, ...);
static int fixture_close(int fd);
static int fixture_unlink(const char *path);
static int fixture_mkstemp(char *path);
static int fixture_fcntl(int fd, int command, void *argument);
static uint32_t fixture_random(void) { static uint32_t value; return ++value; }
static int fixture_printf(const char *format, ...) { unconditional_prints++; return 0; }
static void fixture_debug(const char *format, ...) {}
static uint64_t proc_self(void) { return 1; }
static int kreadbuf(uint64_t address, void *output, size_t size);
static uint8_t kread8(uint64_t address);
static uint64_t kread64(uint64_t address);
static int kwrite32(uint64_t address, uint32_t value);
static int kwrite64(uint64_t address, uint64_t value);
static bool is_kcall_available(void) { return true; }
static bool is_kcall_initialized(void) { return true; }
static int kcall(uint64_t *result, uint64_t function, int argc, const uint64_t *arguments);
static char *basename_r(const char *path, char *output)
{
    const char *name = strrchr(path, '/');
    strcpy(output, name ? name + 1 : path);
    return output;
}
#define open fixture_open
#define close fixture_close
#define unlink fixture_unlink
#define mkstemp fixture_mkstemp
#define fcntl fixture_fcntl
#define arc4random fixture_random
#define printf fixture_printf
#ifdef ENABLE_LOGS
#define JBLogDebug fixture_debug
#else
#define JBLogDebug(...) ((void)0)
#endif
#define JBLogError fixture_debug

#include "implementation.h"

#undef open
#undef close
#undef unlink
#undef mkstemp
#undef fcntl
#undef arc4random
#undef printf

static struct vnode directory_node, file_node, parent_node, tail_node;
static struct namecache file_cache, tail_cache, child_cache, hash_cache;
static uint64_t hash_bucket, old_hash_bucket, list_slot;
static struct vnode original_file_node, original_parent_node;
static struct namecache original_file_cache, original_tail_cache, original_hash_cache;
static uint64_t original_old_hash_bucket, original_hash_bucket, original_list_slot;

static bool is_case(const char *name) { return !strcmp(scenario, name); }
static int allocate_descriptor(bool tail)
{
    int fd = tail && is_case("tail-fd-zero") ? 0 : (int)next_descriptor++;
    if ((unsigned)fd >= sizeof(descriptors) / sizeof(descriptors[0]) || descriptors[fd]) {
        bad_lifetimes++;
        return -1;
    }
    descriptors[fd] = true;
    live_descriptors++;
    if (tail) tail_fd = fd;
    return fd;
}
static int fixture_open(const char *path, int flags, ...)
{
    if (flags & O_CREAT) {
        if (is_case("tail-open-refused")) { errno = EMFILE; return -1; }
        snprintf(tail_name, sizeof(tail_name), "%s", path);
        tail_files++;
        return allocate_descriptor(true);
    }
    if (!strcmp(path, "/fixture/dir")) {
        if (is_case("dir-open-refused")) { errno = EACCES; return -1; }
        return (int)(directory_fd = allocate_descriptor(false));
    }
    if (!strcmp(path, "/fixture/file")) {
        if (is_case("file-open-refused")) { errno = EACCES; return -1; }
        return (int)(file_fd = allocate_descriptor(false));
    }
    if (is_case("new-open-refused")) { errno = EACCES; return -1; }
    return allocate_descriptor(false);
}
static int fixture_mkstemp(char *path)
{
    if (is_case("tail-open-refused")) { errno = EMFILE; return -1; }
    snprintf(path, PATH_MAX, "/tmp/fixture-tail-%u", fixture_random());
    snprintf(tail_name, sizeof(tail_name), "%s", path);
    tail_files++;
    return allocate_descriptor(true);
}
static int fixture_close(int fd)
{
    if (fd < 0 || (unsigned)fd >= sizeof(descriptors) / sizeof(descriptors[0]) || !descriptors[fd]) {
        bad_lifetimes++;
        errno = EBADF;
        return -1;
    }
    descriptors[fd] = false;
    live_descriptors--;
    return 0;
}
static int fixture_unlink(const char *path)
{
    unlink_calls++;
    if (strcmp(path, tail_name) || !tail_files) { bad_lifetimes++; errno = ENOENT; return -1; }
    tail_files--;
    return 0;
}
static int fixture_fcntl(int fd, int command, void *argument)
{
    if (is_case("getpath-refused")) { errno = EIO; return -1; }
    if (command != F_GETPATH || !descriptors[fd]) { bad_lifetimes++; return -1; }
    strcpy(argument, "/fixture/dir/file");
    return 0;
}
uint64_t proc_fd_vnode(uint64_t process, int fd)
{
    if (!descriptors[fd]) { bad_lifetimes++; return 0; }
    if (fd == tail_fd) return is_case("tail-vnode-refused") ? 0 : (uint64_t)&tail_node;
    if ((unsigned)fd == directory_fd) return is_case("dir-vnode-refused") ? 0 : (uint64_t)&directory_node;
    if ((unsigned)fd == file_fd) return is_case("file-vnode-refused") ? 0 : (uint64_t)&file_node;
    return 0;
}
static void require_live_tail(void)
{
    if (tail_fd < 0 || !descriptors[tail_fd] || !tail_files) bad_lifetimes++;
    if (++reads > 2000) { escaped++; longjmp(escape, 1); }
}
static int kreadbuf(uint64_t address, void *output, size_t size)
{
    require_live_tail();
    if (address == (uint64_t)&child_cache || address == (uint64_t)&hash_cache ||
        address == (uint64_t)&tail_node || address == (uint64_t)&tail_cache) diagnostic_reads++;
    memcpy(output, (void *)address, size);
    return 0;
}
static uint8_t kread8(uint64_t address)
{
    require_live_tail();
    diagnostic_reads++;
    return *(uint8_t *)address;
}
static uint64_t kread64(uint64_t address)
{
    require_live_tail();
    uint64_t value;
    memcpy(&value, (void *)address, sizeof(value));
    return value;
}
static int kwrite32(uint64_t address, uint32_t value)
{
    require_live_tail();
#if FIXTURE_VERSION == 2
    if (is_case("counter-publish-refused") && address == (uint64_t)&file_cache.nc_counter &&
        value == 3 && !counter_publish_refused_once) {
        counter_publish_refused_once = true;
        errno = EIO;
        return -1;
    }
#endif
    if (is_case("write-refused") && writes++ == 3) { errno = EIO; return -1; }
    if (!is_case("write-refused")) writes++;
    memcpy((void *)address, &value, sizeof(value));
    return 0;
}
static int kwrite64(uint64_t address, uint64_t value)
{
    require_live_tail();
    if (is_case("write-refused") && writes++ == 3) { errno = EIO; return -1; }
    if (!is_case("write-refused")) writes++;
    memcpy((void *)address, &value, sizeof(value));
    return 0;
}
static int kcall(uint64_t *result, uint64_t function, int argc, const uint64_t *arguments)
{
    if (!arguments) return -1;
    if (function == (uint64_t)&symbol_vnode_ref_ext) {
        if (argc != 3) return -1;
        if (result) *result = 0;
        if (is_case("vnode-ref-refused") && vnode_refs == 1) {
            if (result) *result = EBUSY;
            return 0;
        }
        vnode_refs++;
        return 0;
    }
    if (function == (uint64_t)&symbol_vnode_rele_ext) {
        if (argc != 3) return -1;
        vnode_reles++;
        if (result) *result = 0;
        return 0;
    }
    if (argc != 1 || arguments[0] != (uint64_t)&symbol_namecache_rw_lock) return -1;
    if (function == (uint64_t)&symbol_lck_rw_lock_exclusive) {
        if (is_case("writer-lock-refused")) return -1;
        writer_locks++;
        lock_depth++;
        if (is_case("stale-under-lock")) old_hash_bucket = 0;
        return 0;
    }
    if (function == (uint64_t)&symbol_lck_rw_done) {
        writer_unlocks++;
        if (!lock_depth) return -1;
        lock_depth--;
        return 0;
    }
    return -1;
}
void init_crc32(void) {}
unsigned int hash_string(const char *name, int length) { return 0; }

static void prepare_model(void)
{
    memset(&directory_node, 0, sizeof(directory_node));
    memset(&file_node, 0, sizeof(file_node));
    memset(&parent_node, 0, sizeof(parent_node));
    memset(&tail_node, 0, sizeof(tail_node));
    memset(&file_cache, 0, sizeof(file_cache));
    memset(&tail_cache, 0, sizeof(tail_cache));
    memset(&child_cache, 0, sizeof(child_cache));
    memset(&hash_cache, 0, sizeof(hash_cache));
    directory_node.v_ncchildren.tqh_first = (void *)&child_cache;
    directory_node.v_id = 0;
    file_node.v_nclinks.lh_first = (void *)&file_cache;
    file_node.v_parent = &parent_node;
    tail_node.v_nclinks.lh_first = (void *)&tail_cache;
    file_cache.nc_entry.tqe_next = &tail_cache;
    list_slot = (uint64_t)&file_cache;
    file_cache.nc_entry.tqe_prev = (void *)&list_slot;
    tail_cache.nc_entry.tqe_prev = &file_cache.nc_entry.tqe_next;
    parent_node.v_ncchildren.tqh_first = (__typeof__(parent_node.v_ncchildren.tqh_first))&file_cache;
    parent_node.v_ncchildren.tqh_last = (__typeof__(parent_node.v_ncchildren.tqh_last))&file_cache.nc_child.tqe_next;
    file_cache.nc_child.tqe_next = NULL;
    file_cache.nc_child.tqe_prev = (__typeof__(file_cache.nc_child.tqe_prev))&parent_node.v_ncchildren.tqh_first;
    file_cache.nc_un.nc_link.le_next = NULL;
    file_cache.nc_un.nc_link.le_prev = (void *)&file_node.v_nclinks.lh_first;
    file_cache.nc_dvp = &parent_node;
    file_cache.nc_vp = &file_node;
    file_cache.nc_hashval = 0;
#if FIXTURE_VERSION == 2
    file_cache.nc_counter = 1;
    old_hash_bucket = (uint64_t)&file_cache.nc_hash;
    file_cache.nc_hash.le_prev = (struct smrq_link **)&old_hash_bucket;
#else
    old_hash_bucket = (uint64_t)&file_cache;
    file_cache.nc_hash.le_prev = (void *)&old_hash_bucket;
#endif
    child_cache.nc_name = "child";
    hash_cache.nc_name = "hash";
    if (is_case("child-cycle")) child_cache.nc_child.tqe_next = &child_cache;
#if FIXTURE_VERSION == 2
    hash_bucket = (uint64_t)&hash_cache.nc_hash;
    hash_cache.nc_hash.le_prev = (struct smrq_link **)&hash_bucket;
    if (is_case("hash-cycle")) hash_cache.nc_hash.le_next = &hash_cache.nc_hash;
#else
    hash_bucket = (uint64_t)&hash_cache;
    hash_cache.nc_hash.le_prev = (void *)&hash_bucket;
    if (is_case("hash-cycle")) hash_cache.nc_hash.le_next = &hash_cache;
#endif
    symbol_nchashtbl = (uint64_t)&hash_bucket;
    symbol_nchashmask = 0;
    tail_fd = -1;
    tail_name[0] = 0;
    reads = 0;
    writes = 0;
    writer_locks = writer_unlocks = lock_depth = vnode_refs = vnode_reles = 0;
    counter_publish_refused_once = false;
    original_file_node = file_node;
    original_parent_node = parent_node;
    original_file_cache = file_cache;
    original_tail_cache = tail_cache;
    original_hash_cache = hash_cache;
    original_old_hash_bucket = old_hash_bucket;
    original_hash_bucket = hash_bucket;
    original_list_slot = list_slot;
}

static bool original_topology_restored(void)
{
    struct namecache expected_file = original_file_cache;
#if FIXTURE_VERSION == 2
    expected_file.nc_counter = file_cache.nc_counter;
#endif
    return memcmp(&file_node, &original_file_node, sizeof(file_node)) == 0 &&
           memcmp(&parent_node, &original_parent_node, sizeof(parent_node)) == 0 &&
           memcmp(&file_cache, &expected_file, sizeof(file_cache)) == 0 &&
           memcmp(&tail_cache, &original_tail_cache, sizeof(tail_cache)) == 0 &&
           memcmp(&hash_cache, &original_hash_cache, sizeof(hash_cache)) == 0 &&
           old_hash_bucket == original_old_hash_bucket && hash_bucket == original_hash_bucket &&
           list_slot == original_list_slot;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    scenario = argv[1];
    unsigned failures = 0;
    unsigned iterations = is_case("repeated") ? 16 : 1;
    for (unsigned i = 0; i < iterations; i++) {
        prepare_model();
        int result = -2;
        if (setjmp(escape) == 0) result = UNSANDBOX_IMPL("/fixture/dir", "/fixture/file");
        bool expected_failure = (strstr(scenario, "refused") != NULL && !is_case("getpath-refused") &&
                                 !is_case("counter-publish-refused")) || is_case("stale-under-lock");
#if FIXTURE_VERSION == 2
        expected_failure = expected_failure || is_case("counter-publish-refused");
#endif
        failures += result != (expected_failure ? -1 : 0);
        failures += live_descriptors != 0 || tail_files != 0 || bad_lifetimes || escaped;
        if (!expected_failure) failures += vnode_refs != 3 || vnode_reles != 0;
        if (expected_failure && vnode_refs) failures += vnode_reles != vnode_refs;
        if (strstr(scenario, "writer-") || is_case("stale-under-lock") || is_case("write-refused") ||
            is_case("new-open-refused") || is_case("getpath-refused")) {
            failures += lock_depth != 0;
            if (!is_case("writer-lock-refused")) failures += writer_locks == 0 || writer_unlocks == 0;
        }
        if (is_case("write-refused") || is_case("new-open-refused")) {
            failures += !original_topology_restored();
        }
#if FIXTURE_VERSION == 2
        if (is_case("counter-publish-refused")) failures += !original_topology_restored();
        if (!expected_failure) failures += file_cache.nc_counter != 3;
        if (is_case("write-refused") || is_case("new-open-refused") || is_case("counter-publish-refused")) {
            failures += (file_cache.nc_counter & 1U) == 0;
        }
#endif
#ifndef ENABLE_LOGS
        failures += diagnostic_reads != 0 || unconditional_prints != 0;
#endif
        if (escaped) break;
    }
    printf("%s: live_fds=%u files=%u bad_lifetimes=%u diagnostic_reads=%u prints=%u escaped=%u "
           "locks=%u unlocks=%u depth=%u refs=%u reles=%u restored=%u counter=%u failures=%u\n",
           scenario, live_descriptors, tail_files, bad_lifetimes, diagnostic_reads, unconditional_prints, escaped,
           writer_locks, writer_unlocks, lock_depth, vnode_refs, vnode_reles, original_topology_restored(),
#if FIXTURE_VERSION == 2
           file_cache.nc_counter,
#else
           0U,
#endif
           failures);
    return failures ? 1 : 0;
}
