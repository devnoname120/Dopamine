#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <choma/CSBlob.h>
#include <choma/Fat.h>
#include <choma/Host.h>
#include <mach/machine.h>
#include "../BaseBin/libjailbreak/src/signatures.h"

typedef uint8_t cdhash_t[20];
typedef struct {
    uint32_t Count;
    uint32_t *Types;
    uint32_t *Subtypes;
} preferredArchInfo;

int recurse_collect_untrusted_cdhashes(const char *path, const char *callerImagePath,
                                       const char *callerExecutablePath, const char *workingDir,
                                       preferredArchInfo *preferredArch, cdhash_t **cdhashesOut,
                                       uint32_t *cdhashCountOut);

static const char *scenario;
static const char *replacement_path;
static bool replacement_done;
static const char *expected_arch_component;
static bool saw_expected_dependency;
static bool saw_wrong_dependency;
static const char *root_path;
static uint64_t observed_root_offset = UINT64_MAX;
static uint64_t observed_dep_offset = UINT64_MAX;
static unsigned trust_signature_calls;

bool isRemovableBundlePath(const char *path) { (void)path; return false; }
bool hasTrollstoreLiteMarker(const char *path) { (void)path; return false; }
bool string_has_prefix(const char *string, const char *prefix)
{
    return strncmp(string, prefix, strlen(prefix)) == 0;
}
bool is_cdhash_trustcached(cdhash_t hash)
{
    (void)hash;
    return strcmp(scenario, "already-trusted") == 0;
}
bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob)
{
    CS_DecodedBlob *wrapper = csd_superblob_find_blob(superblob, CSSLOT_SIGNATURESLOT, NULL);
    return !wrapper || csd_blob_get_size(wrapper) <= 8;
}
void ensure_jbroot_symlink(const char *path) { (void)path; }
int ensure_randomized_cdhash_for_slice(const char *path, uint64_t offset, void *cdhashOut);

int trust_signatures(int pid, int fd, struct siginfo *sigInfos, uint32_t sigInfoCount)
{
    (void)pid;
    if (!sigInfos || sigInfoCount != 1 || sigInfos[0].source != SIGNATURE_SOURCE_ALLOCATION) return 93;
    trust_signature_calls++;
    if (!strcmp(scenario, "normalization-failure")) return 94;
    char path[PATH_MAX] = {0};
    if (fcntl(fd, F_GETPATH, path) != 0) return 95;
    cdhash_t ignored = {0};
    return ensure_randomized_cdhash_for_slice(path, sigInfos[0].signature.fs_file_start, ignored);
}

int ensure_randomized_cdhash_for_slice(const char *path, uint64_t offset, void *cdhashOut)
{
    if (!strncmp(scenario, "arch-", 5)) {
        if (root_path && !strcmp(path, root_path)) observed_root_offset = offset;
        else if (strstr(path, "/libdep.dylib")) observed_dep_offset = offset;
    }
    if (!strcmp(scenario, "branding-failure")) return 77;
    if (!strcmp(scenario, "replacement") && replacement_path && !replacement_done) {
        replacement_done = true;
        if (rename(replacement_path, path) != 0) return 78;
    }
    if (!strncmp(scenario, "arch-", 5) && strstr(path, "/libleaf.dylib")) {
        if (expected_arch_component && strstr(path, expected_arch_component)) saw_expected_dependency = true;
        else saw_wrong_dependency = true;
    }
    memset(cdhashOut, 0x5a, 20);
    return 0;
}

int main(int argc, const char **argv)
{
    if (argc < 3) return 2;
    scenario = argv[1];
    root_path = argv[2];
    replacement_path = argc > 3 ? argv[3] : NULL;

    preferredArchInfo preferred = {0};
    uint32_t type = CPU_TYPE_ARM64;
    uint32_t subtype = 0;
    if (!strcmp(scenario, "arch-arm64")) {
        subtype = CPU_SUBTYPE_ARM64_ALL;
        preferred = (preferredArchInfo){1, &type, &subtype};
        // An arm64 executable on arm64e hardware still loads the host-preferred
        // arm64e dylib slice. Keep the main executable on arm64, but trust the
        // dependency slice dyld will actually map.
        expected_arch_component = "/arm64e/";
    } else if (!strcmp(scenario, "arch-arm64e")) {
        subtype = CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2;
        preferred = (preferredArchInfo){1, &type, &subtype};
        expected_arch_component = "/arm64e/";
    } else if (!strcmp(scenario, "arch-arm64e-generic")) {
        subtype = CPU_SUBTYPE_ARM64E;
        preferred = (preferredArchInfo){1, &type, &subtype};
        expected_arch_component = "/arm64e/";
    }
    cdhash_t *hashes = NULL;
    uint32_t count = 0;
    int result = recurse_collect_untrusted_cdhashes(argv[2], NULL, argv[2], NULL,
                                                    &preferred, &hashes, &count);
    free(hashes);

    if (strcmp(scenario, "required-missing") && result == 0 && trust_signature_calls == 0) {
        fprintf(stderr, "%s: recursive trust did not invoke the shared signature contract\n", scenario);
        return 1;
    }

    if (!strncmp(scenario, "arch-", 5)) {
        uint32_t main_subtype = !strcmp(scenario, "arch-arm64") ? CPU_SUBTYPE_ARM64_ALL :
                                (CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
        uint32_t dep_subtype = CPU_SUBTYPE_ARM64E;
        Fat *main_fat = fat_init_from_path(argv[2]);
        NSString *dep_path = [[NSString stringWithUTF8String:argv[2]].stringByDeletingLastPathComponent stringByAppendingPathComponent:@"libdep.dylib"];
        Fat *dep_fat = fat_init_from_path(dep_path.fileSystemRepresentation);
        MachO *main_slice = main_fat ? fat_find_slice(main_fat, CPU_TYPE_ARM64, main_subtype) : NULL;
        MachO *dep_slice = dep_fat ? fat_find_slice(dep_fat, CPU_TYPE_ARM64, dep_subtype) : NULL;
        uint64_t expected_root_offset = main_slice ? main_slice->archDescriptor.offset : UINT64_MAX;
        uint64_t expected_dep_offset = dep_slice ? dep_slice->archDescriptor.offset : UINT64_MAX;
        bool offsets_match = observed_root_offset == expected_root_offset && observed_dep_offset == expected_dep_offset;
        if (main_fat) fat_free(main_fat);
        if (dep_fat) fat_free(dep_fat);
        if (result != 0 || !saw_expected_dependency || saw_wrong_dependency || !offsets_match) {
            fprintf(stderr, "%s: result=%d expected_dep=%d wrong_dep=%d root=%llu/%llu dep=%llu/%llu\n",
                    scenario, result, saw_expected_dependency, saw_wrong_dependency,
                    observed_root_offset, expected_root_offset, observed_dep_offset, expected_dep_offset);
            return 1;
        }
        return 0;
    }

    bool should_fail = !strcmp(scenario, "required-missing") ||
                       !strcmp(scenario, "branding-failure") ||
                       !strcmp(scenario, "normalization-failure") ||
                       !strcmp(scenario, "replacement");
    if (should_fail != (result != 0)) {
        fprintf(stderr, "%s: result=%d count=%u expected_failure=%d\n",
                scenario, result, count, should_fail);
        return 1;
    }
    printf("%s: result=%d count=%u\n", scenario, result, count);
    return 0;
}
