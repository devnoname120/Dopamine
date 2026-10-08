#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>

#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "line %d: %s\n", __LINE__, #cond); return 1; } } while (0)
#define JBROOT_PATH(path) "/fixture/jbroot" path

static void roothide_bootlog(const char *line) { (void)line; }

static bool preference;
static bool forced_path;
static const char *fixture_path;
static int dyld_calls;
static int bootstrap_calls;
static int csflag_calls;
static int bootstrap_result;

static bool dyld_patch_enabled(void) { return preference; }
static bool process_force_dyld_patch(const char *path, const char **argv)
{
    (void)path; (void)argv;
    return forced_path;
}
static char *proc_get_path(pid_t pid, char path[PATH_MAX])
{
    (void)pid;
    strcpy(path, fixture_path);
    return path;
}
static int proc_patch_dyld(pid_t pid) { (void)pid; dyld_calls++; return 11; }
static int proc_bootstrap_dyld(pid_t pid) { (void)pid; bootstrap_calls++; return bootstrap_result; }
static int proc_patch_csflags(pid_t pid) { (void)pid; csflag_calls++; return 22; }
static bool fixture_isSubPathOf(const char *child, const char *parent)
{
    size_t parentLength = strlen(parent);
    return child && strncmp(child, parent, parentLength) == 0 && child[parentLength] == '/';
}
#define isSubPathOf fixture_isSubPathOf

#include "implementation.h"

static void reset(void)
{
    preference = forced_path = false;
    fixture_path = "/System/Library/PrivateFrameworks/IMCore.framework/IMTransferAgent";
    dyld_calls = bootstrap_calls = csflag_calls = 0;
    bootstrap_result = 0;
    unsetenv(ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV);
}

int main(void)
{
    reset();
    CHECK(!roothide_systemhook_dyld_fallback_enabled());
    CHECK(roothide_patch_proc(42) == 22 && csflag_calls == 1 && dyld_calls == 0 && bootstrap_calls == 0);

    reset();
    CHECK(setenv(ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV, "1", 1) == 0);
    CHECK(roothide_systemhook_dyld_fallback_enabled());
    CHECK(roothide_patch_proc(42) == 22 && bootstrap_calls == 0 && dyld_calls == 0 && csflag_calls == 1);

    reset();
    CHECK(setenv(ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV, "1", 1) == 0);
    fixture_path = "/fixture/jbroot/usr/bin/ssh";
    CHECK(roothide_patch_proc(42) == 0 && bootstrap_calls == 1 && dyld_calls == 0 && csflag_calls == 0);

    reset();
    CHECK(setenv(ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV, "1", 1) == 0);
    fixture_path = "/fixture/jbroot/usr/bin/ssh";
    bootstrap_result = -1;
    CHECK(roothide_patch_proc(42) == 11 && bootstrap_calls == 1 && dyld_calls == 1 && csflag_calls == 0);

    reset();
    preference = true;
    CHECK(roothide_patch_proc(42) == 11 && dyld_calls == 1 && bootstrap_calls == 0 && csflag_calls == 0);

    reset();
    forced_path = true;
    CHECK(roothide_patch_proc(42) == 11 && dyld_calls == 1 && bootstrap_calls == 0 && csflag_calls == 0);

    reset();
    CHECK(setenv(ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV, "1", 1) == 0);
    preference = true;
    CHECK(roothide_patch_proc(42) == 11 && dyld_calls == 1 && bootstrap_calls == 0 && csflag_calls == 0);

    reset();
    CHECK(setenv(ROOTHIDE_SYSTEMHOOK_DYLD_FALLBACK_ENV, "1", 1) == 0);
    forced_path = true;
    CHECK(roothide_patch_proc(42) == 11 && dyld_calls == 1 && bootstrap_calls == 0 && csflag_calls == 0);

    puts("8 systemhook loader policy cases passed");
    return 0;
}
