#include <stdbool.h>
#include <stdio.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "failed at line %d\n", __LINE__); return 1; } } while (0)

static bool insideJbroot;
static bool installedApp;
static bool blacklisted;
static int blacklistStatus;

static bool path_is_within_jbroot(const char *path) { (void)path; return insideJbroot; }
static bool isRemovableBundlePath(const char *path) { (void)path; return installedApp; }
static bool jbclient_blacklist_check_path(const char *path) { (void)path; return blacklisted; }
static int jbclient_blacklist_check_path_checked(const char *path, bool *outBlacklisted)
{
    (void)path;
    if (blacklistStatus != 0) return blacklistStatus;
    *outBlacklisted = blacklisted;
    return 0;
}

#include "implementation.h"

int main(void)
{
    const char *path = "/fixture/example";
    CHECK(!path_eligible_for_private_search_injection(path));

    insideJbroot = true;
    CHECK(path_eligible_for_private_search_injection(path));

    insideJbroot = false;
    installedApp = true;
    CHECK(path_eligible_for_private_search_injection(path));

    blacklisted = true;
    CHECK(!path_eligible_for_private_search_injection(path));

    installedApp = false;
    CHECK(!path_eligible_for_private_search_injection(path));

    installedApp = true;
    blacklisted = false;
    blacklistStatus = -1;
    CHECK(!path_eligible_for_private_search_injection(path));

    puts("6 private-search injection scope cases passed");
    return 0;
}
