#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "implementation.h"

static int touch_file(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (fd < 0) return -1;
    return close(fd);
}

int main(void)
{
    char directory[] = "/tmp/jbroot-target-scope.XXXXXX";
    if (!mkdtemp(directory)) return 1;

    char root[PATH_MAX];
    char alias[PATH_MAX];
    char bin[PATH_MAX];
    char tool[PATH_MAX];
    char outside[PATH_MAX];
    char sibling[PATH_MAX];
    snprintf(root, sizeof(root), "%s/root", directory);
    snprintf(alias, sizeof(alias), "%s/root-alias", directory);
    snprintf(bin, sizeof(bin), "%s/bin", root);
    snprintf(tool, sizeof(tool), "%s/tool", bin);
    snprintf(outside, sizeof(outside), "%s/outside", directory);
    snprintf(sibling, sizeof(sibling), "%s/root-other", directory);

    if (mkdir(root, 0755) != 0 || mkdir(bin, 0755) != 0 || mkdir(sibling, 0755) != 0) return 2;
    if (touch_file(tool) != 0 || touch_file(outside) != 0) return 3;
    if (symlink(root, alias) != 0) return 4;

    fixtureJbroot = alias;
    if (!path_is_within_jbroot(tool)) return 5;
    if (!path_is_within_jbroot(root)) return 6;
    if (path_is_within_jbroot(outside)) return 7;
    if (path_is_within_jbroot(sibling)) return 8;
    if (path_is_within_jbroot(NULL)) return 9;
    if (path_is_within_jbroot("/definitely/not/present")) return 10;

    unlink(alias);
    unlink(outside);
    unlink(tool);
    rmdir(bin);
    rmdir(sibling);
    rmdir(root);
    rmdir(directory);
    puts("jbroot target scope cases passed");
    return 0;
}
