#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "implementation.h"

static int touch_file(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return -1;
    return close(fd);
}

int main(void)
{
    char directory[] = "/tmp/systemhook-path-identity.XXXXXX";
    if (!mkdtemp(directory)) return 1;

    char target[1024];
    char alias[1024];
    char other[1024];
    snprintf(target, sizeof(target), "%s/systemhook.dylib", directory);
    snprintf(alias, sizeof(alias), "%s/systemhook-alias.dylib", directory);
    snprintf(other, sizeof(other), "%s/other.dylib", directory);

    if (touch_file(target) != 0 || touch_file(other) != 0) return 2;
    if (symlink(target, alias) != 0) return 3;

    if (!paths_refer_to_same_file(target, target)) return 4;
    if (!paths_refer_to_same_file(target, alias)) return 5;
    if (paths_refer_to_same_file(target, other)) return 6;
    if (paths_refer_to_same_file(NULL, target)) return 7;
    if (paths_refer_to_same_file(target, NULL)) return 8;

    unlink(alias);
    unlink(other);
    unlink(target);
    rmdir(directory);
    puts("systemhook path identity cases passed");
    return 0;
}
