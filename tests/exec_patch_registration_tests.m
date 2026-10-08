#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>

static int kq = 7;
static dispatch_queue_t gExecPatchDataQueue = nil;
static NSMutableDictionary *gExecPatchArray = nil;
static bool gFailKevent;
static bool gRecordVisibleAtKevent;

static void fixture_initExecPatch(void) {}

static int fixture_kevent(int kqArg, const struct kevent *changelist, int nchanges,
                          struct kevent *eventlist, int nevents,
                          const struct timespec *timeout)
{
    (void)kqArg; (void)changelist; (void)nchanges;
    (void)eventlist; (void)nevents; (void)timeout;
    __block NSNumber *record = nil;
    dispatch_sync(gExecPatchDataQueue, ^{
        record = gExecPatchArray[@42];
    });
    gRecordVisibleAtKevent = (record != nil);
    if (!gRecordVisibleAtKevent) {
        errno = ENOENT;
        return -1;
    }
    if (gFailKevent) {
        errno = EIO;
        return -1;
    }
    return 0;
}

#define initExecPatch fixture_initExecPatch
#define kevent(...) fixture_kevent(__VA_ARGS__)
#define JBLogError(...) ((void)0)

#include "implementation.h"

#undef initExecPatch
#undef kevent

static void reset_fixture(void)
{
    gFailKevent = false;
    gRecordVisibleAtKevent = false;
    gExecPatchDataQueue = dispatch_queue_create("fixture.execpatch.registration", DISPATCH_QUEUE_SERIAL);
    gExecPatchArray = [NSMutableDictionary dictionary];
}

int main(int argc, const char *argv[])
{
    @autoreleasepool {
        if (argc != 2) return 2;
        reset_fixture();
        if (!strcmp(argv[1], "visible")) {
            int ret = spawnExecPatchAdd(42, true);
            if (ret != 0) return 10;
            if (!gRecordVisibleAtKevent) return 11;
            __block NSNumber *record = nil;
            dispatch_sync(gExecPatchDataQueue, ^{ record = gExecPatchArray[@42]; });
            if (!record || !record.boolValue) return 12;
            return 0;
        }
        if (!strcmp(argv[1], "rollback")) {
            gFailKevent = true;
            int ret = spawnExecPatchAdd(42, false);
            if (ret == 0) return 20;
            if (!gRecordVisibleAtKevent) return 21;
            __block NSNumber *record = nil;
            dispatch_sync(gExecPatchDataQueue, ^{ record = gExecPatchArray[@42]; });
            if (record != nil) return 22;
            return 0;
        }
        return 2;
    }
}
