//
// Created by Ylarod on 2024/3/15.
//

#include <sys/event.h>
#import <Foundation/Foundation.h>

#include "../libjailbreak.h"
#include "exec_patch.h"
#include "common.h"
#include "log.h"

int kq = -1;
dispatch_queue_t gExecPatchDataQueue = nil;
NSMutableDictionary *gExecPatchArray = nil;

void event_handler(int kq)
{
    while(true)
    {
        struct kevent event = {0};
        int ret = kevent(kq, NULL, 0, &event, 1, NULL);
        if (ret < 0) {
            if (errno != EINTR) {
                JBLogError("[execPatch] kevent failed: %d, %s", errno, strerror(errno));
                usleep(10 * 1000);
            }
            continue;
        }
        if (ret != 1) {
            JBLogError("[execPatch] unexpected kevent result: %d", ret);
            continue;
        }
        if (event.filter != EVFILT_PROC) {
            JBLogError("[execPatch] unexpected kevent filter: %d", event.filter);
            continue;
        }

        pid_t pid = (pid_t)event.ident;

        __block NSNumber* resume;
        dispatch_sync(gExecPatchDataQueue, ^{
            resume = gExecPatchArray[@(pid)];
        });

        if(!resume) {
            JBLogError("[execPatch] no record for process: %d", pid);
            continue;
        }

        if(event.fflags & NOTE_EXIT)
        {
            JBLogError("kevent: unexpected process exit: %d", pid);
        }
        else if(event.fflags & NOTE_EXEC)
        {
            JBLogDebug("kevent: process exec: %d", pid);
            if(roothide_patch_proc(pid) == 0) {
                if (resume.boolValue) kill(pid, SIGCONT);
            } else {
                JBLogError("[execPatch] failed to patch for process: %d", pid);
                //we hosted the spawned(SETEXEC) process so we have to deal with it if patching failed
                kill(pid, SIGQUIT); //core dump
                kill(pid, SIGKILL);
            }
        }

        dispatch_sync(gExecPatchDataQueue, ^{
            [gExecPatchArray removeObjectForKey:@(pid)];
        });

    }
}

void initExecPatch() 
{
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gExecPatchArray = [[NSMutableDictionary alloc] init];
        gExecPatchDataQueue = dispatch_queue_create("roothide.execpatch.data-queue", DISPATCH_QUEUE_SERIAL);

        kq = kqueue();
        assert(kq != -1);

        queue = dispatch_queue_create("roothide.execpatch.event-queue", DISPATCH_QUEUE_SERIAL);
        dispatch_async(queue, ^{
            event_handler(kq);
        });
    });
}

int spawnExecPatchAdd(int pid, bool resume)
{
    initExecPatch();

    // The watched process cannot execute the SETEXEC transition until this RPC
    // returns. Publish the bookkeeping record synchronously first so the NOTE_EXEC
    // event can never outrun its PID -> resume state after the caller continues.
    __block bool duplicate = false;
    dispatch_sync(gExecPatchDataQueue, ^{
        if([gExecPatchArray objectForKey:@(pid)] != nil) {
            JBLogError("[spawnExecPatchAdd] already has record for process: %d", pid);
            duplicate = true;
        } else {
            [gExecPatchArray setObject:@(resume) forKey:@(pid)];
        }
    });
    if (duplicate) return -1;

    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXEC|NOTE_EXIT, 0, NULL);
    if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
        int savedErrno = errno;
        JBLogError("add kevent failed for pid: %d", pid);
        dispatch_sync(gExecPatchDataQueue, ^{
            [gExecPatchArray removeObjectForKey:@(pid)];
        });
        errno = savedErrno;
        return -1;
    }

    return 0;
}

int spawnExecPatchDel(int pid)
{
    initExecPatch();

    struct kevent kev;
    EV_SET(&kev, pid, EVFILT_PROC, EV_DELETE, 0, 0, NULL);
    if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1) {
        JBLogError("delete kevent failed for pid: %d", pid);
        return -1;
    }

    __block int ret = -1;

    //synchronous deletion
    dispatch_sync(gExecPatchDataQueue, ^{
        if([gExecPatchArray objectForKey:@(pid)] != nil) {
            [gExecPatchArray removeObjectForKey:@(pid)];
            ret = 0;
        } else {
            JBLogError("[spawnExecPatchDel] no record for process: %d", pid);
        }
    });

    return ret;
}
