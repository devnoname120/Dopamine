#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER_INPUT_FD 5
#define SERVER_OUTPUT_FD 6
#ifndef POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE
#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
#endif

static int serverInputPipe[2] = {-1, -1};
static int serverOutputPipe[2] = {-1, -1};
static pid_t serverPid = -1;
static int gScenario;
static int gPipeCall;
static int gActionCall;
static int gSpawnCalls;
static bool gParentOpen[128];
static int gNextDup = 20;

typedef struct {
    int kind;
    int a;
    int b;
} action_t;
static action_t gActions[64];
static int gActionCount;

static void fixture_mark_open(int fd)
{
    if (fd >= 0 && fd < (int)(sizeof(gParentOpen) / sizeof(gParentOpen[0]))) gParentOpen[fd] = true;
}

static int fixture_close(int fd)
{
    if (fd >= 0 && fd < (int)(sizeof(gParentOpen) / sizeof(gParentOpen[0]))) gParentOpen[fd] = false;
    return 0;
}

static int fixture_pipe(int fds[2])
{
    gPipeCall++;
    if (gScenario == 5 && gPipeCall == 1) {
        errno = EMFILE;
        return -1;
    }
    static const int normal[][2] = {{10,11},{12,13},{14,15},{16,17}};
    static const int collision[][2] = {{3,4},{5,6},{7,8},{9,10}};
    const int (*table)[2] = gScenario == 1 ? collision : normal;
    int index = gPipeCall - 1;
    if (index < 0 || index >= 4) return -1;
    fds[0] = table[index][0];
    fds[1] = table[index][1];
    fixture_mark_open(fds[0]);
    fixture_mark_open(fds[1]);
    return 0;
}

static int fixture_fcntl(int fd, int cmd, ...)
{
    if (cmd != F_DUPFD_CLOEXEC || fd < 0 || !gParentOpen[fd]) {
        errno = EINVAL;
        return -1;
    }
    while (gNextDup < (int)(sizeof(gParentOpen) / sizeof(gParentOpen[0])) && gParentOpen[gNextDup]) gNextDup++;
    if (gNextDup >= (int)(sizeof(gParentOpen) / sizeof(gParentOpen[0]))) {
        errno = EMFILE;
        return -1;
    }
    int moved = gNextDup++;
    gParentOpen[moved] = true;
    return moved;
}

static int fixture_posix_spawnattr_init(posix_spawnattr_t *attr)
{
    (void)attr;
    return gScenario == 2 ? ENOMEM : 0;
}

static int fixture_posix_spawnattr_set_persona_np(posix_spawnattr_t *attr, uid_t persona, uint32_t flags)
{
    (void)attr; (void)persona; (void)flags;
    return gScenario == 3 ? EPERM : 0;
}

static int fixture_posix_spawnattr_set_persona_uid_np(posix_spawnattr_t *attr, uid_t uid)
{
    (void)attr; (void)uid;
    return 0;
}

static int fixture_posix_spawnattr_set_persona_gid_np(posix_spawnattr_t *attr, gid_t gid)
{
    (void)attr; (void)gid;
    return 0;
}

static int fixture_posix_spawnattr_destroy(posix_spawnattr_t *attr)
{
    (void)attr;
    return 0;
}

static int fixture_posix_spawn_file_actions_init(posix_spawn_file_actions_t *actions)
{
    (void)actions;
    return gScenario == 4 ? ENOMEM : 0;
}

static int fixture_posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *actions, int fd)
{
    (void)actions;
    gActionCall++;
    if (gScenario == 6 && gActionCall == 1) return EBADF;
    gActions[gActionCount++] = (action_t){.kind = 0, .a = fd, .b = -1};
    return 0;
}

static int fixture_posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *actions, int from, int to)
{
    (void)actions;
    gActionCall++;
    if (gScenario == 6 && gActionCall == 1) return EBADF;
    gActions[gActionCount++] = (action_t){.kind = 1, .a = from, .b = to};
    return 0;
}

static int fixture_posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *actions)
{
    (void)actions;
    return 0;
}

static bool fixture_child_mappings_valid(void)
{
    bool childOpen[128];
    memcpy(childOpen, gParentOpen, sizeof(childOpen));
    childOpen[STDOUT_FILENO] = true;
    childOpen[STDERR_FILENO] = true;
    for (int i = 0; i < gActionCount; i++) {
        action_t action = gActions[i];
        if (action.kind == 0) {
            if (action.a >= 0 && action.a < 128) childOpen[action.a] = false;
        } else {
            if (action.a < 0 || action.a >= 128 || !childOpen[action.a]) return false;
            if (action.b < 0 || action.b >= 128) return false;
            if (action.a != action.b) childOpen[action.b] = true;
        }
    }
    return childOpen[SERVER_INPUT_FD] && childOpen[SERVER_OUTPUT_FD] &&
           childOpen[STDOUT_FILENO] && childOpen[STDERR_FILENO];
}

static int fixture_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
                               const posix_spawnattr_t *attr, char *const argv[], char *const envp[])
{
    (void)path; (void)actions; (void)attr; (void)argv; (void)envp;
    gSpawnCalls++;
    if (gScenario == 7) return EACCES;
    if (!fixture_child_mappings_valid()) return EINVAL;
    *pid = 1234;
    return 0;
}

static dispatch_semaphore_t fixture_dispatch_semaphore_create(long value)
{
    return dispatch_semaphore_create(value);
}

static dispatch_queue_t fixture_dispatch_queue_create(const char *label, dispatch_queue_attr_t attr)
{
    return dispatch_queue_create(label, attr);
}

static dispatch_source_t fixture_dispatch_source_create(dispatch_source_type_t type, uintptr_t handle,
                                                        unsigned long mask, dispatch_queue_t queue)
{
    (void)type; (void)handle; (void)mask;
    return dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, queue);
}

static void fixture_dispatch_source_set_cancel_handler(dispatch_source_t source, dispatch_block_t handler)
{
    (void)source; (void)handler;
}
static void fixture_dispatch_source_set_event_handler(dispatch_source_t source, dispatch_block_t handler)
{
    (void)source; (void)handler;
}
static void fixture_dispatch_source_cancel(dispatch_source_t source) { (void)source; }
static void fixture_dispatch_resume(dispatch_object_t object) { (void)object; }
static long fixture_dispatch_semaphore_signal(dispatch_semaphore_t sem) { (void)sem; return 0; }
static void fixture_server_disconnect(void)
{
    if (serverInputPipe[0] >= 0) fixture_close(serverInputPipe[0]);
    if (serverInputPipe[1] >= 0) fixture_close(serverInputPipe[1]);
    if (serverOutputPipe[0] >= 0) fixture_close(serverOutputPipe[0]);
    if (serverOutputPipe[1] >= 0) fixture_close(serverOutputPipe[1]);
    serverInputPipe[0] = serverInputPipe[1] = -1;
    serverOutputPipe[0] = serverOutputPipe[1] = -1;
}

#define SYSLOG(...) ((void)0)
#define pipe fixture_pipe
#define fcntl fixture_fcntl
#define close fixture_close
#define posix_spawnattr_init fixture_posix_spawnattr_init
#define posix_spawnattr_set_persona_np fixture_posix_spawnattr_set_persona_np
#define posix_spawnattr_set_persona_uid_np fixture_posix_spawnattr_set_persona_uid_np
#define posix_spawnattr_set_persona_gid_np fixture_posix_spawnattr_set_persona_gid_np
#define posix_spawnattr_destroy fixture_posix_spawnattr_destroy
#define posix_spawn_file_actions_init fixture_posix_spawn_file_actions_init
#define posix_spawn_file_actions_addclose fixture_posix_spawn_file_actions_addclose
#define posix_spawn_file_actions_adddup2 fixture_posix_spawn_file_actions_adddup2
#define posix_spawn_file_actions_destroy fixture_posix_spawn_file_actions_destroy
#define posix_spawn fixture_posix_spawn
#define dispatch_semaphore_create fixture_dispatch_semaphore_create
#define dispatch_queue_create fixture_dispatch_queue_create
#define dispatch_source_create fixture_dispatch_source_create
#define dispatch_source_set_cancel_handler fixture_dispatch_source_set_cancel_handler
#define dispatch_source_set_event_handler fixture_dispatch_source_set_event_handler
#define dispatch_source_cancel fixture_dispatch_source_cancel
#define dispatch_resume fixture_dispatch_resume
#define dispatch_semaphore_signal fixture_dispatch_semaphore_signal
#define server_disconnect fixture_server_disconnect

#include "implementation.h"

#undef pipe
#undef fcntl
#undef close
#undef posix_spawnattr_init
#undef posix_spawnattr_set_persona_np
#undef posix_spawnattr_set_persona_uid_np
#undef posix_spawnattr_set_persona_gid_np
#undef posix_spawnattr_destroy
#undef posix_spawn_file_actions_init
#undef posix_spawn_file_actions_addclose
#undef posix_spawn_file_actions_adddup2
#undef posix_spawn_file_actions_destroy
#undef posix_spawn
#undef dispatch_semaphore_create
#undef dispatch_queue_create
#undef dispatch_source_create
#undef dispatch_source_set_cancel_handler
#undef dispatch_source_set_event_handler
#undef dispatch_source_cancel
#undef dispatch_resume
#undef dispatch_semaphore_signal
#undef server_disconnect

static void require(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(int argc, const char *argv[])
{
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "success")) gScenario = 0;
    else if (!strcmp(argv[1], "collision")) gScenario = 1;
    else if (!strcmp(argv[1], "attr-init")) gScenario = 2;
    else if (!strcmp(argv[1], "persona")) gScenario = 3;
    else if (!strcmp(argv[1], "actions-init")) gScenario = 4;
    else if (!strcmp(argv[1], "pipe")) gScenario = 5;
    else if (!strcmp(argv[1], "add-action")) gScenario = 6;
    else if (!strcmp(argv[1], "spawn")) gScenario = 7;
    else return 2;

    memset(gParentOpen, 0, sizeof(gParentOpen));
    gParentOpen[STDOUT_FILENO] = true;
    gParentOpen[STDERR_FILENO] = true;
    serverInputPipe[0] = serverInputPipe[1] = -1;
    serverOutputPipe[0] = serverOutputPipe[1] = -1;
    serverPid = -1;

    char *argvv[] = {(char *)"exploit_server", NULL};
    char *envv[] = {NULL};
    int result = spawn_server("/fixture/exploit_server", argvv, envv);

    if (gScenario == 0 || gScenario == 1) {
        require(result == 0, "valid helper spawn must succeed");
        require(gSpawnCalls == 1, "valid helper spawn attempted once");
        require(serverPid == 1234, "successful helper spawn publishes pid");
        require(serverInputPipe[1] >= 0 && serverOutputPipe[0] >= 0, "parent transport endpoints retained");
    } else {
        require(result != 0, "setup/spawn refusal must propagate failure");
        if (gScenario != 7) require(gSpawnCalls == 0, "setup refusal must stop before spawn");
        require(serverPid <= 1, "failed helper spawn must not publish pid");
    }
    return 0;
}
