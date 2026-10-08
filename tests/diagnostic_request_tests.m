#import <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <mach/mach.h>
#include <dispatch/dispatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>

static xpc_object_t incoming;
static xpc_object_t observed_reply;
static const char *scenario;
static uid_t fixture_uid = 501;
static unsigned aborts, logs, invalid_logs, operations, reply_attempts;

static int fixture_receive(mach_port_t port, xpc_object_t *message)
{
    if (!strcmp(scenario, "receive-failure")) return EIO;
    *message = incoming;
    return 0;
}
static xpc_object_t fixture_create_reply(xpc_object_t message)
{
    reply_attempts++;
    return !strcmp(scenario, "no-reply") ? nil : xpc_dictionary_create_empty();
}
static void fixture_audit_token(xpc_object_t message, audit_token_t *token) { memset(token, 0, sizeof(*token)); }
static uid_t fixture_token_uid(audit_token_t token) { return fixture_uid; }
static pid_t fixture_token_pid(audit_token_t token) { return 42; }
static void jailbreakd_reply_message(int message_id, xpc_object_t reply) { observed_reply = reply; }
static void fixture_debug(const char *format, ...) {}
static void roothide_bootlog(const char *line) { (void)line; }
static void fixture_abort(void) { aborts++; }
static int fixture_kill(pid_t pid, int signal_number) { operations++; return 0; }
static const char *proc_get_path(pid_t pid, char *path) { return "/fixture/daemon"; }
static pid_t proc_get_ppid(pid_t pid) { operations++; return 42; }
static int prepareCredentialHelper(pid_t client, pid_t pid, int version, uint64_t deadline) { operations++; return 0; }
static int proc_patch_csflags(pid_t pid) { operations++; return 0; }
static int proc_fix_spinlock(pid_t pid) { operations++; return 0; }
static int roothide_patch_proc(pid_t pid) { operations++; return 0; }
static int spawnExecPatchAdd(pid_t pid, bool resume) { operations++; return 0; }
static int spawnExecPatchDel(pid_t pid) { operations++; return 0; }
static int execTraceProcess(pid_t pid, uint64_t traced) { operations++; return 0; }
static int execTraceCancel(pid_t pid, uint64_t detached) { operations++; return 0; }
static void JBLogGetLogFilePath(const char *name, const char *suffix, char *path) { strcpy(path, "/fixture/log"); }
static void JBLogFunction(const char *path, pid_t pid, uint64_t tid, const char *name, const char *format, const char *text)
{
    logs++;
    invalid_logs += !text;
}
#define xpc_pipe_receive fixture_receive
#define xpc_dictionary_create_reply fixture_create_reply
#define xpc_dictionary_get_audit_token fixture_audit_token
#define audit_token_to_euid fixture_token_uid
#define audit_token_to_pid fixture_token_pid
#define JBLogDebug fixture_debug
#define JBLogError fixture_debug
#define abort fixture_abort
#define kill fixture_kill

#include "implementation.h"

int main(int argc, char **argv)
{
    @autoreleasepool {
        if (argc != 2) return 2;
        scenario = argv[1];
        incoming = xpc_dictionary_create_empty();
        xpc_dictionary_set_uint64(incoming, "id", 9999);
        bool reply_expected = true;
        int64_t expected_result = ENOTSUP;
        unsigned expected_logs = 0;
        if (!strcmp(scenario, "missing-id")) {
            xpc_dictionary_set_value(incoming, "id", NULL);
            expected_result = EINVAL;
        } else if (!strcmp(scenario, "wrong-id")) {
            xpc_dictionary_set_string(incoming, "id", "102");
            expected_result = EINVAL;
        } else if (!strcmp(scenario, "not-dictionary")) {
            incoming = xpc_string_create("fixture");
            reply_expected = false;
        } else if (!strcmp(scenario, "no-reply") || !strcmp(scenario, "receive-failure")) {
            reply_expected = false;
        } else if (!strncmp(scenario, "log-", 4)) {
            xpc_dictionary_set_uint64(incoming, "id", JBD_MSG_SYSTEMWIDE_LOG);
            xpc_dictionary_set_uint64(incoming, "tid", 1);
            if (!strcmp(scenario, "log-valid")) xpc_dictionary_set_string(incoming, "log", "fixture");
            else if (!strcmp(scenario, "log-wrong")) xpc_dictionary_set_uint64(incoming, "log", 7);
#ifdef ENABLE_LOGS
            expected_result = !strcmp(scenario, "log-valid") ? 0 : EINVAL;
            expected_logs = !strcmp(scenario, "log-valid");
#endif
        } else if (!strncmp(scenario, "test-", 5)) {
            xpc_dictionary_set_uint64(incoming, "id", JBD_MSG_TEST_CALL);
            int64_t value = 17;
            if (!strcmp(scenario, "test-root")) fixture_uid = 0;
            else if (!strcmp(scenario, "test-negative")) value = -17;
            else if (!strcmp(scenario, "test-overflow")) value = INT_MAX;
            if (strcmp(scenario, "test-missing")) xpc_dictionary_set_int64(incoming, "value", value);
            expected_result = !strcmp(scenario, "test-missing") ? EINVAL : value == INT_MAX ? ERANGE : value * 2;
        }
        jailbreakd_received_message(MACH_PORT_NULL);
        unsigned failures = aborts || invalid_logs || operations || logs != expected_logs;
        if (reply_expected) {
            failures += !observed_reply;
            if (observed_reply) {
                failures += !xpc_dictionary_get_value(observed_reply, "result");
                failures += xpc_dictionary_get_int64(observed_reply, "result") != expected_result;
            }
        } else failures += observed_reply != nil;
        if (!strcmp(scenario, "not-dictionary") || !strcmp(scenario, "receive-failure")) failures += reply_attempts != 0;
        printf("%s: replies=%u aborts=%u logs=%u operations=%u failures=%u\n",
               scenario, observed_reply != nil, aborts, logs, operations, failures);
        incoming = nil;
        observed_reply = nil;
        return failures ? 1 : 0;
    }
}
