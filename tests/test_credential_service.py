import pathlib
import subprocess
import tempfile
import unittest

from port_review_test_support import function_source

ROOT = pathlib.Path(__file__).resolve().parents[1]


class CredentialServiceTests(unittest.TestCase):
    def compile_and_run(self, source):
        with tempfile.TemporaryDirectory(prefix="wolf-credential-service-") as directory:
            path = pathlib.Path(directory) / "test.c"
            path.write_text(source)
            executable = path.with_suffix("")
            result = subprocess.run(
                ["xcrun", "clang", "-fblocks", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-g", str(path), "-o", str(executable)],
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # The fixture validates its 30 ms / 500 ms transport deadlines internally.
            # Keep the outer process timeout as a deadlock guard, but leave enough
            # headroom for ASan/libdispatch startup on a loaded host.
            result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_parent_delegates_before_resuming(self):
        body = function_source("BaseBin/libjailbreak/src/util.c", "target_proc_with_ucred_counted")
        self.assertIn("jbdPrepareCredentialHelper(pid, pidversion, deadline)", body)
        self.assertIn("int pidversion = proc_get_pidversion(pid);", body)
        self.assertNotIn("proc_patch_dyld(pid)", body)
        self.assertLess(body.index("jbdPrepareCredentialHelper("), body.index("kill(pid, SIGCONT)"))

    def test_service_checks_stopped_child_identity_and_deadline(self):
        source = (ROOT / "BaseBin/jailbreakd/src/server.m").read_text()
        self.assertIn("static int prepareCredentialHelper(", source)
        body = source.split("static int prepareCredentialHelper(", 1)[1].split("\nvoid jailbreakd_reply_message(", 1)[0]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
static int parent = 1, version = 9, lookupResult, patchResult, calls;
static bool stopped = true;
static pid_t proc_get_ppid(pid_t pid) { assert(pid == 42); return parent; }
static int proc_get_pidversion(pid_t pid) { assert(pid == 42); return version; }
static int proc_paused(pid_t pid, bool *value) { assert(pid == 42); *value = stopped; return lookupResult; }
static int proc_patch_dyld(pid_t pid) { assert(pid == 42); calls++; return patchResult; }
FUNCTION
int main(void) {
    uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC) + 5000000000ULL;
    assert(prepareCredentialHelper(2, 42, 9, deadline) == EPERM);
    assert(prepareCredentialHelper(1, 1, 9, deadline) == EPERM);
    parent = 2; assert(prepareCredentialHelper(1, 42, 9, deadline) == EPERM); parent = 1;
    version = 10; assert(prepareCredentialHelper(1, 42, 9, deadline) == ESRCH); version = 9;
    assert(prepareCredentialHelper(1, 42, 0, deadline) == ESRCH);
    assert(prepareCredentialHelper(1, 42, 9, 1) == ETIMEDOUT);
    stopped = false; assert(prepareCredentialHelper(1, 42, 9, deadline) == EBUSY); stopped = true;
    lookupResult = -1; assert(prepareCredentialHelper(1, 42, 9, deadline) == ESRCH); lookupResult = 0;
    assert(calls == 0);
    patchResult = -1; assert(prepareCredentialHelper(1, 42, 9, deadline) == EIO);
    patchResult = 0; assert(prepareCredentialHelper(1, 42, 9, deadline) == 0);
    assert(calls == 2);
}
'''.replace("FUNCTION", "static int prepareCredentialHelper(" + body)
        self.compile_and_run(harness)
        self.assertIn("case JBD_MSG_PREPARE_CREDENTIAL_HELPER:", source)
        self.assertIn("prepareCredentialHelper(clientPid, pid, pidversion, deadline)", source)

    def test_transport_timeout_and_single_inflight_request(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/jailbreakd.c").read_text()
        self.assertIn("int jbdPrepareCredentialHelper(", source)
        body = source.split("int jbdPrepareCredentialHelper(", 1)[1].split("\nint jbdSpawnPatchChild(", 1)[0]
        harness = r'''
#include <assert.h>
#include <dispatch/dispatch.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <xpc/xpc.h>
#define JBD_MSG_PREPARE_CREDENTIAL_HELPER 1007
static atomic_int mode, requests;
static dispatch_semaphore_t blocked, releaseReply;
static xpc_object_t jailbreakdXpcRequest(xpc_object_t message) {
    assert(xpc_dictionary_get_uint64(message, "id") == JBD_MSG_PREPARE_CREDENTIAL_HELPER);
    assert(xpc_dictionary_get_int64(message, "pid") == 42);
    assert(xpc_dictionary_get_int64(message, "pidversion") == 9);
    assert(xpc_dictionary_get_uint64(message, "deadline") > 0);
    atomic_fetch_add(&requests, 1);
    int selected = atomic_load(&mode);
    if (selected == 3) {
        dispatch_semaphore_signal(blocked);
        dispatch_semaphore_wait(releaseReply, DISPATCH_TIME_FOREVER);
    }
    if (selected == 1) return NULL;
    xpc_object_t reply = xpc_dictionary_create(NULL, NULL, 0);
    if (selected != 2) xpc_dictionary_set_int64(reply, "result", selected == 4 ? ESRCH : 0);
    return reply;
}
FUNCTION
static int request(unsigned milliseconds) {
    return jbdPrepareCredentialHelper(42, 9, clock_gettime_nsec_np(CLOCK_MONOTONIC) + milliseconds * 1000000ULL);
}
int main(void) {
    blocked = dispatch_semaphore_create(0);
    releaseReply = dispatch_semaphore_create(0);
    assert(request(500) == 0);
    atomic_store(&mode, 1); assert(request(500) == -1 && errno == EIO);
    atomic_store(&mode, 2); assert(request(500) == -1 && errno == EPROTO);
    atomic_store(&mode, 4); assert(request(500) == -1 && errno == ESRCH);
    assert(jbdPrepareCredentialHelper(42, 9, 1) == -1 && errno == ETIMEDOUT);
    assert(jbdPrepareCredentialHelper(42, 0, clock_gettime_nsec_np(CLOCK_MONOTONIC) + 500000000ULL) == -1 && errno == ESRCH);
    atomic_store(&mode, 3);
    assert(request(30) == -1 && errno == ETIMEDOUT);
    assert(dispatch_semaphore_wait(blocked, dispatch_time(DISPATCH_TIME_NOW, 500000000)) == 0);
    int previous = atomic_load(&requests);
    assert(request(30) == -1 && errno == EBUSY);
    assert(atomic_load(&requests) == previous);
    dispatch_semaphore_signal(releaseReply);
    atomic_store(&mode, 0);
    bool recovered = false;
    for (unsigned i = 0; i < 100; i++) {
        if (request(500) == 0) { recovered = true; break; }
        assert(errno == EBUSY);
        usleep(1000);
    }
    assert(recovered);
    dispatch_release(blocked);
    dispatch_release(releaseReply);
}
'''.replace("FUNCTION", "int jbdPrepareCredentialHelper(" + body)
        self.compile_and_run(harness)


if __name__ == "__main__":
    unittest.main()
