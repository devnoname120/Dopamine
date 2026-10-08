#include <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/roothider/bootlog.h>

static int prepareCredentialHelper(pid_t clientPid, pid_t pid, int pidversion, uint64_t deadline)
{
	if (clientPid != 1 || pid <= 1 || proc_get_ppid(pid) != clientPid) return EPERM;
	if (pidversion <= 0 || proc_get_pidversion(pid) != pidversion) return ESRCH;
	if (clock_gettime_nsec_np(CLOCK_MONOTONIC) >= deadline) return ETIMEDOUT;
	bool paused = false;
	if (proc_paused(pid, &paused) != 0) return ESRCH;
	if (!paused) return EBUSY;
	// Unlike launchd, this service has the task-port and thread-state entitlements.
	return proc_patch_dyld(pid) == 0 ? 0 : EIO;
}

void jailbreakd_reply_message(JBD_MESSAGE_ID msgId, xpc_object_t reply)
{
	char* desc = NULL;
	JBLogDebug("reply message %d with %s", msgId, (desc=xpc_copy_description(reply)));
	if(desc) free(desc);
	int err = xpc_pipe_routine_reply(reply);
	if (err != 0) {
		JBLogError("Error %d sending response", err);
	}
}

void jailbreakd_received_message(mach_port_t port)
{
	@autoreleasepool {
		xpc_object_t message = nil;
		int err = xpc_pipe_receive(port, &message);
		if (err != 0) {
			JBLogError("xpc_pipe_receive error %d", err);
			return;
		}
		if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;

		xpc_object_t reply = xpc_dictionary_create_reply(message);
		if (!reply) return;
		xpc_object_t identifier = xpc_dictionary_get_value(message, "id");
		if (!identifier || xpc_get_type(identifier) != XPC_TYPE_UINT64) {
			xpc_dictionary_set_int64(reply, "result", EINVAL);
			jailbreakd_reply_message(0, reply);
			return;
		}
		uint64_t rawId = xpc_uint64_get_value(identifier);
		if (rawId > INT_MAX) {
			xpc_dictionary_set_int64(reply, "result", ENOTSUP);
			jailbreakd_reply_message(0, reply);
			return;
		}

			JBD_MESSAGE_ID msgId = (JBD_MESSAGE_ID)rawId;
		
		if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
			audit_token_t auditToken = {0};
			xpc_dictionary_get_audit_token(message, &auditToken);
				pid_t clientPid = audit_token_to_pid(auditToken);

			char* desc = NULL;
			JBLogDebug("received message %d from %d(%s) with dictionary: %s", msgId, clientPid, proc_get_path(clientPid,NULL), (desc=xpc_copy_description(message)));
			if(desc) free(desc);

				switch (msgId) {
					case JBD_MSG_PREPARE_CREDENTIAL_HELPER: {
						pid_t pid = xpc_dictionary_get_int64(message, "pid");
						int pidversion = xpc_dictionary_get_int64(message, "pidversion");
						uint64_t deadline = xpc_dictionary_get_uint64(message, "deadline");
						int result = prepareCredentialHelper(clientPid, pid, pidversion, deadline);
						xpc_dictionary_set_int64(reply, "result", result);
						break;
					}
					case JBD_MSG_SPINLOCK_FIX_ONLY: {
					int64_t result = 0;
					pid_t pid = xpc_dictionary_get_int64(message, "pid");
					bool resume = xpc_dictionary_get_bool(message, "resume");
					pid_t ppid = proc_get_ppid(pid);
					JBLogDebug("spinlock fix: client pid=%d, child pid=%d, child's parent pid=%d, child proc=%s", clientPid, pid, ppid, proc_get_path(pid,NULL));
					if(ppid == clientPid) {
						if(ppid==1 && resume==false) {
							//`frida -f` sucks with proc_fix_spinlock on ios15
							result = proc_patch_csflags(pid);
						}
						else if(proc_fix_spinlock(pid) == 0) {
							if(resume) kill(pid, SIGCONT);
						} else {
							JBLogError("spinlock fix failed: %d", pid);
							result = -1;
						}
					} else {
						JBLogError("spinlock fix denied: %d", pid);
						result = -1;
					}
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPAWN_PATCH_CHILD: {
					int64_t result = 0;
					pid_t pid = xpc_dictionary_get_int64(message, "pid");
					bool resume = xpc_dictionary_get_bool(message, "resume");
					pid_t ppid = proc_get_ppid(pid);
					const char *childPath = proc_get_path(pid,NULL);
					bool traceXpcProxy = childPath && strcmp(childPath, "/usr/libexec/xpcproxy") == 0;
					if (traceXpcProxy) {
						char phase[256];
						snprintf(phase, sizeof(phase), "jailbreakd: xpcproxy patch begin child=%d parent=%d resume=%d", pid, ppid, resume);
						roothide_bootlog(phase);
					}
					JBLogDebug("spawn patch: client pid=%d, child pid=%d, child's parent pid=%d, child proc=%s", clientPid, pid, ppid, proc_get_path(pid,NULL));
					if(ppid == clientPid) {
						if(ppid==1 && resume==false) {
							//`frida -f` sucks with proc_patch_dyld on ios15
							result = proc_patch_csflags(pid);
						}
						else if(roothide_patch_proc(pid) == 0) {
							if(resume) kill(pid, SIGCONT);
						} else {
							JBLogError("spawn patch failed: %d", pid);
							result = -1;
						}
					} else {
						JBLogError("spawn patch denied: %d", pid);
						result = -1;
					}
					if (traceXpcProxy) {
						char phase[256];
						snprintf(phase, sizeof(phase), "jailbreakd: xpcproxy patch end child=%d result=%lld", pid, (long long)result);
						roothide_bootlog(phase);
					}
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPAWN_EXEC_START: {
					bool resume = xpc_dictionary_get_bool(message, "resume");
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("spawn exec start: %d %s", clientPid, execfile);
					int64_t result = spawnExecPatchAdd(clientPid, resume);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPAWN_EXEC_CANCEL: {
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("spawn exec cancel: %d %s", clientPid, execfile);
					int64_t result = spawnExecPatchDel(clientPid);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_EXEC_TRACE_START: {
					//dead lock: jbd->ptrace->kernel->amfi port->launchd->spawn amfid->jdb
					dispatch_async(dispatch_get_global_queue(0, 0), ^{
						int64_t result = -1;
						uint64_t traced = xpc_dictionary_get_uint64(message, "traced");
						const char* execfile = xpc_dictionary_get_string(message, "execfile");
						JBLogDebug("exec trace start: %d %s", clientPid, execfile);
						result = execTraceProcess(clientPid, traced);
						xpc_dictionary_set_int64(reply, "result", result);
						jailbreakd_reply_message(msgId, reply);
					});
					reply = nil; //reply later
					break;
				}

				case JBD_MSG_EXEC_TRACE_CANCEL: {
					int64_t result = -1;
					uint64_t detached = xpc_dictionary_get_uint64(message, "detached");
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("exec trace cancel: %d %s", clientPid, execfile);
					result = execTraceCancel(clientPid, detached);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

					case JBD_MSG_SYSTEMWIDE_LOG: {
#ifdef ENABLE_LOGS
						const char* log = xpc_dictionary_get_string(message, "log");
						if (!log) {
							xpc_dictionary_set_int64(reply, "result", EINVAL);
							break;
						}
						static char logFilePath[PATH_MAX] = {0};
					static dispatch_once_t onceToken;
					dispatch_once(&onceToken, ^{
						JBLogGetLogFilePath("systemwide", NULL, logFilePath);
					});

					const char* progname = NULL;
					const char* procpath = proc_get_path(clientPid,NULL);
					if(procpath) {
						progname = strrchr(procpath, '/');
						if(progname) progname++; else progname = procpath;
					}
						uint64_t tid = xpc_dictionary_get_uint64(message, "tid");
						JBLogFunction(logFilePath, clientPid, tid, progname ? progname : "(null)", "%s", log);
					xpc_dictionary_set_int64(reply, "result", 0);
#else
						xpc_dictionary_set_int64(reply, "result", ENOTSUP);
#endif
					break;
				}

					case JBD_MSG_TEST_CALL: {
						xpc_object_t input = xpc_dictionary_get_value(message, "value");
						if (!input || xpc_get_type(input) != XPC_TYPE_INT64) {
							xpc_dictionary_set_int64(reply, "result", EINVAL);
							break;
						}
						int64_t value = xpc_int64_get_value(input);
						if (value < INT_MIN / 2 || value > INT_MAX / 2) {
							xpc_dictionary_set_int64(reply, "result", ERANGE);
							break;
						}
						JBLogDebug("jailbreakd test call(%lld) from %d,%s", value, clientPid, proc_get_path(clientPid,NULL));
						xpc_dictionary_set_int64(reply, "result", value * 2);

#ifdef ENABLE_CRASH_TESTS
						if (audit_token_to_euid(auditToken) == 0) {
							abort(); // crashreporter test
						}
#endif

						break;
					}
					default:
						xpc_dictionary_set_int64(reply, "result", ENOTSUP);
						break;
			}
		}
		if (reply) {
			jailbreakd_reply_message(msgId, reply);
		}
	}
}
