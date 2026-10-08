#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <libjailbreak/jbclient_mach.h>

#include "dyld.h"
#include "dyld_jbinfo.h"

bool gDyldHookLog = false;
extern uint64_t gDyldhookBootstrapReturn;
__attribute__((used)) char gDyldhookBootstrapSandboxExtensions[JBSERVER_SANDBOX_EXTENSIONS_MAX] = {0};

__attribute__((section("__DATA,__jbinfo"))) static char jbinfoSection[0x4000];
#define jbInfo ((struct dyld_jbinfo *)&jbinfoSection[0])

bool gDyldhookInitDone = false;

bool jbinfo_is_checked_in(void)
{
	return jbInfo->state == DYLD_STATE_CHECKED_IN;
}

char *jbinfo_get_jbroot(void)
{
	return jbInfo->jbRootPath;
}

bool jbinfo_should_force_cs_adhoc(void)
{
	return jbInfo->forceCSAdhoc;
}

int consume_tokenized_sandbox_extensions(char *sandboxExtensions)
{
	if (!sandboxExtensions || sandboxExtensions[0] == '\0') return -1;

	int tokenCount = 1;
	bool tokenHasData = false;
	for (char *it = sandboxExtensions; *it; it++) {
		if (*it == '|') {
			if (!tokenHasData) return -1;
			tokenCount++;
			tokenHasData = false;
		}
		else {
			tokenHasData = true;
		}
	}
	if (!tokenHasData || tokenCount != 3) return -1;

	char *token = sandboxExtensions;
	for (char *it = sandboxExtensions; ; it++) {
		if (*it != '|' && *it != '\0') continue;
		char saved = *it;
		*it = '\0';
		int64_t handle = sandbox_extension_consume(token);
		*it = saved;
		if (handle < 0) return -1;
		if (saved == '\0') break;
		token = &it[1];
	}
	return 0;
}

void dyldhook_perform_checkin(void)
{
	struct jbserver_mach_msg_checkin_reply *replyPtr; // Only for sizeof macro

	char *jbRootPathPtr = &jbInfo->data[0];
	char *bootUUIDPtr = &jbInfo->data[sizeof(replyPtr->jbRootPath)];
	char *sandboxExtensionsPtr = &jbInfo->data[sizeof(replyPtr->jbRootPath)+sizeof(replyPtr->bootUUID)];

	// Tell jbserver (in launchd) that this process exists
	// This will, amongst other things, disable page validation, which allows instruction hooks to be applied later
	if (jbclient_mach_process_checkin(jbRootPathPtr, bootUUIDPtr, sandboxExtensionsPtr, &jbInfo->fullyDebugged, &jbInfo->forceCSAdhoc) == 0) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Performed checkin [%s %s %s]\n", jbRootPathPtr, bootUUIDPtr, sandboxExtensionsPtr);
		}
			if (consume_tokenized_sandbox_extensions(sandboxExtensionsPtr) != 0) return;
		jbInfo->jbRootPath = jbRootPathPtr;
		jbInfo->bootUUID = bootUUIDPtr;
		jbInfo->sandboxExtensions = sandboxExtensionsPtr;
		jbInfo->state = DYLD_STATE_CHECKED_IN;
	}
	else {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Checkin failed???\n");
		}
	}
}

int simple_atoi(char *p)
{
	int negate = p[0] == '-';
	if (negate) p++;

    int k = 0;
    while (*p) {
		if (*p >= '0' && *p <= '9') {
			k = k * 10 + (*p) - '0';
		}
		p++;
	}

	return (negate ? -1 : 1) * k;
}

static bool parse_credential_number(const char *text, uint32_t *number)
{
	if (!text || !text[0]) return false;
	uint32_t value = 0;
	for (const char *p = text; *p; p++) {
		if (*p < '0' || *p > '9') return false;
		uint32_t digit = (uint32_t)(*p - '0');
		if (value > (UINT32_MAX - digit) / 10) return false;
		value = value * 10 + digit;
	}
	*number = value;
	return true;
}

mach_port_t mach_task_self_ = MACH_PORT_NULL;
void mach_init_4real(void)
{
	// Because mach_init has a "call once" mechanism, we can just call it ourselves without breaking anything in the later dyld flow
	// This allows us to have a proper pthread descriptor which fixes a whole bunch of stuff
	extern void mach_init(void);
	mach_init(); // This sets up mach_task_self_ in dyld but we can't get it since getting a global from dyld is not implemented in MachOMerger

	mach_task_self_ = task_self_trap();
	// Apparently task_self_trap increases the refcount of the task so we call deallocate again to decrease it
	mach_port_deallocate(mach_task_self_, mach_task_self_);
}

void dyldhook_init(uintptr_t kernelParams)
{
	mach_init_4real();
	extern void dyldhook_init_roothide(uintptr_t);
	dyldhook_init_roothide(kernelParams);

	// If we are in launchd, bail out
	if (getpid() == 1) {
		return;
	}

	// Walk kernelParams to get envp
	uintptr_t argc = *(uintptr_t *)(kernelParams + sizeof(void *));
	char **argv = (char **)(kernelParams + sizeof(void *) + sizeof(argc));
	char **envp = (char **)(kernelParams + sizeof(void *) + sizeof(argc) + (sizeof(const char *) * argc) + sizeof(void *));

	if (_simple_getenv(envp, "DYLD_HOOK_PRINT") != NULL) {
		gDyldHookLog = true;
	}

	if (_simple_getenv(envp, "DYLD_HOOK_SETUID") != NULL) {
		uint32_t uid = 0, gid = 0, ruid = 0, rgid = 0, ngroups = 0;
		int fd = -1;
		gid_t groups[NGROUPS_MAX] = { 0 };
		unsigned fields = 0;
		bool valid = true;

		for (int i = 1; i < argc; i++) {
			unsigned field;
			uint32_t *destination = NULL;
			if (!strcmp(argv[i], "--fd")) field = 1;
			else if (!strcmp(argv[i], "--uid")) { field = 2; destination = &uid; }
			else if (!strcmp(argv[i], "--ruid")) { field = 4; destination = &ruid; }
			else if (!strcmp(argv[i], "--gid")) { field = 8; destination = &gid; }
			else if (!strcmp(argv[i], "--rgid")) { field = 16; destination = &rgid; }
			else if (!strcmp(argv[i], "--ngroups")) { field = 32; destination = &ngroups; }
			else if (!strcmp(argv[i], "--groups")) field = 64;
			else { valid = false; break; }
			if (fields & field) { valid = false; break; }
			if (field == 64) {
				if (!(fields & 32) || ngroups == 0 || ngroups > NGROUPS_MAX || ngroups > (uint32_t)(argc - i - 1)) {
					valid = false;
					break;
				}
				for (uint32_t k = 0; k < ngroups; k++) {
					uint32_t group;
					if (!parse_credential_number(argv[++i], &group) || group == UINT32_MAX) {
						valid = false;
						break;
					}
					groups[k] = group;
				}
				if (!valid) break;
			} else {
				uint32_t value;
				if (i + 1 >= argc || !parse_credential_number(argv[++i], &value)) { valid = false; break; }
				if (field == 1) {
					if (value > INT_MAX) { valid = false; break; }
					fd = (int)value;
				} else {
					if (value == UINT32_MAX) { valid = false; break; }
					*destination = value;
				}
			}
			fields |= field;
		}

		if (gDyldHookLog) {
			_simple_dprintf(2, "DYLD_HOOK_SETUID (fd=%d, uid=%u, ruid=%u, gid=%u, rgid=%u)\n", fd, uid, ruid, gid, rgid);
		}

		if (fd == -1) return;
		if (!valid || fields != 127 || ngroups == 0 || ngroups > NGROUPS_MAX || groups[0] != gid) {
			char failure = 0;
			write(fd, &failure, sizeof(failure));
			__asm("b .");
			return;
		}

		int credentialResult = setgid(gid);
		credentialResult |= setgid(gid);
		credentialResult |= setregid(rgid, -1);
		credentialResult |= setgroups(ngroups, groups);
			// Both IDs must be installed before a non-root effective UID removes that authority.
			credentialResult |= setreuid(ruid, uid);

		// if (gDyldHookLog) {
		// 	uid_t uid  = getuid();
		// 	uid_t euid = geteuid();
		// 	gid_t gid  = getgid();
		// 	gid_t egid = getegid();

		// 	_simple_dprintf(2, "PID  : %d\n", (int)getpid());
		// 	_simple_dprintf(2, "PPID : %d\n", (int)getppid());
		// 	_simple_dprintf(2, "uid  : real=%d  effective=%d\n", (int)uid,  (int)euid);
		// 	_simple_dprintf(2, "gid  : real=%d  effective=%d\n", (int)gid,  (int)egid);
		// }

		char r = credentialResult == 0 ? 0x42 : 0;
		write(fd, &r, sizeof(r));

		__asm("b .");
	}

	// If DYLD_INSERT_LIBRARIES is not set or does not contain systemhook, bail out
	const char *insertLibrariesVar = _simple_getenv(envp, "DYLD_INSERT_LIBRARIES");
	if (!insertLibrariesVar) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Not checking in, DYLD_INSERT_LIBRARIES was not found\n");
		}
		return;		
	}
	if (!strstr(insertLibrariesVar, "/usr/lib/systemhook-") &&
	    !strstr(insertLibrariesVar, "/basebin/systemhook.dylib") &&
	    !strstr(insertLibrariesVar, "/basebin/systemhook-")) {
		if (gDyldHookLog) {
			_simple_dprintf(2, "Not checking in, no systemhook found in DYLD_INSERT_LIBRARIES (%s)\n", insertLibrariesVar);
		}
		return;
	}

	// No-kcall fallback only needs enough access for stock dyld to load the
	// direct-JBROOT systemhook.  The parent pre-seeds extensions targeted to
	// this suspended process; consume them here without doing the full RootHide
	// process check-in before stock dyld has started.  systemhook will perform
	// the normal full check-in later, at the historical constructor timing.
	if (gDyldhookBootstrapReturn != 0) {
		if (consume_tokenized_sandbox_extensions(gDyldhookBootstrapSandboxExtensions) == 0) {
			memset(gDyldhookBootstrapSandboxExtensions, 0, sizeof(gDyldhookBootstrapSandboxExtensions));
			return;
		}
		// Preserve the old fallback behavior if the pre-seeded tokens were not
		// consumable; this keeps explicit/full dyld replacement semantics intact.
		memset(gDyldhookBootstrapSandboxExtensions, 0, sizeof(gDyldhookBootstrapSandboxExtensions));
	}

	// If all is well, do check-in right here before dyld_start!
	dyldhook_perform_checkin();
}
