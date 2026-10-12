#include "common.h"
#include "../roothider.h"
#include <xpc/xpc.h>
#include <xpc_private.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sandbox.h>
#include <paths.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stddef.h>
#include <dlfcn.h>
#include <stdlib.h>
#include "envbuf.h"
#include "private.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/jbserver_domains.h>
#include <libjailbreak/util.h>
#include <libjailbreak/jbroot.h>
#include <libjailbreak/hookd.h>
#include <libkern/OSCacheControl.h>

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char* str, const char* suffix)
{
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

static bool colon_list_contains_component(const char *list, const char *component)
{
	if (!list || !component || !component[0]) return false;
	size_t componentLength = strlen(component);
	const char *cursor = list;
	while (*cursor) {
		const char *end = strchr(cursor, ':');
		size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
		if (length == componentLength && strncmp(cursor, component, length) == 0) return true;
		if (!end) break;
		cursor = end + 1;
	}
	return false;
}

static char *colon_list_prepend_component(const char *list, const char *component)
{
	if (!component || !component[0]) return list ? strdup(list) : NULL;
	size_t componentLength = strlen(component);
	size_t listLength = list ? strlen(list) : 0;
	char *result = malloc(componentLength + (listLength ? listLength + 1 : 0) + 1);
	if (!result) return NULL;
	memcpy(result, component, componentLength);
	if (listLength) {
		result[componentLength] = ':';
		memcpy(result + componentLength + 1, list, listLength);
		result[componentLength + 1 + listLength] = '\0';
	}
	else {
		result[componentLength] = '\0';
	}
	return result;
}

static char *colon_list_remove_component(const char *list, const char *component)
{
	if (!list) return NULL;
	if (!component || !component[0]) return strdup(list);
	char *result = calloc(1, strlen(list) + 1);
	if (!result) return NULL;
	bool first = true;
	size_t componentLength = strlen(component);
	const char *cursor = list;
	while (*cursor) {
		const char *end = strchr(cursor, ':');
		size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
		if (!(length == componentLength && strncmp(cursor, component, length) == 0)) {
			if (!first) strcat(result, ":");
			strncat(result, cursor, length);
			first = false;
		}
		if (!end) break;
		cursor = end + 1;
	}
	return result;
}

void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop))
{
	if (!string || !separator || !enumBlock) return;
	char *stringCopy = strdup(string);
	if (!stringCopy) return;
	char *state = NULL;
	char *curString = strtok_r(stringCopy, separator, &state);
	while (curString != NULL) {
		bool stop = false;
		enumBlock(curString, &stop);
		if (stop) break;
		curString = strtok_r(NULL, separator, &state);
	}
	free(stringCopy);
}

int timespec_compare(struct timespec *t1, struct timespec *t2)
{
	if (t1->tv_sec == t2->tv_sec && t1->tv_nsec == t2->tv_nsec) return 0;

	if (t1->tv_sec == t2->tv_sec) {
		return t1->tv_nsec > t2->tv_nsec ? 1 : -1;
	}
	else {
		return t1->tv_sec > t2->tv_sec ? 1 : -1;
	}
}

static bool config_file_matches(const struct stat *left, const struct stat *right)
{
	return left->st_dev == right->st_dev && left->st_ino == right->st_ino && left->st_size == right->st_size &&
		left->st_mtimespec.tv_sec == right->st_mtimespec.tv_sec && left->st_mtimespec.tv_nsec == right->st_mtimespec.tv_nsec &&
		left->st_ctimespec.tv_sec == right->st_ctimespec.tv_sec && left->st_ctimespec.tv_nsec == right->st_ctimespec.tv_nsec;
}

static xpc_object_t config_read_plist(const char *path, struct stat *loadedStat)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return NULL;
	struct stat before, after;
	if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0 || (uint64_t)before.st_size > SSIZE_MAX) {
		close(fd);
		return NULL;
	}
	size_t length = (size_t)before.st_size;
	void *bytes = malloc(length);
	if (!bytes) {
		close(fd);
		return NULL;
	}
	// Reading into owned storage avoids SIGBUS when an in-place writer truncates the plist.
	size_t offset = 0;
	while (offset < length) {
		ssize_t received = read(fd, (uint8_t *)bytes + offset, length - offset);
		if (received < 0 && errno == EINTR) continue;
		if (received <= 0) break;
		offset += (size_t)received;
	}
	bool complete = offset == length && fstat(fd, &after) == 0 && config_file_matches(&before, &after);
	close(fd);
	xpc_object_t object = complete ? xpc_create_from_plist(bytes, length) : NULL;
	free(bytes);
	if (object && loadedStat) *loadedStat = after;
	return object;
}

xpc_object_t xpc_object_from_plist(const char *path)
{
	return config_read_plist(path, NULL);
}

struct config_snapshot {
	xpc_object_t dictionary;
	struct stat identity;
};

static pthread_key_t configSnapshotKey;
static pthread_once_t configSnapshotOnce = PTHREAD_ONCE_INIT;
static int configSnapshotKeyError;

static void config_snapshot_destroy(void *context)
{
	struct config_snapshot *snapshot = context;
	if (snapshot->dictionary) xpc_release(snapshot->dictionary);
	free(snapshot);
}

static void config_snapshot_initialize(void)
{
	configSnapshotKeyError = pthread_key_create(&configSnapshotKey, config_snapshot_destroy);
}

xpc_object_t jbuserconfig_copy_value(const char *key)
{
	if (!key || pthread_once(&configSnapshotOnce, config_snapshot_initialize) != 0 || configSnapshotKeyError) return NULL;
	struct config_snapshot *snapshot = pthread_getspecific(configSnapshotKey);
	if (!snapshot) {
		snapshot = calloc(1, sizeof(*snapshot));
		if (!snapshot) return NULL;
		if (pthread_setspecific(configSnapshotKey, snapshot) != 0) {
			free(snapshot);
			return NULL;
		}
	}

	const char *configPath = JBROOT_PATH("/basebin/config.plist");
	struct stat identity;
	if (stat(configPath, &identity) != 0) {
		if (errno == ENOENT && snapshot->dictionary) {
			xpc_release(snapshot->dictionary);
			snapshot->dictionary = NULL;
		}
	}
	else if (!snapshot->dictionary || !config_file_matches(&identity, &snapshot->identity)) {
		xpc_object_t replacement = config_read_plist(configPath, &identity);
		if (replacement) {
			if (xpc_get_type(replacement) == XPC_TYPE_DICTIONARY) {
				xpc_object_t previous = snapshot->dictionary;
				snapshot->dictionary = replacement;
				snapshot->identity = identity;
				if (previous) xpc_release(previous);
			}
			else xpc_release(replacement);
		}
	}
	if (!snapshot->dictionary) return NULL;
	xpc_object_t value = xpc_dictionary_get_value(snapshot->dictionary, key);
	return value ? xpc_retain(value) : NULL;
}

kSpawnConfig spawn_config_for_executable(const char* path, char *const argv[restrict])
{
	// Blacklist to ensure general system stability
	// I don't like this but for some processes it seems neccessary
	const char *processBlacklist[] = {
		"/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
		"/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd",
		"/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
		"/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService",
	};
	size_t blacklistCount = sizeof(processBlacklist) / sizeof(processBlacklist[0]);
	for (size_t i = 0; i < blacklistCount; i++)
	{
		if (!strcmp(processBlacklist[i], path)) return 0;
	}

	kSpawnConfig result = kSpawnConfigInject | kSpawnConfigTrust;
	xpc_object_t userBlacklist = jbuserconfig_copy_value("ProcessBlacklist");
	if (userBlacklist && xpc_get_type(userBlacklist) == XPC_TYPE_ARRAY) {
		size_t userBlacklistCount = xpc_array_get_count(userBlacklist);
		for (size_t i = 0; i < userBlacklistCount; i++) {
			xpc_object_t item = xpc_array_get_value(userBlacklist, i);
			const char *entry = xpc_get_type(item) == XPC_TYPE_STRING ? xpc_string_get_string_ptr(item) : NULL;
			if (entry && !strcmp(entry, path)) {
				result = kSpawnConfigTrust;
				break;
			}
		}
	}
	if (userBlacklist) xpc_release(userBlacklist);
	return result;
}

// 1. Ensure the binary about to be spawned and all of it's dependencies are trust cached
// 2. Insert "DYLD_INSERT_LIBRARIES=/usr/lib/systemhook.dylib" into all binaries spawned
// 3. Increase Jetsam limit to more sane value (Multipler defined as JETSAM_MULTIPLIER)
// 4. Fix spawning as root via persona entitlement on iOS 17.6+

static int copy_spawn_attributes(const struct _posix_spawn_args_desc *source, struct _posix_spawn_args_desc *copy,
									void **ownedAttributes, void **ownedPersona)
{
	*ownedAttributes = NULL;
	*ownedPersona = NULL;
	*copy = *source;
	if (!source->attrp) return 0;
	if (source->attr_size < POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE + sizeof(int)) return EINVAL;

	void *attributes = malloc(source->attr_size);
	if (!attributes) return ENOMEM;
	memcpy(attributes, source->attrp, source->attr_size);

	const void *persona = source->persona_info;
	size_t personaSize = source->persona_info_size;
	bool hasPersonaSlot = source->attr_size >= POSIX_SPAWNATTR_OFF_PERSONA + sizeof(void *);
	if (!persona && hasPersonaSlot) {
		memcpy(&persona, (uint8_t *)source->attrp + POSIX_SPAWNATTR_OFF_PERSONA, sizeof(persona));
		if (persona) personaSize = sizeof(struct _posix_spawn_persona_info);
	}
	if (persona) {
		if (personaSize < offsetof(struct _posix_spawn_persona_info, pspi_gid) + sizeof(gid_t)) {
			free(attributes);
			return EINVAL;
		}
		void *personaCopy = malloc(personaSize);
		if (!personaCopy) {
			free(attributes);
			return ENOMEM;
		}
		memcpy(personaCopy, persona, personaSize);
		if (hasPersonaSlot) memcpy((uint8_t *)attributes + POSIX_SPAWNATTR_OFF_PERSONA, &personaCopy, sizeof(personaCopy));
		copy->persona_info = personaCopy;
		copy->persona_info_size = personaSize;
		*ownedPersona = personaCopy;
	}
	copy->attrp = (posix_spawnattr_t)attributes;
	*ownedAttributes = attributes;
	return 0;
}

static bool hook_dylib_backing_path(char pathOut[PATH_MAX])
{
	if (!HOOK_DYLIB_PATH || !HOOK_DYLIB_PATH[0] || !pathOut) return false;
	if (access(HOOK_DYLIB_PATH, F_OK) == 0) {
		strlcpy(pathOut, HOOK_DYLIB_PATH, PATH_MAX);
		return true;
	}
	if (!HOOK_DYLIB_SEARCH_PATH || !HOOK_DYLIB_SEARCH_PATH[0]) return false;
	const char *leaf = strrchr(HOOK_DYLIB_PATH, '/');
	leaf = leaf ? leaf + 1 : HOOK_DYLIB_PATH;
	if (snprintf(pathOut, PATH_MAX, "%s/%s", HOOK_DYLIB_SEARCH_PATH, leaf) <= 0) return false;
	return access(pathOut, F_OK) == 0;
}

static bool path_is_within_jbroot(const char *path)
{
	if (!path || !path[0]) return false;
	const char *jbroot = get_jbroot();
	if (!jbroot || !jbroot[0]) return false;

	char resolvedPath[PATH_MAX];
	char resolvedRoot[PATH_MAX];
	if (!realpath(path, resolvedPath) || !realpath(jbroot, resolvedRoot)) return false;

	size_t rootLength = strlen(resolvedRoot);
	while (rootLength > 1 && resolvedRoot[rootLength - 1] == '/') rootLength--;
	if (strncmp(resolvedPath, resolvedRoot, rootLength) != 0) return false;
	return resolvedPath[rootLength] == '\0' || resolvedPath[rootLength] == '/';
}

static bool path_eligible_for_private_search_injection(const char *path)
{
	if (path_is_within_jbroot(path)) return true;
	// Outside JBROOT, the no-kcall fallback is for ordinary installed apps only.
	// This binary links the RootHide RPC client, not the Objective-C blacklist
	// implementation. A failed lookup must not opt an app back into injection.
	if (!isRemovableBundlePath(path)) return false;
	bool blacklisted = false;
	return jbclient_blacklist_check_path_checked(path, &blacklisted) == 0 && !blacklisted;
}

static int spawn_exec_hook_common(bool isExec,
						   const char *path,
						   char *const argv[restrict],
						   char *const envp[restrict],
		struct _posix_spawn_args_desc *desc,
								 int (*trust_binary)(const char *path),
								double jetsamMultiplier,
									 int (^orig)(pid_t *pid, char *const envp[restrict], struct _posix_spawn_args_desc *patchedDesc))
{
		if (!path) {
			return orig(NULL, envp, desc);
		}

		struct _posix_spawn_args_desc privateDesc;
		void *ownedAttributes = NULL;
		void *ownedPersona = NULL;
		int r = 0;
		if (desc) {
			r = copy_spawn_attributes(desc, &privateDesc, &ownedAttributes, &ownedPersona);
			if (r != 0) return r;
			desc = &privateDesc;
		}

	bool personaFixNeedsResume = true;
	int personaFixUid = -1;
	int personaFixGid = -1;
	posix_spawnattr_t attr = NULL;
	if (desc) attr = desc->attrp;

	kSpawnConfig spawnConfig = spawn_config_for_executable(path, argv);

	if (spawnConfig & kSpawnConfigTrust) {
		// Upload binary to trustcache if needed
		trust_binary(path);
	}

		const char *existingLibraryInserts = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES");
		__block bool systemHookAlreadyInserted = false;
		if (existingLibraryInserts) {
			string_enumerate_components(existingLibraryInserts, ":", ^(const char *existingLibraryInsert, bool *stop) {
				if (!strcmp(existingLibraryInsert, HOOK_DYLIB_PATH)) {
					systemHookAlreadyInserted = true;
				}
			});
		}
		const char *existingLibrarySearchPath = envbuf_getenv((const char **)envp, "DYLD_LIBRARY_PATH");
		bool hookSearchAlreadyInserted = HOOK_DYLIB_SEARCH_PATH &&
			colon_list_contains_component(existingLibrarySearchPath, HOOK_DYLIB_SEARCH_PATH);

		int JBEnvAlreadyInsertedCount = (int)systemHookAlreadyInserted;

	// Check if we can find at least one reason to not insert jailbreak related environment variables
	// In this case we also need to remove pre existing environment variables if they are already set
		bool shouldInsertJBEnv = true;
		bool hasSafeModeVariable = false;
		do {
			if (!(spawnConfig & kSpawnConfigInject)) {
				shouldInsertJBEnv = false;
				break;
			}
			if (HOOK_DYLIB_SEARCH_PATH_JBROOT_ONLY && !path_eligible_for_private_search_injection(path)) {
				shouldInsertJBEnv = false;
				break;
			}
				// Check if we can find a _SafeMode or _MSSafeMode variable
		// In this case we do not want to inject anything
		const char *safeModeValue = envbuf_getenv((const char **)envp, "_SafeMode");
		const char *msSafeModeValue = envbuf_getenv((const char **)envp, "_MSSafeMode");
		if (safeModeValue) {
			if (!strcmp(safeModeValue, "1")) {
				if(!allowInjectWithSafeMode(path)) shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}
		if (msSafeModeValue) {
			if (!strcmp(msSafeModeValue, "1")) {
				if(!allowInjectWithSafeMode(path)) shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}

		int proctype = 0;
		if (posix_spawnattr_getprocesstype_np(&attr, &proctype) == 0) {
			if (proctype == POSIX_SPAWN_PROC_TYPE_DRIVER) {
				// Do not inject hook into DriverKit drivers
				shouldInsertJBEnv = false;
				break;
			}
		}

			char hookBackingPath[PATH_MAX];
			if (!hook_dylib_backing_path(hookBackingPath)) {
				// If the hook dylib doesn't exist, don't try to inject it (would crash the process)
				shouldInsertJBEnv = false;
			break;
		}
	} while (0);

	uint8_t *attrStruct = (uint8_t *)attr;
	if (attrStruct) {
		// If systemhook is being injected and jetsam limits are set, increase them by a factor of jetsamMultiplier
		if (shouldInsertJBEnv) {
			if (jetsamMultiplier == 0 || isnan(jetsamMultiplier)) jetsamMultiplier = 3; // default value (3x)
			if (jetsamMultiplier > 1) {
				int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
					if (memlimit_active > 0) {
						double scaled = memlimit_active * jetsamMultiplier;
						*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = scaled >= INT_MAX ? INT_MAX : (int)scaled;
				}
				int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
					if (memlimit_inactive > 0) {
						double scaled = memlimit_inactive * jetsamMultiplier;
						*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = scaled >= INT_MAX ? INT_MAX : (int)scaled;
				}
			}
		}

		// On iOS 17.6 and up Apple neutered persona overwrites to block going from (non root) -> (root)
		// Since jailbreak infra relies on this, we need to reenable it via our patches
		// To do this we will spawn the process as suspended, modify the ucred to the desired uid/gid and resume it
		// POSIX_SPAWN_SETEXEC is not a concern since using it together with POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE is not supported anyways
		if (__builtin_available(iOS 17.6, *)) {
			bool hasExecFlag = false;
			short flags = 0;
				r = posix_spawnattr_getflags(&attr, &flags);
				if (r != 0) goto cleanup;
				if (flags & POSIX_SPAWN_SETEXEC) hasExecFlag = true;
				if (!hasExecFlag && !isExec && getuid() != 0) {
					struct _posix_spawn_persona_info *personaInfo = desc->persona_info;
				if (personaInfo) {
					if (personaInfo->pspi_id == 99 && (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE)) {
						if (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_UID) {
							personaFixUid = personaInfo->pspi_uid;
						}
						if (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_GID) {
							personaFixGid = personaInfo->pspi_gid;
						}
					}
				}

				if (personaFixUid == 0 || personaFixGid == 0) {
					// Revert any request to become root back to mobile
					// Otherwise posix_spawn will straight up fail
					if (personaFixUid == 0) personaInfo->pspi_uid = 501;
					if (personaFixGid == 0) personaInfo->pspi_gid = 501;

					if (flags & POSIX_SPAWN_START_SUSPENDED) {
						personaFixNeedsResume = false;
					}
					else {
							r = posix_spawnattr_setflags(&attr, flags | POSIX_SPAWN_START_SUSPENDED);
							if (r != 0) goto cleanup;
					}
				}
			}
		}
	}

		r = -1;

	pid_t childPid = -1;

		bool hookSearchStateMatches = !HOOK_DYLIB_SEARCH_PATH ||
			(shouldInsertJBEnv ? hookSearchAlreadyInserted : !hookSearchAlreadyInserted);
		if (((shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 1) ||
			 (!shouldInsertJBEnv && JBEnvAlreadyInsertedCount == 0 && !hasSafeModeVariable)) && hookSearchStateMatches) {
		// we're already good, just call orig
			r = orig(&childPid, envp, desc);
	}
	else {
		// the state we want to be in is not the state we are in right now

		char **envc = envbuf_mutcopy((const char **)envp);

			if (shouldInsertJBEnv) {
			if (!systemHookAlreadyInserted) {
				char newLibraryInsert[strlen(HOOK_DYLIB_PATH) + (existingLibraryInserts ? (strlen(existingLibraryInserts) + 1) : 0) + 1];
				strcpy(newLibraryInsert, HOOK_DYLIB_PATH);
				if (existingLibraryInserts) {
					strcat(newLibraryInsert, ":");
					strcat(newLibraryInsert, existingLibraryInserts);
				}
				envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);
				}
				if (HOOK_DYLIB_SEARCH_PATH && !hookSearchAlreadyInserted) {
					char *newLibrarySearchPath = colon_list_prepend_component(existingLibrarySearchPath, HOOK_DYLIB_SEARCH_PATH);
					if (!newLibrarySearchPath) {
						r = ENOMEM;
						goto env_cleanup;
					}
					envbuf_setenv(&envc, "DYLD_LIBRARY_PATH", newLibrarySearchPath);
					free(newLibrarySearchPath);
				}
			}
			else {
			if (systemHookAlreadyInserted && existingLibraryInserts) {
				if (!strcmp(existingLibraryInserts, HOOK_DYLIB_PATH)) {
					envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
				}
				else {
					char *newLibraryInsert = malloc(strlen(existingLibraryInserts)+1);
					newLibraryInsert[0] = '\0';

					__block bool first = true;
					string_enumerate_components(existingLibraryInserts, ":", ^(const char *existingLibraryInsert, bool *stop) {
						if (strcmp(existingLibraryInsert, HOOK_DYLIB_PATH) != 0) {
							if (first) {
								strcpy(newLibraryInsert, existingLibraryInsert);
								first = false;
							}
							else {
								strcat(newLibraryInsert, ":");
								strcat(newLibraryInsert, existingLibraryInsert);
							}
						}
					});
					envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", newLibraryInsert);

					free(newLibraryInsert);
				}
				}
				if (HOOK_DYLIB_SEARCH_PATH && hookSearchAlreadyInserted && existingLibrarySearchPath) {
					char *newLibrarySearchPath = colon_list_remove_component(existingLibrarySearchPath, HOOK_DYLIB_SEARCH_PATH);
					if (!newLibrarySearchPath) {
						r = ENOMEM;
						goto env_cleanup;
					}
					if (newLibrarySearchPath[0]) envbuf_setenv(&envc, "DYLD_LIBRARY_PATH", newLibrarySearchPath);
					else envbuf_unsetenv(&envc, "DYLD_LIBRARY_PATH");
					free(newLibrarySearchPath);
				}
				envbuf_unsetenv(&envc, "_SafeMode");
			envbuf_unsetenv(&envc, "_MSSafeMode");
		}

				r = orig(&childPid, envc, desc);

		env_cleanup:
				envbuf_free(envc);
	}

	if (r == 0 && childPid > 0 && (personaFixUid == 0 || personaFixGid == 0)) {
		if (jbclient_persona_fix(childPid, personaFixUid, personaFixGid) != 0) {
			r = EPERM;
		}
		else if (personaFixNeedsResume && kill(childPid, SIGCONT) != 0) {
			r = errno;
		}
		if (r != 0) {
			// Running with the wrong identity is not a successful spawn.
			if (kill(childPid, SIGKILL) == 0) {
				uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC) + 1000000000ULL;
				while (waitpid(childPid, NULL, WNOHANG) == 0 && clock_gettime_nsec_np(CLOCK_MONOTONIC) < deadline) usleep(10000);
			}
		}
	}

cleanup:
		free(ownedPersona);
		free(ownedAttributes);
		return r;
}

int posix_spawn_hook_shared(pid_t *restrict pid, 
					   const char *restrict path,
			 struct _posix_spawn_args_desc *desc,
						  	    char *const argv[restrict],
					   			char *const envp[restrict],
					   				  void *orig,
					   				  int (*trust_binary)(const char *path),
					   				  int (*set_process_debugged)(uint64_t pid, bool fullyDebugged),
					   				 double jetsamMultiplier)
{
	int (*posix_spawn_orig)(pid_t *restrict, const char *restrict, struct _posix_spawn_args_desc *, char *const[restrict], char *const[restrict]) = orig;

		int r = spawn_exec_hook_common(false, path, argv, envp, desc, trust_binary, jetsamMultiplier, ^int(pid_t *pidOut, char *const envp_patched[restrict], struct _posix_spawn_args_desc *patchedDesc) {
			int rr = posix_spawn_orig(pid ?: pidOut, path, patchedDesc, argv, envp_patched);
		if (rr == 0 && pid && pidOut) {
			*pidOut = *pid;
		}
		return rr;
	});

	if (r == 0 && pid && desc) {
		posix_spawnattr_t attr = desc->attrp;
		short flags = 0;
		if (posix_spawnattr_getflags(&attr, &flags) == 0) {
			if (flags & POSIX_SPAWN_START_SUSPENDED) {
				// If something spawns a process as suspended, ensure mapping invalid pages in it is possible
				// Normally it would only be possible after systemhook.dylib enables it
				// Fixes Frida issues
				set_process_debugged(*pid, false);
			}
		}
	}

	return r;
}

kern_return_t vm_allocate_nearby(vm_map_t target_task, vm_address_t from_area, vm_size_t from_area_size, vm_address_t *address, vm_size_t size, uint64_t limit)
{
	if (from_area != 0 && from_area_size > 0 && address) {
		// Make sure allocation is within limit for every single page in the area
		uint64_t realLimit = limit - (from_area_size / 2);

		for (uint64_t off = 0; off < realLimit; off += vm_page_size) {
			vm_address_t tmp = (from_area + from_area_size) + off;
			kern_return_t kr = vm_allocate(target_task, &tmp, size, VM_FLAGS_FIXED);
			if (kr == KERN_SUCCESS) {
				*address = tmp;
				return kr;
			}

			tmp = (from_area - size) - off;
			kr = vm_allocate(target_task, &tmp, size, VM_FLAGS_FIXED);
			if (kr == KERN_SUCCESS) {
				*address = tmp;
				return kr;
			}
		}
	}

	return KERN_NO_SPACE;
}

int execve_hook_shared(const char *path,
					   char *const argv[],
					   char *const envp[],
			 				 void *orig,
			 				 int (*trust_binary)(const char *path))
{
	int (*execve_orig)(const char *, char *const[], char *const[]) = orig;

		int r = spawn_exec_hook_common(true, path, argv, envp, NULL, trust_binary, 0, ^int(pid_t *pidOut, char *const envp_patched[restrict], struct _posix_spawn_args_desc *patchedDesc){
		return execve_orig(path, argv, envp_patched);
	});

	return r;
}

__attribute__((noinline, naked)) volatile void *get_tpidrr0_el0(void)
{
	asm("MRS X0, TPIDRRO_EL0");
	asm("RET");
}

kern_return_t litehook_hook_memory_hookd(void *target, void *source, size_t sourceSize)
{
	kern_return_t kr = hookd_hook(mach_task_self_, (uint64_t)target, source, sourceSize);
	if (kr == KERN_SUCCESS) {
		sys_icache_invalidate(target, sourceSize);
	}
	return kr;
}

kern_return_t mach_vm_protect_fixed(mach_port_name_t task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
	kern_return_t rv;

	bool skipped = false;
	if (!skipped) {
		if ((new_protection & VM_PROT_EXECUTE) || (new_protection & VM_PROT_COPY)) {
			rv = hookd_vm_protect(task, address, size, set_maximum, new_protection);
		}
		else {
			rv = _kernelrpc_mach_vm_protect_trap(task, address, size, set_maximum, new_protection);
			if (rv == MACH_SEND_INVALID_DEST) {
				rv = _kernelrpc_mach_vm_protect(task, address, size, set_maximum, new_protection);
			}
		}
	}

	return rv;
}
