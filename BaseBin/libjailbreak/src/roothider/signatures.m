#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/FileStream.h>
#include <mach-o/dyld.h>
#include "../trustcache.h"
#include "../roothider.h"
#include "../signatures.h"

#include <sys/stat.h>
#include <sys/mount.h>
#import <Foundation/Foundation.h>

#define DEBUG_LOG(...) //JBLogDebug(__VA_ARGS__)

MachO* fat_find_preferred_slice(Fat *fat)
{
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	if (host_get_cpu_information(&cputype, &cpusubtype) != 0) { return NULL; }
	
	MachO *candidateSlice = NULL;

	if (cpusubtype == CPU_SUBTYPE_ARM64E) {
		// New arm64e ABI
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
		if (!candidateSlice) {
			// Old arm64e ABI
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E);
			if (candidateSlice) {
				// If we found an old arm64e slice, make sure this is a library! If it's a binary, skip!!!
				// For binaries the system will fall back to the arm64 slice, which has the CDHash that we want to add
				if (macho_get_filetype(candidateSlice) == MH_EXECUTE) candidateSlice = NULL;
			}
		}
	}

	if (!candidateSlice) {
		// On iOS 15+ the kernels prefers ARM64_V8 to ARM64_ALL
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_V8);
		if (!candidateSlice) {
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_ALL);
		}
	}

	return candidateSlice;
}

extern bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob);

typedef struct {
	bool Valid;
	uint32_t Type;
	uint32_t Subtype;
} executionArchInfo;

static MachO *fat_find_execution_slice(Fat *fat, executionArchInfo *arch)
{
	if (!fat || !arch || !arch->Valid) return fat ? fat_find_preferred_slice(fat) : NULL;

	MachO *macho = fat_find_slice(fat, arch->Type, arch->Subtype);
	if (arch->Type != CPU_TYPE_ARM64) return macho;

	uint32_t baseSubtype = arch->Subtype & ~CPU_SUBTYPE_MASK;
	if (baseSubtype == CPU_SUBTYPE_ARM64E) {
		bool requestsV2 = (arch->Subtype & CPU_SUBTYPE_ARM64E_ABI_V2) != 0;
		if (macho && (requestsV2 || macho_get_filetype(macho) != MH_EXECUTE)) return macho;
		macho = NULL;
		if (!requestsV2) {
			macho = fat_find_slice(fat, arch->Type, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
			if (macho) return macho;
		}
		macho = fat_find_slice(fat, arch->Type, CPU_SUBTYPE_ARM64E);
		if (macho && macho_get_filetype(macho) == MH_EXECUTE) macho = NULL;
		if (!macho) macho = fat_find_slice(fat, arch->Type, CPU_SUBTYPE_ARM64_V8);
		if (!macho) macho = fat_find_slice(fat, arch->Type, CPU_SUBTYPE_ARM64_ALL);
		return macho;
	}
	if (macho) return macho;

	if (baseSubtype == CPU_SUBTYPE_ARM64_V8) {
		macho = fat_find_slice(fat, arch->Type, CPU_SUBTYPE_ARM64_ALL);
	} else if (baseSubtype == CPU_SUBTYPE_ARM64_ALL) {
		macho = fat_find_slice(fat, arch->Type, CPU_SUBTYPE_ARM64_V8);
	}
	return macho;
}

NSString* resolveLoaderExecutablePaths(NSString *loadPath, NSString *loaderPath, NSString *mainExecutablePath)
{
	if ([loadPath hasPrefix:@"@loader_path/"] || [loadPath isEqualToString:@"@loader_path"]) {
		return [loadPath stringByReplacingCharactersInRange:NSMakeRange(0,sizeof("@loader_path")-1) withString:loaderPath.stringByDeletingLastPathComponent];
	}
	if ([loadPath hasPrefix:@"@executable_path/"] || [loadPath isEqualToString:@"@executable_path"]) {
		return [loadPath stringByReplacingCharactersInRange:NSMakeRange(0,sizeof("@executable_path")-1) withString:mainExecutablePath.stringByDeletingLastPathComponent];
	}
	return nil;
};

NSString* resolveRpaths(NSString *subPath, NSString *mainExecutablePath, NSArray* rpathStack, executionArchInfo *executionArch)
{
@autoreleasepool {

	DEBUG_LOG("Resolving rpaths for %s, mainExecutable: %s, rpathStack: %s", subPath.fileSystemRepresentation, mainExecutablePath.fileSystemRepresentation, rpathStack.description.UTF8String);

	__block NSString *rpathResolvedPath = nil;

	for (NSString* loaderPath in rpathStack.reverseObjectEnumerator)
	{
		Fat *fat = fat_init_from_path(loaderPath.fileSystemRepresentation);
		if (fat) {
			MachO *macho = [loaderPath isEqualToString:mainExecutablePath]
				? fat_find_execution_slice(fat, executionArch)
				: fat_find_preferred_slice(fat);
			if (macho) {
				macho_enumerate_rpaths(macho, ^(const char *rpathCStr, bool *stop) {
					NSString* possiblePath = [@(rpathCStr) stringByAppendingPathComponent:subPath];
					possiblePath = resolveLoaderExecutablePaths(possiblePath, loaderPath, mainExecutablePath) ?: possiblePath;
					if(![possiblePath hasPrefix:@"/"]) { // dyld only supports relative path in rpath on macOS
						JBLogDebug("Skipping relative rpath: %s -> %s", subPath.fileSystemRepresentation, possiblePath.fileSystemRepresentation);
						return;
					}
					if (_dyld_shared_cache_contains_path(possiblePath.fileSystemRepresentation)
					 || [[NSFileManager defaultManager] fileExistsAtPath:possiblePath]) {
						rpathResolvedPath = possiblePath;
						*stop = true;
					}
				});
			}
			fat_free(fat);
		}

		if(rpathResolvedPath)
			break;
	}
	
	return rpathResolvedPath;

} //autoreleasepool
}

NSString *resolveLoadPath(NSString *loadPath, NSString *loaderPath, NSString *mainExecutablePath, NSString* workingDir, NSArray* rpathStack, executionArchInfo *executionArch)
{
	if (!loadPath) return nil;

	if ([loadPath hasPrefix:@"@rpath/"]) {
		return resolveRpaths([loadPath substringFromIndex:(sizeof("@rpath/")-1)], mainExecutablePath, rpathStack, executionArch);
	}
	
	NSString *expandedPath = resolveLoaderExecutablePaths(loadPath, loaderPath, mainExecutablePath);
	if (expandedPath) {
		return expandedPath;
	}

	if([loadPath hasPrefix:@"@"]) { // dyld does not support this path
		JBLogDebug("Skipping unresolvable loadPath: %s", loadPath.fileSystemRepresentation);
		return nil;
	}

	if(![loadPath hasPrefix:@"/"])
	{
		JBLogDebug("Resolving relative path: %s", loadPath.fileSystemRepresentation);

		//non-@ path is treated as an implicit @rpath first
		NSString* resolvedPath = resolveRpaths(loadPath, mainExecutablePath, rpathStack, executionArch);

		if(!resolvedPath && workingDir) {
			resolvedPath = [workingDir stringByAppendingPathComponent:loadPath];
		}

		return resolvedPath;
	}
	
	return loadPath; //absolute path
}

typedef struct {
	uint32_t Count;
	uint32_t* Types;
	uint32_t* Subtypes;
} preferredArchInfo;

static bool recursive_path_matches_open_file(const char *path, const struct stat *openedStat)
{
	struct stat currentStat = {0};
	if (!path || !openedStat || stat(path, &currentStat) != 0) return false;
	return currentStat.st_dev == openedStat->st_dev &&
		currentStat.st_ino == openedStat->st_ino &&
		currentStat.st_gen == openedStat->st_gen;
}

static int recurse_handler(NSString *loadPath, NSString *loaderPath, NSString *mainExecutablePath, NSString *workingDir, NSMutableArray* fileCaches, NSMutableArray* rpathStack, preferredArchInfo* preferredArch, executionArchInfo *executionArch, bool weakDependency, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
@autoreleasepool {

	DEBUG_LOG("Recursing into loadPath: %s\n\tloader: %s\n\tmainExecutable: %s\nworkingDir: %s\n", loadPath.fileSystemRepresentation, loaderPath.fileSystemRepresentation, mainExecutablePath.fileSystemRepresentation, workingDir.fileSystemRepresentation);

	bool (^cdhashesContains)(cdhash_t) = ^bool(cdhash_t cdhash) {
		for (int i = 0; i < (*cdhashCountOut); i++) {
			if (!memcmp((*cdhashesOut)[i], cdhash, sizeof(cdhash_t))) {
				return true;
			}
		}
		return false;
	};
		bool (^cdhashesAdd)(cdhash_t) = ^bool(cdhash_t cdhash) {
			uint32_t newCount = (*cdhashCountOut) + 1;
			cdhash_t *newHashes = realloc((*cdhashesOut), newCount * sizeof(cdhash_t));
			if (!newHashes) return false;
			(*cdhashesOut) = newHashes;
			memcpy((*cdhashesOut)[newCount - 1], cdhash, sizeof(cdhash_t));
			(*cdhashCountOut) = newCount;
			return true;
		};


			NSString *resolvedLoadPath = resolveLoadPath(loadPath, loaderPath, mainExecutablePath, workingDir, rpathStack, executionArch);
		if(!resolvedLoadPath) {
			JBLogError("Failed to resolve dependency library for %s (loader: %s, mainExecutable: %s)", loadPath.fileSystemRepresentation, loaderPath.fileSystemRepresentation, mainExecutablePath.fileSystemRepresentation);
			return weakDependency ? 0 : -1;
		}

		if(_dyld_shared_cache_contains_path(resolvedLoadPath.fileSystemRepresentation)) {
			DEBUG_LOG("Skipping dyld shared cached library: %s", resolvedLoadPath.fileSystemRepresentation);
			return 0;
		}

	char realfilepath[PATH_MAX] = {0};
		int fd = open(resolvedLoadPath.fileSystemRepresentation, O_RDONLY);
		if (fd < 0) {
			JBLogError("Failed to open binary at path: %s (loader: %s)", resolvedLoadPath.fileSystemRepresentation, loaderPath.fileSystemRepresentation);
			return weakDependency && errno == ENOENT ? 0 : -1;
		}
		if(fcntl(fd, F_GETPATH, realfilepath) != 0) {
			JBLogError("Failed to get file path for fd %d", fd);
			close(fd);
			return -1;
		}
		struct stat openedStat = {0};
		if (fstat(fd, &openedStat) != 0) {
			close(fd);
			return -1;
		}

		if(string_has_prefix(realfilepath, "/private/preboot/Cryptexes/")) {
			JBLogDebug("Skipping Cryptexes file: %s", realfilepath);
			close(fd);
			return 0;
		}
	
		if(isRemovableBundlePath(realfilepath) && !hasTrollstoreLiteMarker(realfilepath)) {
			// ignore adhoc signed apps(removable system apps or other stuffs) which is not installed via tslite
			JBLogDebug("ignoring addhoc signed app: %s\n", realfilepath);
			close(fd);
			return 0;
		}
	
		struct statfs fs;
		int sfsret = statfs(realfilepath, &fs);
		if(sfsret == 0) {
			if(strcmp(fs.f_mntonname, "/")==0 || strcmp(fs.f_mntonname, "/Developer")==0) {
				close(fd);
				return 0;
			}
		}

	NSString* realLoadPath = @(realfilepath);

	DEBUG_LOG("loadPath = %s, \n\tresolvedLoadPath = %s, \n\trealLoadPath = %s\n", loadPath.fileSystemRepresentation, resolvedLoadPath.fileSystemRepresentation, realLoadPath.fileSystemRepresentation);

		if([fileCaches containsObject:realLoadPath]) {
			DEBUG_LOG("Skipping already parsed file: %s", realLoadPath.fileSystemRepresentation);
			close(fd);
			return 0; // Already parsed
		}
	//add realLoadPath to fileCaches
	[fileCaches addObject:realLoadPath];
	
		ensure_jbroot_symlink(realLoadPath.fileSystemRepresentation);

			MemoryStream *stream = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
			if (!stream) {
				close(fd);
				return -1;
			}
			Fat *fat = fat_init_from_memory_stream(stream);
			if (!fat) {
				memory_stream_free(stream);
				close(fd);
				JBLogError("Failed to parse fat binary at path: %s", realLoadPath.fileSystemRepresentation);
				return -1;
			}
			if (!recursive_path_matches_open_file(realLoadPath.fileSystemRepresentation, &openedStat)) {
				fat_free(fat);
				close(fd);
				return ESTALE;
			}

		MachO *macho = NULL;
		bool isMainExecutable = [loadPath isEqualToString:mainExecutablePath];
		if (isMainExecutable) {
			if (preferredArch->Count > 0) {
			for (size_t i = 0; i < preferredArch->Count; i++) {
				if (preferredArch->Types[i] != 0 && preferredArch->Subtypes[i] != UINT32_MAX) {
					macho = fat_find_slice(fat, preferredArch->Types[i], preferredArch->Subtypes[i]);
					if (macho) break;
				}
				}
			}
			if (!macho && executionArch->Valid) macho = fat_find_execution_slice(fat, executionArch);
		}
		if (!macho) {
			macho = fat_find_preferred_slice(fat);
				if (!macho) {
					JBLogError("Failed to find preferred slice for file: %s", realLoadPath.fileSystemRepresentation);
					fat_free(fat);
					close(fd);
					return -1;
				}
		}
		if (isMainExecutable) {
			executionArch->Valid = true;
			executionArch->Type = macho->machHeader.cputype;
			executionArch->Subtype = macho->machHeader.cpusubtype;
		}

	// Calculate cdhash and add it to our array
		bool cdhashWasKnown = true;
		bool isAdhocSigned = false;
		CS_SuperBlob *superblob = macho_read_code_signature(macho);
		if (superblob) {
			CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
				if (!decodedSuperblob) {
					free(superblob);
					fat_free(fat);
					close(fd);
					return -1;
				}
			if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
				isAdhocSigned = true;
				cdhash_t cdhash = {0};
					if (csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhash, NULL) != 0) {
						csd_superblob_free(decodedSuperblob);
						free(superblob);
						fat_free(fat);
						close(fd);
						return -1;
					}
					if (!cdhashesContains(cdhash)) {
						if (!is_cdhash_trustcached(cdhash)) {
							if (!cdhashesAdd(cdhash)) {
								csd_superblob_free(decodedSuperblob);
								free(superblob);
								fat_free(fat);
								close(fd);
								return -1;
							}
						}
						cdhashWasKnown = false;
					}

					struct siginfo sigInfo = {
						.source = SIGNATURE_SOURCE_ALLOCATION,
						.signature = {
							.fs_file_start = macho->archDescriptor.offset,
							.fs_blob_start = superblob,
							.fs_blob_size = OSSwapBigToHostInt32(superblob->length),
						},
					};
					int trustResult = trust_signatures(0, fd, &sigInfo, 1);
					if (sigInfo.source == SIGNATURE_SOURCE_ALLOCATION) free(sigInfo.signature.fs_blob_start);
					superblob = NULL;
					if (trustResult != 0) {
						csd_superblob_free(decodedSuperblob);
						fat_free(fat);
						close(fd);
						return trustResult;
					}
					if (!recursive_path_matches_open_file(realLoadPath.fileSystemRepresentation, &openedStat)) {
						csd_superblob_free(decodedSuperblob);
						fat_free(fat);
						close(fd);
						return ESTALE;
					}
				}
				csd_superblob_free(decodedSuperblob);
				free(superblob);
			}
			close(fd);

		if (cdhashWasKnown || // If we already knew the cdhash, we can skip parsing dependencies
				!isAdhocSigned) { // If it was not ad hoc signed, we can safely skip it aswell
				fat_free(fat);
				return 0;
		}

		// Recurse this block on all dependencies
		__block int dependencyResult = 0;
		macho_enumerate_dependencies(macho, ^(const char *pathCStr, uint32_t cmd, struct dylib* dylib, bool *stop) {

		NSMutableArray* nextChain = rpathStack.mutableCopy;
		[nextChain addObject:realLoadPath]; //Loading dependencies, add current macho itself to the rpath stack
		
				int childResult = recurse_handler(@(pathCStr), realLoadPath, mainExecutablePath, workingDir, fileCaches, nextChain, preferredArch, executionArch, cmd == LC_LOAD_WEAK_DYLIB, cdhashesOut, cdhashCountOut);
			if (childResult != 0) {
				dependencyResult = childResult;
				*stop = true;
			}
		});

		fat_free(fat);
		return dependencyResult;
} //autoreleasepool
}

int recurse_collect_untrusted_cdhashes(const char *path, const char *callerImagePath, const char *callerExecutablePath, const char *workingDir, preferredArchInfo* preferredArch, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
		if (!path || !preferredArch || !cdhashesOut || !cdhashCountOut) return -1;
		executionArchInfo executionArch = {0};
		for (size_t i = 0; i < preferredArch->Count; i++) {
			if (preferredArch->Types[i] != 0 && preferredArch->Subtypes[i] != UINT32_MAX) {
				executionArch.Valid = true;
				executionArch.Type = preferredArch->Types[i];
				executionArch.Subtype = preferredArch->Subtypes[i];
				break;
			}
		}
		if(!callerExecutablePath) {
			callerExecutablePath = path;
	}

	NSMutableArray* rpathStack = [NSMutableArray array];

	[rpathStack addObject:@(callerExecutablePath)]; //initial rpath stack
	
	if(callerImagePath && strcmp(callerImagePath, callerExecutablePath) != 0) {
		[rpathStack addObject:@(callerImagePath)];
	}

	if(!callerImagePath) {
		callerImagePath = path;
	}

	NSMutableArray* fileCaches = [NSMutableArray array];

		int result = recurse_handler(@(path), @(callerImagePath), @(callerExecutablePath), workingDir ? @(workingDir) : nil, fileCaches, rpathStack, preferredArch, &executionArch, false, cdhashesOut, cdhashCountOut);

		DEBUG_LOG("fileCaches: %s", path, fileCaches.description.UTF8String);
		DEBUG_LOG("Finished collecting cdhashes for path: %s, found %u cdhashes, processed %d files", path, *cdhashCountOut, fileCaches.count);
		return result;
}
