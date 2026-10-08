#import <Foundation/Foundation.h>

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <CoreSymbolication.h>

#include "../libjailbreak.h"
#include "../codesign.h"
#include "../jbserver.h"
#include "common.h"
#include "log.h"
#include "bootlog.h"
#include "dyld_task_metadata_policy.h"

uint64_t show_dyld_regions(mach_port_t task, bool more)
{
    uint64_t dyld_address = 0;
    
    vm_address_t region_base = 0;
    vm_size_t region_size = 0;

    // vm_region_basic_info_data_64_t info;
	// vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
    // mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;

    vm_region_extended_info_data_t info;
	vm_region_flavor_t flavor = VM_REGION_EXTENDED_INFO;
    mach_msg_type_number_t info_count = VM_REGION_EXTENDED_INFO_COUNT;

    while (true) {
        region_base += region_size;

        mach_port_t object_name;
        kern_return_t kr = vm_region_64(task, &region_base, &region_size, flavor, (vm_region_info_t) &info, &info_count, &object_name);
        if (kr != KERN_SUCCESS) break;

        if(dyld_address != 0) {
		    // JBLogDebug("show_dyld_regions: region base=%llx size=%llx prot=%x/%x inhert=%d shared=%d", region_base, region_size, info.protection, info.max_protection, info.inheritance, info.shared);
            JBLogDebug("show_dyld_regions: region base=%llx size=%llx prot=%x/%x inhert=%d share_mode=%d", region_base, region_size, info.protection, -1, -1, info.share_mode);
        }

		if(info.protection==(VM_PROT_READ|VM_PROT_EXECUTE)) {
            // JBLogDebug("show_dyld_regions: region base=%llx size=%llx prot=%x/%x inhert=%d shared=%d", region_base, region_size, info.protection, info.max_protection, info.inheritance, info.shared);
            JBLogDebug("show_dyld_regions: region base=%llx size=%llx prot=%x/%x inhert=%d share_mode=%d", region_base, region_size, info.protection, -1, -1, info.share_mode);
    
			size_t readsize=0;
			struct mach_header_64 header={0};
			kr = vm_read_overwrite(task, (vm_address_t)region_base, sizeof(header), (vm_address_t)&header, &readsize);
			if(kr != KERN_SUCCESS) {
				JBLogDebug("show_dyld_regions: vm_read failed! %d %s", kr, mach_error_string(kr));
				break;
			}
			JBLogDebug("show_dyld_regions: header=%p magic=%08x filetype=%d", region_base, header.magic, header.filetype);
			if(header.magic==MH_MAGIC_64 && header.filetype==MH_DYLINKER) {
                JBLogDebug("show_dyld_regions: dyld found! %p", region_base);
				dyld_address = (uint64_t)region_base;
				if(!more) break;
			}
		}
    }

    return dyld_address;
}

void patchedtest(mach_port_t task, uint64_t remoteLoadAddress)
{
    // show_dyld_regions(task, true);

    uint64_t getAMFI=0;
    if (__builtin_available(iOS 16.0, *)) {
     getAMFI = remoteLoadAddress + 0x197FC;
    }
    else {
     getAMFI = remoteLoadAddress + 0x1C3C0;
    }

    size_t readsize=0;
    uint32_t readdata=0;
    vm_read_overwrite(task, (vm_address_t)getAMFI, sizeof(readdata), (vm_address_t)&readdata, &readsize);

    JBLogDebug("getAMFI=%X", readdata);
#ifdef __arm64e__
    getAMFI = (uint64_t)__builtin_ptrauth_sign_unauthenticated((void*)getAMFI, 0, 0);
#endif

    if(task == mach_task_self()) {
        JBLogDebug("getAMFI=%llX", ((uint64_t(*)())getAMFI)());
    }

    task_dyld_info_data_t dyldInfo;
    uint32_t count = TASK_DYLD_INFO_COUNT;
    task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    JBLogDebug("new all_image_info_addr=%p", (void*)dyldInfo.all_image_info_addr);
    JBLogDebug("new all_image_info_size=%p", (void*)dyldInfo.all_image_info_size);

}

#define DYLD_INFO_MAX_SEARCH_INDEX 200
#define DYLD_INFO_INVALID_OFFSET UINT32_MAX
struct task_dyld_info_snapshot {
    uint64_t pairAddress;
    uint64_t pair[2];
    bool hasFlags;
    uint64_t flagsAddress;
    uint32_t flags;
    bool hasAuxiliary;
    uint64_t auxiliaryAddress;
    uint64_t auxiliary[6];
};

static int restore_task_dyld_info_snapshot(const struct task_dyld_info_snapshot *snapshot)
{
    if (!snapshot || !snapshot->pairAddress) return -1;

    int result = 0;
    if (kwritebuf(snapshot->pairAddress, snapshot->pair, sizeof(snapshot->pair)) != 0) {
        result = -1;
    }
    uint64_t verifyPair[2] = {0};
    if (kreadbuf(snapshot->pairAddress, verifyPair, sizeof(verifyPair)) != 0 ||
        memcmp(verifyPair, snapshot->pair, sizeof(verifyPair)) != 0) {
        result = -1;
    }

    if (snapshot->hasFlags) {
        if (kwritebuf(snapshot->flagsAddress, &snapshot->flags, sizeof(snapshot->flags)) != 0) {
            result = -1;
        }
        uint32_t verifyFlags = 0;
        if (kreadbuf(snapshot->flagsAddress, &verifyFlags, sizeof(verifyFlags)) != 0 ||
            verifyFlags != snapshot->flags) {
            result = -1;
        }
    }

    if (snapshot->hasAuxiliary) {
        if (kwritebuf(snapshot->auxiliaryAddress, snapshot->auxiliary, sizeof(snapshot->auxiliary)) != 0) {
            result = -1;
        }
        uint64_t verifyAuxiliary[6] = {0};
        if (kreadbuf(snapshot->auxiliaryAddress, verifyAuxiliary, sizeof(verifyAuxiliary)) != 0 ||
            memcmp(verifyAuxiliary, snapshot->auxiliary, sizeof(verifyAuxiliary)) != 0) {
            result = -1;
        }
    }
    return result;
}

static int task_set_dyld_info_internal(uint64_t task, mach_port_t taskPort, uint64_t addr, uint64_t size,
                                       struct task_dyld_info_snapshot *snapshotOut)
{
    static uint32_t all_image_info_addr_offset = DYLD_INFO_INVALID_OFFSET;
    static uint32_t all_image_info_size_offset = DYLD_INFO_INVALID_OFFSET;
    static uint32_t info_offset = DYLD_INFO_INVALID_OFFSET;
    static bool layoutReady = false;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        task_dyld_info_data_t dyldInfo={0};
        uint32_t count = TASK_DYLD_INFO_COUNT;
        kern_return_t kr = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
        if(kr != KERN_SUCCESS) {
            JBLogError("task_info failed: %d,%s", kr, mach_error_string(kr));
            return;
        }
        JBLogDebug("task_set_dyld_info: all_image_info_addr=%p", (void*)dyldInfo.all_image_info_addr);
        JBLogDebug("task_set_dyld_info: all_image_info_size=%p", (void*)dyldInfo.all_image_info_size);
    
        uint64_t selftask = task_self();
        JBLogDebug("task_set_dyld_info: selftask=%llx", selftask);

        uint32_t candidateCount = 0;
        for (uint32_t i = 0; i + 1 < DYLD_INFO_MAX_SEARCH_INDEX; i++) {
            uint64_t pair[2] = {0};
            if (kreadbuf(selftask + i * sizeof(uint64_t), pair, sizeof(pair)) != 0) {
                JBLogError("task_set_dyld_info: failed reading self task while locating dyld fields");
                return;
            }
            if (pair[0] == dyldInfo.all_image_info_addr && pair[1] == dyldInfo.all_image_info_size) {
                candidateCount++;
                all_image_info_addr_offset = i * sizeof(uint64_t);
                all_image_info_size_offset = (i + 1) * sizeof(uint64_t);
            }
        }

        if (candidateCount != 1) {
            JBLogError("task_set_dyld_info: expected one dyld-info field pair, found %u", candidateCount);
            all_image_info_addr_offset = DYLD_INFO_INVALID_OFFSET;
            all_image_info_size_offset = DYLD_INFO_INVALID_OFFSET;
            return;
        }

        if (!__builtin_available(iOS 26.0, *)) {
            const uint64_t expectedInfo[6] = {1,0,0,0,1,0};
            candidateCount = 0;
            for (uint32_t i = 0; i + 6 <= DYLD_INFO_MAX_SEARCH_INDEX; i++) {
                uint64_t buffer[6] = {0};
                if (kreadbuf(selftask + i * sizeof(uint64_t), buffer, sizeof(buffer)) != 0) {
                    JBLogError("task_set_dyld_info: failed reading self task while locating auxiliary dyld fields");
                    return;
                }
                if (memcmp(buffer, expectedInfo, sizeof(expectedInfo)) == 0) {
                    candidateCount++;
                    info_offset = i * sizeof(uint64_t);
                }
            }

            if (candidateCount != 1) {
                JBLogError("task_set_dyld_info: auxiliary layout is not unique (%u candidates)", candidateCount);
                info_offset = DYLD_INFO_INVALID_OFFSET;
            }
        }

        JBLogDebug("task_set_dyld_info: dyld offsets=%x/%x auxiliary=%x",
                   all_image_info_addr_offset, all_image_info_size_offset, info_offset);
        layoutReady = true;
    });

    if (!layoutReady || all_image_info_addr_offset == DYLD_INFO_INVALID_OFFSET ||
        all_image_info_size_offset == DYLD_INFO_INVALID_OFFSET || !MACH_PORT_VALID(taskPort)) {
        JBLogError("invalid all_image_info_addr/size offset");
        return -1;
    }

    task_dyld_info_data_t currentInfo = {0};
    uint32_t currentInfoCount = TASK_DYLD_INFO_COUNT;
    kern_return_t kr = task_info(taskPort, TASK_DYLD_INFO, (task_info_t)&currentInfo, &currentInfoCount);
    if (kr != KERN_SUCCESS) {
        JBLogError("task_set_dyld_info: target task_info failed: %d,%s", kr, mach_error_string(kr));
        return -1;
    }

    struct task_dyld_info_snapshot snapshot = {
        .pairAddress = task + all_image_info_addr_offset,
    };
    if (kreadbuf(snapshot.pairAddress, snapshot.pair, sizeof(snapshot.pair)) != 0 ||
        snapshot.pair[0] != currentInfo.all_image_info_addr || snapshot.pair[1] != currentInfo.all_image_info_size) {
        JBLogError("task_set_dyld_info: target dyld fields do not match TASK_DYLD_INFO");
        return -1;
    }

    uint64_t launchdTask = 0;
    uint64_t launchdProc = proc_find(1);
    if (launchdProc) launchdTask = proc_task(launchdProc);

    if (__builtin_available(iOS 26.0, *)) {
        // Darwin 25 / XNU 12377 lays out uint32_t t_flags and uint32_t
        // t_procflags in the qword immediately before the validated dyld pair.
        // Clear only TF_DYLD_ALL_IMAGE_FINAL; all unrelated task state survives.
        if (!launchdTask || task != launchdTask) {
            snapshot.flagsAddress = task_dyld_flags_address_from_pair(snapshot.pairAddress);
            if (!snapshot.flagsAddress ||
                kreadbuf(snapshot.flagsAddress, &snapshot.flags, sizeof(snapshot.flags)) != 0) {
                JBLogError("task_set_dyld_info: failed reading target task flags");
                return -1;
            }
            snapshot.hasFlags = true;
            uint32_t mutableFlags = task_dyld_flags_for_replacement(snapshot.flags);
            if (mutableFlags != snapshot.flags) {
                if (kwritebuf(snapshot.flagsAddress, &mutableFlags, sizeof(mutableFlags)) != 0) {
                    JBLogError("task_set_dyld_info: failed clearing dyld-final task flag");
                    return restore_task_dyld_info_snapshot(&snapshot) == 0 ? -1 : -2;
                }
                uint32_t verifyFlags = 0;
                if (kreadbuf(snapshot.flagsAddress, &verifyFlags, sizeof(verifyFlags)) != 0 ||
                    verifyFlags != mutableFlags) {
                    JBLogError("task_set_dyld_info: dyld-final task flag update did not verify");
                    return restore_task_dyld_info_snapshot(&snapshot) == 0 ? -1 : -2;
                }
            }
        }
    }
    else {
        const uint64_t expectedInfo[6] = {1,0,0,0,1,0};
        uint64_t oldAuxInfo[6] = {0};
        bool clearAuxInfo = false;
        if (info_offset != DYLD_INFO_INVALID_OFFSET) {
            snapshot.auxiliaryAddress = task + info_offset;
            if (kreadbuf(snapshot.auxiliaryAddress, oldAuxInfo, sizeof(oldAuxInfo)) != 0) {
                JBLogError("task_set_dyld_info: failed reading target auxiliary fields");
                return -1;
            }
            clearAuxInfo = memcmp(oldAuxInfo, expectedInfo, sizeof(expectedInfo)) == 0;
            if (clearAuxInfo) {
                snapshot.hasAuxiliary = true;
                memcpy(snapshot.auxiliary, oldAuxInfo, sizeof(oldAuxInfo));
            }
        }
        if (!clearAuxInfo && (!launchdTask || task != launchdTask)) {
            JBLogError("task_set_dyld_info: target auxiliary layout does not match validated task layout");
            return -1;
        }

        if (clearAuxInfo) {
            uint64_t zeroInfo[6] = {0};
            if (kwritebuf(snapshot.auxiliaryAddress, zeroInfo, sizeof(zeroInfo)) != 0) {
                JBLogError("task_set_dyld_info: failed clearing target auxiliary dyld fields");
                return restore_task_dyld_info_snapshot(&snapshot) == 0 ? -1 : -2;
            }
        }
    }

    uint64_t newPair[2] = {addr, size};
    if (kwritebuf(snapshot.pairAddress, newPair, sizeof(newPair)) != 0) {
        JBLogError("task_set_dyld_info: failed publishing target dyld fields");
        return restore_task_dyld_info_snapshot(&snapshot) == 0 ? -1 : -2;
    }

    uint64_t verifyPair[2] = {0};
    if (kreadbuf(snapshot.pairAddress, verifyPair, sizeof(verifyPair)) != 0 ||
        memcmp(verifyPair, newPair, sizeof(newPair)) != 0) {
        JBLogError("task_set_dyld_info: target dyld publication did not verify");
        return restore_task_dyld_info_snapshot(&snapshot) == 0 ? -1 : -2;
    }

    if (snapshotOut) *snapshotOut = snapshot;
    return 0;
}

int task_set_dyld_info(uint64_t task, mach_port_t taskPort, uint64_t addr, uint64_t size)
{
    return task_set_dyld_info_internal(task, taskPort, addr, size, NULL);
}

void analyzeSegmentsLayout(struct mach_header_64* header, uint64_t* vmSpace, bool* hasZeroFill)
{
    bool     writeExpansion = false;
    uint64_t lowestVmAddr   = 0xFFFFFFFFFFFFFFFFULL;
    uint64_t highestVmAddr  = 0;
    uint64_t sumVmSizes     = 0;

    uint64_t preferredLoadAddress = 0;

    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {        
        if(lc->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64* seg = (struct segment_command_64*)lc;
            JBLogDebug("[analyzeSegmentsLayout] segment: %s file=%llx:%llx vm=%llx:%llx prot=%x/%x", seg->segname, seg->fileoff, seg->filesize, seg->vmaddr, seg->vmsize, seg->initprot, seg->maxprot);

            if ( strcmp(seg->segname, SEG_PAGEZERO) == 0 )
                continue;
            if ( strcmp(seg->segname, SEG_TEXT) == 0 ) {
                preferredLoadAddress = seg->vmaddr;
            }
            if ( (seg->initprot & VM_PROT_WRITE) && (seg->filesize !=  seg->vmsize) )
                writeExpansion = true; // zerofill at end of __DATA
            if ( seg->vmsize == 0 ) {
                // Always zero fill if we have zero-sized segments
                writeExpansion = true;
            }
            if ( seg->vmaddr < lowestVmAddr )
                lowestVmAddr = seg->vmaddr;
            if ( seg->vmaddr+seg->vmsize > highestVmAddr )
                highestVmAddr = seg->vmaddr+seg->vmsize;
            sumVmSizes += seg->vmsize;
        }
        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }

    uint64_t totalVmSpace = (highestVmAddr - lowestVmAddr);
    // LINKEDIT vmSize is not required to be a multiple of page size.  Round up if that is the case
    totalVmSpace = (totalVmSpace + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
    bool hasHole = (totalVmSpace != sumVmSizes); // segments not contiguous

    // The aux KC may have __DATA first, in which case we always want to vm_copy to the right place
    bool hasOutOfOrderSegments = false;
#if BUILDING_APP_CACHE_UTIL
    uint64_t textSegVMAddr = preferredLoadAddress;
    hasOutOfOrderSegments = textSegVMAddr != lowestVmAddr;
#endif

    *vmSpace     = totalVmSpace;
    *hasZeroFill = writeExpansion || hasHole || hasOutOfOrderSegments;
}

int loadSinature(int fd, struct mach_header_64* header)
{
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {        
        switch(lc->cmd) {
            case LC_CODE_SIGNATURE: {
                struct linkedit_data_command* codeSignCmd = (struct linkedit_data_command*)lc;
                fsignatures_t siginfo;
                siginfo.fs_file_start = 0; // start of mach-o slice in fat file
                siginfo.fs_blob_start = (void*)(long)codeSignCmd->dataoff; // start of CD in mach-o file
                siginfo.fs_blob_size  = codeSignCmd->datasize; // size of CD
                int result            = fcntl(fd, F_ADDFILESIGS, &siginfo);
                if(result == 0) {
                    JBLogDebug("fcntl add signature success: %d", result);
                    return 0;
                } else {
                    JBLogError("fcntl add signture failed: %d, %s", errno, strerror(errno));
                    return -1;
                }
                break;
            }
        }
        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }
    return -1;
}

static uint64_t get_symbol(const char* path, const char* name)
{
    void *csHandle = dlopen("/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication", RTLD_NOW);
	if (!csHandle) return 0;
	CSSymbolicatorRef (*__CSSymbolicatorCreateWithPathAndArchitecture)(const char* path, cpu_type_t type) = dlsym(csHandle, "CSSymbolicatorCreateWithPathAndArchitecture");
	CSSymbolRef (*__CSSymbolicatorGetSymbolWithMangledNameAtTime)(CSSymbolicatorRef cs, const char* name, uint64_t time) = dlsym(csHandle, "CSSymbolicatorGetSymbolWithMangledNameAtTime");
	CSRange (*__CSSymbolGetRange)(CSSymbolRef sym) = dlsym(csHandle, "CSSymbolGetRange");
	if (!__CSSymbolicatorCreateWithPathAndArchitecture ||
		!__CSSymbolicatorGetSymbolWithMangledNameAtTime || !__CSSymbolGetRange) {
		dlclose(csHandle);
		return 0;
	}

	CSSymbolicatorRef symbolicator = __CSSymbolicatorCreateWithPathAndArchitecture(path, CPU_TYPE_ARM64);
	if (!symbolicator.csCppObj) {
		dlclose(csHandle);
		return 0;
	}
	CSSymbolRef symbol = __CSSymbolicatorGetSymbolWithMangledNameAtTime(symbolicator, name, 0);
	if (!symbol.csCppObj) {
		dlclose(csHandle);
		return 0;
	}
	CSRange range = __CSSymbolGetRange(symbol);
	dlclose(csHandle);
    return range.location;
}

struct DYLDINFO {
    uint64_t entrypoint;
    uint64_t vmSpaceSize;
    void*    imageAddress;
    uint64_t all_image_info_addr;
    uint64_t all_image_info_size;
    uint64_t bootstrap_return;
    uint64_t bootstrap_complete;
    uint64_t bootstrap_sandbox_extensions;
    uint64_t loadDyldCache_function;
    uint64_t loadDyldCache_trampoline;
};

struct DYLDINFO* loadDyldInfo(const char* path)
{
    JBLogDebug("loadDyldInfo: %s", path);

    int fd = -1;
    kern_return_t kr;
    void* dyld = MAP_FAILED;

    struct DYLDINFO* result = malloc(sizeof(struct DYLDINFO));
    memset(result, 0, sizeof(struct DYLDINFO));

    result->loadDyldCache_function = get_symbol(path, "__ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE");
    JBLogDebug("loadDyldCache function: %llx", result->loadDyldCache_function);

    result->loadDyldCache_trampoline = get_symbol(path, "_ORIG__ZN5dyld313loadDyldCacheERKNS_18SharedCacheOptionsEPNS_19SharedCacheLoadInfoE");
    JBLogDebug("loadDyldCache orig trampoline: %llx", result->loadDyldCache_trampoline);

    result->bootstrap_return = get_symbol(path, "_gDyldhookBootstrapReturn");
    JBLogDebug("bootstrap return slot: %llx", result->bootstrap_return);

    result->bootstrap_complete = get_symbol(path, "_gDyldhookBootstrapComplete");
    JBLogDebug("bootstrap completion slot: %llx", result->bootstrap_complete);

    result->bootstrap_sandbox_extensions = get_symbol(path, "_gDyldhookBootstrapSandboxExtensions");
    JBLogDebug("bootstrap sandbox-extension slot: %llx", result->bootstrap_sandbox_extensions);

    fd = open(path, O_RDONLY);
    if(fd<0) {
        JBLogError("open dyld failed: %d, %s", errno, strerror(errno));
        goto failed;
    }

    struct stat sb;
    if(fstat(fd, &sb)<0) {
        JBLogError("fstat dyld failed: %d, %s", errno, strerror(errno));
        goto failed;
    }

    dyld = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE|MAP_RESILIENT_CODESIGN, fd, 0);
    if(dyld==MAP_FAILED) {
        JBLogError("mmap dyld failed: %d, %s", errno, strerror(errno));
        goto failed;
    }

    JBLogDebug("dyld file map=%p", dyld);

    struct mach_header_64* header = (struct mach_header_64*)dyld;

    // load code signature before mmap text segment
    if(loadSinature(fd, header) != 0) {
        JBLogError("loadSinature failed: %s", path);
        goto failed;
    }

    struct fgetsigsinfo siginfo = {0, GETSIGSINFO_PLATFORM_BINARY, 0};
    JBLogDebug("fcntl F_GETSIGSINFO=%d, %d", fcntl(fd, F_GETSIGSINFO, &siginfo), errno);
    JBLogDebug("siginfo: fg_sig_is_platform=%d", siginfo.fg_sig_is_platform);

    bool hasZeroFill = false;
    analyzeSegmentsLayout(header, &result->vmSpaceSize, &hasZeroFill);
    JBLogDebug("vmSpace=%llx hasZeroFill=%d", result->vmSpaceSize, hasZeroFill);

    // reserve address range
    kr = vm_allocate(mach_task_self(), (vm_address_t*)&result->imageAddress, (vm_size_t)result->vmSpaceSize, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        JBLogError("vm_allocate %d,%s", kr, mach_error_string(kr));
        goto failed;
    }

    JBLogDebug("dyld image address: %p", result->imageAddress);

    int segIndex=0;
    struct load_command* lc = (struct load_command*)((uint64_t)header + sizeof(*header));
    for (int i = 0; i < header->ncmds; i++) {        
        switch(lc->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64 * seg = (struct segment_command_64 *) lc;
                
                JBLogDebug("segment: %s file=%llx:%llx vm=%llx:%llx prot=%x/%x", seg->segname, seg->fileoff, seg->filesize, seg->vmaddr, seg->vmsize, seg->initprot, seg->maxprot);

                if (seg->filesize == 0)  {
                    JBLogDebug("skip segment %s", seg->segname);
                    break; //break switch
                }
                if ( (seg->vmaddr == 0) && (segIndex > 0) ) {
                    JBLogDebug("skip segment %s", seg->segname);
                    break; //break switch
                }

                bool hasZeroFill = (seg->initprot == (VM_PROT_READ|VM_PROT_WRITE)) && (seg->filesize < seg->vmsize);
                if ( !hasZeroFill || (seg->filesize != 0) ) {
                    // add region for content that is not wholely zerofill

                    size_t mapSize = seg->filesize;
                    // special case LINKEDIT, the vmsize is often larger than the filesize
                    // but we need to mmap off end of file, otherwise we may have r/w pages at end
                    if (strcmp(seg->segname, SEG_LINKEDIT)==0 && seg->initprot==VM_PROT_READ) {
                        mapSize = (uint32_t)seg->vmsize;
                    }

                    void* segAddress = mmap((void*)((uint64_t)result->imageAddress + seg->vmaddr), mapSize, seg->initprot, MAP_FIXED | MAP_PRIVATE, fd, (size_t)seg->fileoff);
                    if ( segAddress == MAP_FAILED ) {
                        JBLogError("mmap %s failed: %d, %s", seg->segname, errno, strerror(errno));
                        goto failed;
                    }
                    segIndex++;
                } else {
                    // <rdar://problem/32363581> Mapping zero filled regions fails with mmap of size 0
                    uint32_t fileOffset   = 0;
                    uint32_t fileSize     = (uint32_t)(seg->vmsize - seg->filesize);
                    uint64_t vmOffset     = seg->vmaddr + seg->filesize;
                    int32_t  perms        = seg->initprot;
                    JBLogDebug("segment %s has zero fill: %llx:%llx", seg->segname, vmOffset, fileSize);
                }

                struct section_64* sec = (struct section_64*)((uint64_t)seg+sizeof(*seg));
                for(int j=0; j<seg->nsects; j++)
                {
                    JBLogDebug("section[%d] = %.*s/%.*s vm=%llx offset=%x:%llx", j, 
                        sizeof(sec[j].segname),sec[j].segname, 
                        sizeof(sec[j].sectname),sec[j].sectname,
                        sec[j].addr, sec[j].offset, sec[j].size);

                    if(strncmp(sec[j].sectname, "__all_image_info", sizeof(sec[j].sectname)) == 0) {
                        JBLogDebug("all_image_info section: %llx:%llx", sec[j].addr, sec[j].size);
                        result->all_image_info_addr = sec[j].addr;
                        result->all_image_info_size = sec[j].size;
                        break;
                    }
                }
                break;
            }

            case LC_UNIXTHREAD: {

                if(lc->cmdsize != sizeof(*lc) + sizeof(uint32_t)*2 + sizeof(arm_thread_state64_t)) {
                    JBLogError("unexpected dyld thread_command: %x", lc->cmdsize);
                    goto failed;
                }
                
                uint32_t* tcdata = (uint32_t*)((uint64_t)lc + sizeof(struct thread_command));
                
                uint32_t flavor = tcdata[0];
                uint32_t count = tcdata[1];
                if(tcdata[0] != ARM_THREAD_STATE64 || count != ARM_THREAD_STATE64_COUNT) {
                    JBLogError("unexpected dyld thread state: %x", tcdata[0]);
                    goto failed;
                }

                arm_thread_state64_t *threadState = (arm_thread_state64_t*)&tcdata[2];
#ifdef __arm64e__
                uint64_t entry = (uint64_t)threadState->__opaque_pc;
#else
                uint64_t entry = (uint64_t)threadState->__pc;
#endif
                JBLogDebug("dyld entry: %llx", entry);
                result->entrypoint = entry;
                break;
            }
        }
        
        /////////
        lc = (struct load_command *) ((char *)lc + lc->cmdsize);
    }

    if(result->all_image_info_addr == 0 || result->all_image_info_size == 0) {
        JBLogError("dyld all_image_info section not found");
        goto failed;
    }

    if(result->entrypoint == 0) {
        JBLogError("dyld entrypoint not found");
        goto failed;
    }

    goto final;

failed:
    if(result->imageAddress) vm_deallocate(mach_task_self(), (vm_address_t)result->imageAddress, result->vmSpaceSize);
    free(result);
	result = NULL;

final:
    if(fd >= 0) close(fd);
    if(dyld != MAP_FAILED) munmap(dyld, sb.st_size);
    return result;
}

static int read_target_audit_token(uint64_t proc, pid_t expectedPid, audit_token_t *tokenOut)
{
    if (!proc || expectedPid <= 0 || !tokenOut || !gSystemInfo.kernelStruct.proc_ro.exists ||
        !koffsetof(proc, proc_ro) || !koffsetof(proc_ro, task_tokens) ||
        !koffsetof(task_token_ro_data, audit_token)) {
        return -1;
    }

    uint64_t procRo = kread_ptr(proc + koffsetof(proc, proc_ro));
    if (!procRo) return -1;

    uint64_t auditTokenAddress = procRo + koffsetof(proc_ro, task_tokens) +
                                 koffsetof(task_token_ro_data, audit_token);
    audit_token_t token = {0};
    if (kreadbuf(auditTokenAddress, &token, sizeof(token)) != 0) return -1;
    if (audit_token_to_pid(token) != expectedPid) return -1;

    *tokenOut = token;
    return 0;
}

static void schedule_bootstrap_mapping_cleanup(pid_t pid, uint64_t expectedTask,
                                               uint64_t remoteLoadAddress, uint64_t vmSpaceSize,
                                               uint64_t bootstrapCompleteAddress)
{
    if (pid <= 0 || !expectedTask || !remoteLoadAddress || !vmSpaceSize ||
        !bootstrapCompleteAddress) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        uint64_t currentProc = proc_find(pid);
        if (!currentProc || proc_task(currentProc) != expectedTask) return;

        task_port_t cleanupTask = MACH_PORT_NULL;
        kern_return_t cleanupTaskResult = task_for_pid(mach_task_self(), pid, &cleanupTask);
        if (cleanupTaskResult != KERN_SUCCESS || !MACH_PORT_VALID(cleanupTask)) return;

        uint64_t bootstrapComplete = 0;
        vm_size_t completionRead = 0;
        kern_return_t completionResult = vm_read_overwrite(cleanupTask,
            (vm_address_t)bootstrapCompleteAddress, sizeof(bootstrapComplete),
            (vm_address_t)&bootstrapComplete, &completionRead);
        if (completionResult != KERN_SUCCESS || completionRead != sizeof(bootstrapComplete) ||
            bootstrapComplete != 1) {
            mach_port_deallocate(mach_task_self(), cleanupTask);
            return;
        }

        kern_return_t cleanupResult = vm_deallocate(cleanupTask, remoteLoadAddress, vmSpaceSize);
        if (cleanupResult != KERN_SUCCESS) {
            JBLogError("bootstrap dyld cleanup failed for pid=%d: %d,%s", pid,
                       cleanupResult, mach_error_string(cleanupResult));
        }
        mach_port_deallocate(mach_task_self(), cleanupTask);
    });
}

int proc_bootstrap_dyld(pid_t pid)
{
    kern_return_t kr = KERN_SUCCESS;
    task_port_t task = MACH_PORT_NULL;
    vm_address_t remoteLoadAddress = 0;
    thread_act_array_t allThreads = NULL;
    mach_msg_type_number_t threadCount = 0;
    uint64_t bsd_proc = 0;
    uint64_t mach_task = 0;
    uint32_t originalCsflags = 0;
    char *bootstrapSandboxExtensions = NULL;
    bool csflagsChanged = false;
    bool reentry = false;

    static struct DYLDINFO *stockDyldInfo = NULL;
    static struct DYLDINFO *patchedDyldInfo = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        stockDyldInfo = loadDyldInfo("/usr/lib/dyld");
        patchedDyldInfo = loadDyldInfo(JBROOT_PATH("/basebin/.fakelib/dyld"));
    });

    if (!stockDyldInfo || !patchedDyldInfo || !patchedDyldInfo->bootstrap_return ||
        !patchedDyldInfo->bootstrap_complete || !patchedDyldInfo->bootstrap_sandbox_extensions) {
        JBLogError("bootstrap dyld metadata unavailable");
        return -1;
    }

    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
        JBLogError("bootstrap task_for_pid failed: %x,%s task=%x", kr, mach_error_string(kr), task);
        goto failed;
    }

    task_dyld_info_data_t dyldInfo = {0};
    uint32_t dyldInfoCount = TASK_DYLD_INFO_COUNT;
    kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &dyldInfoCount);
    if (kr != KERN_SUCCESS) {
        JBLogError("bootstrap task_info failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }

    uint64_t dyld_address = dyldInfo.all_image_info_addr - stockDyldInfo->all_image_info_addr;
    uint64_t dyld_entry = dyld_address + stockDyldInfo->entrypoint;

    vm_prot_t cur_prot = 0, max_prot = 0;
    kr = vm_remap(task, &remoteLoadAddress, patchedDyldInfo->vmSpaceSize, 0,
                  VM_FLAGS_ANYWHERE, mach_task_self(),
                  (mach_vm_address_t)patchedDyldInfo->imageAddress, true,
                  &cur_prot, &max_prot, VM_INHERIT_COPY);
    if (kr != KERN_SUCCESS) {
        JBLogError("bootstrap vm_remap failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }

    uint64_t bootstrap_return = dyld_entry;
    kr = vm_write(task,
                  (vm_address_t)(remoteLoadAddress + patchedDyldInfo->bootstrap_return),
                  (vm_offset_t)&bootstrap_return, sizeof(bootstrap_return));
    if (kr != KERN_SUCCESS) {
        JBLogError("bootstrap return write failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }

    bsd_proc = proc_find(pid);
    if (!bsd_proc) {
        JBLogError("bootstrap proc_find %d failed", pid);
        goto failed;
    }
    mach_task = proc_task(bsd_proc);
    if (!mach_task) {
        JBLogError("bootstrap proc_task %d failed", pid);
        goto failed;
    }

    originalCsflags = proc_getcsflags(bsd_proc);

    audit_token_t targetAuditToken = {0};
    if (read_target_audit_token(bsd_proc, pid, &targetAuditToken) != 0) {
        JBLogError("bootstrap could not read target audit token for pid=%d", pid);
        goto failed;
    }

    bool isPlatformProcess = (originalCsflags & CS_PLATFORM_BINARY) != 0;
    bootstrapSandboxExtensions = generate_sandbox_extensions(&targetAuditToken, isPlatformProcess);
    if (!bootstrapSandboxExtensions) {
        JBLogError("bootstrap sandbox-extension generation failed for pid=%d", pid);
        goto failed;
    }
    size_t bootstrapSandboxExtensionsLength = strnlen(bootstrapSandboxExtensions, JBSERVER_SANDBOX_EXTENSIONS_MAX);
    if (bootstrapSandboxExtensionsLength == 0 ||
        bootstrapSandboxExtensionsLength >= JBSERVER_SANDBOX_EXTENSIONS_MAX) {
        JBLogError("bootstrap sandbox-extension payload invalid for pid=%d", pid);
        goto failed;
    }

    kr = vm_write(task,
                  (vm_address_t)(remoteLoadAddress + patchedDyldInfo->bootstrap_sandbox_extensions),
                  (vm_offset_t)bootstrapSandboxExtensions,
                  (mach_msg_type_number_t)(bootstrapSandboxExtensionsLength + 1));
    if (kr != KERN_SUCCESS) {
        JBLogError("bootstrap sandbox-extension write failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    free(bootstrapSandboxExtensions);
    bootstrapSandboxExtensions = NULL;

    proc_csflags_set(bsd_proc, CS_GET_TASK_ALLOW);
    csflagsChanged = true;

    kr = task_threads(task, &allThreads, &threadCount);
    if (kr != KERN_SUCCESS || threadCount == 0) {
        JBLogError("bootstrap task_threads failed: %d,%s count=%u", kr, mach_error_string(kr), threadCount);
        goto failed;
    }

    for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
        arm_thread_state64_t threadState = {0};
        mach_msg_type_number_t threadStateCount = ARM_THREAD_STATE64_COUNT;
        kr = thread_get_state(allThreads[i], ARM_THREAD_STATE64,
                              (thread_state_t)&threadState, &threadStateCount);
        if (kr != KERN_SUCCESS) continue;

        arm_thread_state64_t strippedState = threadState;
        __darwin_arm_thread_state64_ptrauth_strip(strippedState);
        uint64_t strippedPC = (uint64_t)__darwin_arm_thread_state64_get_pc(strippedState);
        if (strippedPC != dyld_entry) continue;

#ifdef __arm64e__
        arm_thread_state64_t resignCheck = threadState;
        void *savedPC = resignCheck.__opaque_pc;
        void *resignedPC = ptrauth_sign_unauthenticated((void *)strippedPC,
                                                        ptrauth_key_process_independent_code, 0);
        __darwin_arm_thread_state64_set_pc_fptr(resignCheck, resignedPC);
        if (resignCheck.__opaque_pc != savedPC) {
            JBLogError("bootstrap cannot safely resign target dyld PC for pid=%d", pid);
            break;
        }
#endif

        void *new_entry = (void *)(remoteLoadAddress + patchedDyldInfo->entrypoint);
#ifdef __arm64e__
        new_entry = ptrauth_sign_unauthenticated(new_entry, ptrauth_key_process_independent_code, 0);
#endif
        __darwin_arm_thread_state64_set_pc_fptr(threadState, new_entry);
        kr = thread_set_state(allThreads[i], ARM_THREAD_STATE64,
                              (thread_state_t)&threadState, threadStateCount);
        if (kr == KERN_SUCCESS) {
            reentry = true;
        }
        else {
            JBLogError("bootstrap thread_set_state failed: %d,%s", kr, mach_error_string(kr));
        }
        break;
    }

    for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
        mach_port_deallocate(mach_task_self(), allThreads[i]);
    }
    if (allThreads) {
        vm_deallocate(mach_task_self(), (mach_vm_address_t)allThreads,
                      threadCount * sizeof(allThreads[0]));
        allThreads = NULL;
    }

    if (!reentry) goto failed;

    schedule_bootstrap_mapping_cleanup(pid, mach_task, remoteLoadAddress,
                                       patchedDyldInfo->vmSpaceSize,
                                       remoteLoadAddress + patchedDyldInfo->bootstrap_complete);
    remoteLoadAddress = 0;
    if (MACH_PORT_VALID(task)) mach_port_deallocate(mach_task_self(), task);
    return 0;

failed:
    if (bootstrapSandboxExtensions) {
        free(bootstrapSandboxExtensions);
        bootstrapSandboxExtensions = NULL;
    }
    if (allThreads) {
        for (mach_msg_type_number_t i = 0; i < threadCount; i++) {
            mach_port_deallocate(mach_task_self(), allThreads[i]);
        }
        vm_deallocate(mach_task_self(), (mach_vm_address_t)allThreads,
                      threadCount * sizeof(allThreads[0]));
    }
    if (csflagsChanged && bsd_proc) {
        proc_csflags_update(bsd_proc, originalCsflags);
    }
    if (remoteLoadAddress && MACH_PORT_VALID(task)) {
        vm_deallocate(task, remoteLoadAddress, patchedDyldInfo->vmSpaceSize);
    }
    if (MACH_PORT_VALID(task)) mach_port_deallocate(mach_task_self(), task);
    return -1;
}

static void log_dyld_reentry_route(pid_t pid, const char *reentryRoute, uint32_t threadFlags)
{
    if (pid <= 0 || !reentryRoute) return;

    char path[PATH_MAX] = {0};
    if (!proc_get_path(pid, path)) return;

    const char *probeClass = NULL;
    if (!strcmp(path, "/usr/libexec/thermalmonitord") ||
        !strcmp(path, "/System/Library/PrivateFrameworks/BackBoardServices.framework/backboardd") ||
        !strcmp(path, "/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter") ||
        !strcmp(path, "/usr/libexec/audiomxd")) {
        probeClass = "watchdog-fail";
    }
    else if (!strcmp(path, "/usr/libexec/logd") ||
             !strcmp(path, "/usr/libexec/runningboardd") ||
             !strcmp(path, "/usr/sbin/wifid") ||
             !strcmp(path, "/usr/libexec/configd")) {
        probeClass = "watchdog-control";
    }
    if (!probeClass) return;

    char message[384];
    snprintf(message, sizeof(message),
             "dyld reentry class=%s route=%s pid=%d path=%s threadflags=0x%08x",
             probeClass, reentryRoute, pid, path, threadFlags);
    roothide_bootlog(message);
}

static void schedule_dyld_finalization_probe(pid_t pid, uint64_t expectedTask,
                                             uint64_t flagsAddress, uint64_t pairAddress,
                                             const char *reentryRoute)
{
    if (pid <= 0 || !expectedTask || !flagsAddress || !pairAddress || !reentryRoute) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        uint64_t proc = proc_find(pid);
        if (!proc) return;

        uint64_t currentTask = proc_task(proc);
        char path[PATH_MAX] = {0};
        proc_get_path(pid, path);
        const char *probeClass = NULL;
        bool watchdogTarget =
            strcmp(path, "/usr/libexec/backboardd") == 0 ||
            strcmp(path, "/usr/libexec/audiomxd") == 0 ||
            strcmp(path, "/usr/libexec/thermalmonitord") == 0 ||
            strcmp(path, "/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter") == 0;
        bool controlTarget =
            strcmp(path, "/usr/libexec/logd") == 0 ||
            strcmp(path, "/usr/libexec/runningboardd") == 0 ||
            strcmp(path, "/usr/sbin/wifid") == 0 ||
            strcmp(path, "/usr/libexec/configd") == 0;
        if (watchdogTarget) probeClass = "watchdog-fail";
        else if (controlTarget) probeClass = "watchdog-control";

        if (probeClass && currentTask == expectedTask) {
            uint32_t flags = 0;
            uint64_t pair[2] = {0};
            int flagsRead = kreadbuf(flagsAddress, &flags, sizeof(flags));
            int pairRead = kreadbuf(pairAddress, pair, sizeof(pair));
            char message[384];
            snprintf(message, sizeof(message),
                     "dyld finalization probe class=%s route=%s pid=%d path=%s taskmatch=1 flagsread=%d pairread=%d flags=0x%08x final=%d pair=%llx:%llx",
                     probeClass, reentryRoute, pid, path, flagsRead, pairRead, flags,
                     (flags & TF_DYLD_ALL_IMAGE_FINAL) != 0, pair[0], pair[1]);
            roothide_bootlog(message);
        }

        proc_rele(proc);
    });
}

int hook_dyld_entry(mach_port_t task, uint64_t old_header, uint64_t old_entry, uint64_t new_entry)
{
    //Destroy the old dyld header first to avoid double dyld being found via vm_region*
    struct mach_header_64 originalHeader = {0};
    uint32_t originalEntry[5] = {0};
    vm_size_t readSize = 0;
    if (vm_read_overwrite(task, (vm_address_t)old_header, sizeof(originalHeader),
                          (vm_address_t)&originalHeader, &readSize) != KERN_SUCCESS ||
        readSize != sizeof(originalHeader)) {
        JBLogError("vm_read original header failed");
        return -1;
    }
    readSize = 0;
    if (vm_read_overwrite(task, (vm_address_t)old_entry, sizeof(originalEntry),
                          (vm_address_t)originalEntry, &readSize) != KERN_SUCCESS ||
        readSize != sizeof(originalEntry)) {
        JBLogError("vm_read original entry failed");
        return -1;
    }

    bool headerWritable = false;
    bool headerChanged = false;
    bool entryWritable = false;
    bool entryChanged = false;
    struct mach_header_64 padding = {0};

    kern_return_t kr = vm_protect(task, (vm_address_t)old_header, sizeof(padding), false, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_protect header failed: %d,%s", kr, mach_error_string(kr));
        return -1;
    }
    headerWritable = true;

    kr = vm_write(task, (vm_address_t)old_header, (vm_offset_t)&padding, sizeof(padding));
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_write header failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    headerChanged = true;


    uint32_t codes[] = {
/*
movz x0, 0x0000, lsl 48
movk x0, 0x0000, lsl 32
movk x0, 0x0000, lsl 16
movk x0, 0x0000
br   x0
*/
        0xD2E00000,
        0xF2C00000,
        0xF2A00000,
        0xF2800000,
        0xD61F0000,
    };

    codes[0] |= ((new_entry >> 48) & 0xffff) << 5;
    codes[1] |= ((new_entry >> 32) & 0xffff) << 5;
    codes[2] |= ((new_entry >> 16) & 0xffff) << 5;
    codes[3] |= ((new_entry >>  0) & 0xffff) << 5;

    kr = vm_protect(task, (vm_address_t)old_entry, sizeof(codes), false, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_protect rw(cpoy) failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    entryWritable = true;

    kr = vm_write(task, (vm_address_t)old_entry, (vm_offset_t)codes, sizeof(codes));
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_write failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    entryChanged = true;

    kr = vm_protect(task, (vm_address_t)old_entry, sizeof(codes), false, VM_PROT_READ|VM_PROT_EXECUTE);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_protect rx failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    entryWritable = false;

    kr = vm_protect(task, (vm_address_t)old_header, sizeof(padding), false, VM_PROT_READ|VM_PROT_EXECUTE);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_protect header rx failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    headerWritable = false;

    return 0;

failed:
{
    bool rollbackFailed = false;
    if (entryChanged || entryWritable) {
        if (vm_protect(task, (vm_address_t)old_entry, sizeof(originalEntry), false,
                       VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY) == KERN_SUCCESS) {
            if (entryChanged) {
                if (vm_write(task, (vm_address_t)old_entry, (vm_offset_t)originalEntry, sizeof(originalEntry)) != KERN_SUCCESS) {
                    rollbackFailed = true;
                }
            }
            if (vm_protect(task, (vm_address_t)old_entry, sizeof(originalEntry), false,
                           VM_PROT_READ|VM_PROT_EXECUTE) != KERN_SUCCESS) rollbackFailed = true;
        }
        else rollbackFailed = true;
    }
    if (headerChanged || headerWritable) {
        if (vm_protect(task, (vm_address_t)old_header, sizeof(originalHeader), false,
                       VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY) == KERN_SUCCESS) {
            if (headerChanged) {
                if (vm_write(task, (vm_address_t)old_header, (vm_offset_t)&originalHeader, sizeof(originalHeader)) != KERN_SUCCESS) {
                    rollbackFailed = true;
                }
            }
            if (vm_protect(task, (vm_address_t)old_header, sizeof(originalHeader), false,
                           VM_PROT_READ|VM_PROT_EXECUTE) != KERN_SUCCESS) rollbackFailed = true;
        }
        else rollbackFailed = true;
    }
    return rollbackFailed ? -2 : -1;
}
}

int hook_dyld_function(mach_port_t task, uint64_t old_func, uint64_t new_func, uint64_t orig_func)
{
/*
movz x17, 0x0000, lsl 48
movk x17, 0x0000, lsl 32
movk x17, 0x0000, lsl 16
movk x17, 0x0000
br   x17
*/
#define HOOK_CODE_TEMPLATE { \
    0xD2E00011, \
    0xF2C00011, \
    0xF2A00011, \
    0xF2800011, \
    0xD61F0220  \
}

    uint32_t tramp[] = HOOK_CODE_TEMPLATE;
    tramp[0] |= (((old_func+sizeof(tramp)) >> 48) & 0xffff) << 5;
    tramp[1] |= (((old_func+sizeof(tramp)) >> 32) & 0xffff) << 5;
    tramp[2] |= (((old_func+sizeof(tramp)) >> 16) & 0xffff) << 5;
    tramp[3] |= (((old_func+sizeof(tramp)) >>  0) & 0xffff) << 5;

    uint8_t originalFunction[sizeof(tramp)] = {0};
    uint8_t originalTrampoline[sizeof(tramp) * 2] = {0};
    vm_size_t readSize = 0;
    if (vm_read_overwrite(task, (vm_address_t)old_func, sizeof(originalFunction),
                          (vm_address_t)originalFunction, &readSize) != KERN_SUCCESS ||
        readSize != sizeof(originalFunction)) {
        JBLogError("vm_read original dyld function failed");
        return -1;
    }
    readSize = 0;
    if (vm_read_overwrite(task, (vm_address_t)orig_func, sizeof(originalTrampoline),
                          (vm_address_t)originalTrampoline, &readSize) != KERN_SUCCESS ||
        readSize != sizeof(originalTrampoline)) {
        JBLogError("vm_read original dyld trampoline failed");
        return -1;
    }

    bool trampolineWritable = false;
    bool trampolineChanged = false;
    bool functionWritable = false;
    bool functionChanged = false;

    kern_return_t kr = vm_protect(task, (vm_address_t)orig_func, sizeof(tramp)*2, false, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_protect rw(cpoy) failed: %d,%s", kr, mach_error_string(kr));
        return -1;
    }
    trampolineWritable = true;

    kr = vm_copy(task, (vm_address_t)old_func, sizeof(tramp), (vm_address_t)orig_func);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_copy failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    trampolineChanged = true;

    kr = vm_write(task, (vm_address_t)(orig_func+sizeof(tramp)), (vm_offset_t)tramp, sizeof(tramp));
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_write failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }

    kr = vm_protect(task, (vm_address_t)orig_func, sizeof(tramp)*2, false, VM_PROT_READ|VM_PROT_EXECUTE);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_protect rx failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    trampolineWritable = false;



    uint32_t codes[] = HOOK_CODE_TEMPLATE;

    codes[0] |= ((new_func >> 48) & 0xffff) << 5;
    codes[1] |= ((new_func >> 32) & 0xffff) << 5;
    codes[2] |= ((new_func >> 16) & 0xffff) << 5;
    codes[3] |= ((new_func >>  0) & 0xffff) << 5;

    kr = vm_protect(task, (vm_address_t)old_func, sizeof(codes), false, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_protect rw(cpoy) failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    functionWritable = true;

    kr = vm_write(task, (vm_address_t)old_func, (vm_offset_t)codes, sizeof(codes));
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_write failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    functionChanged = true;

    kr = vm_protect(task, (vm_address_t)old_func, sizeof(codes), false, VM_PROT_READ|VM_PROT_EXECUTE);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_protect rx failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    functionWritable = false;

    return 0;

failed:
{
    bool rollbackFailed = false;
    if (functionChanged || functionWritable) {
        if (vm_protect(task, (vm_address_t)old_func, sizeof(originalFunction), false,
                       VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY) == KERN_SUCCESS) {
            if (functionChanged) {
                if (vm_write(task, (vm_address_t)old_func, (vm_offset_t)originalFunction, sizeof(originalFunction)) != KERN_SUCCESS) {
                    rollbackFailed = true;
                }
            }
            if (vm_protect(task, (vm_address_t)old_func, sizeof(originalFunction), false,
                           VM_PROT_READ|VM_PROT_EXECUTE) != KERN_SUCCESS) rollbackFailed = true;
        }
        else rollbackFailed = true;
    }
    if (trampolineChanged || trampolineWritable) {
        if (vm_protect(task, (vm_address_t)orig_func, sizeof(originalTrampoline), false,
                       VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY) == KERN_SUCCESS) {
            if (trampolineChanged) {
                if (vm_write(task, (vm_address_t)orig_func, (vm_offset_t)originalTrampoline, sizeof(originalTrampoline)) != KERN_SUCCESS) {
                    rollbackFailed = true;
                }
            }
            if (vm_protect(task, (vm_address_t)orig_func, sizeof(originalTrampoline), false,
                           VM_PROT_READ|VM_PROT_EXECUTE) != KERN_SUCCESS) rollbackFailed = true;
        }
        else rollbackFailed = true;
    }
    return rollbackFailed ? -2 : -1;
}
}

int proc_patch_dyld_internal(pid_t pid, bool spinlockFixOnly)
{
    int ret = 0;

    kern_return_t kr = KERN_SUCCESS;
    const char *phase = "dyld metadata";
    const char *reentryRoute = NULL;
    task_port_t task = MACH_PORT_NULL;
    vm_address_t  remoteLoadAddress = 0;
    bool keepRemoteMapping = false;

    static struct DYLDINFO* stockDyldInfo = NULL;
    static struct DYLDINFO* patchedDyldInfo = NULL;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        stockDyldInfo = loadDyldInfo("/usr/lib/dyld");
        patchedDyldInfo = loadDyldInfo(JBROOT_PATH("/basebin/.fakelib/dyld"));
    });

    if(stockDyldInfo == NULL || patchedDyldInfo == NULL) {
        JBLogError("load dyld failed");
        return -1;
    }

    phase = "task_for_pid";
    kr = task_for_pid(mach_task_self(), pid, &task);
    if(kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
        JBLogError("task_for_pid failed: %x,%s task=%x", kr, mach_error_string(kr), task);
        goto failed;
    }

    // show_dyld_regions(task, true);

    task_dyld_info_data_t dyldInfo={0};
    uint32_t count = TASK_DYLD_INFO_COUNT;
    phase = "task_info";
    kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    if(kr != KERN_SUCCESS) {
    	JBLogError("task_info failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }

    uint64_t dyld_address = dyldInfo.all_image_info_addr - stockDyldInfo->all_image_info_addr;
    uint64_t dyld_entry = dyld_address + stockDyldInfo->entrypoint;
    JBLogDebug("default dyld=%p entry=%p", (void*)dyld_address, (void*)dyld_entry);

    vm_prot_t cur_prot=0, max_prot=0;
    phase = "remap";
    kr = vm_remap(task, &remoteLoadAddress, patchedDyldInfo->vmSpaceSize, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (mach_vm_address_t)patchedDyldInfo->imageAddress, true, &cur_prot, &max_prot, VM_INHERIT_COPY);
    if(kr != KERN_SUCCESS) {
        JBLogError("vm_remap %d,%s", kr, mach_error_string(kr));
        goto failed;
    }

    JBLogDebug("remap dyld=%p prot=%x/%x", remoteLoadAddress, cur_prot, max_prot);

    phase = "kernel process lookup";
    uint64_t bsd_proc = proc_find(pid);
    if(!bsd_proc) {
        JBLogError("proc_find %d failed", pid);
        goto failed;
    }
    uint64_t mach_task = proc_task(bsd_proc);
    if(!mach_task) {
        JBLogError("proc_task %d failed", pid);
        goto failed;
    }

    if(spinlockFixOnly)
    {
        bool iOS15Arm64e = false;
#ifdef __arm64e__
        if (!__builtin_available(iOS 16.0, *))
        {
            iOS15Arm64e = true;
        }
#endif
        if (!iOS15Arm64e || !dyld_patch_enabled()) {
            JBLogError("spinlock-only dyld patch requested outside the supported iOS 15 arm64e mode");
            goto failed;
        }
		if (stockDyldInfo->loadDyldCache_function == 0 || patchedDyldInfo->loadDyldCache_function == 0 ||
			patchedDyldInfo->loadDyldCache_trampoline == 0) {
			JBLogError("loadDyldCache symbols unavailable for iOS 15 arm64e spinlock fix");
			goto failed;
		}

        uint64_t loadDyldCache_old = dyld_address + stockDyldInfo->loadDyldCache_function;
        uint64_t loadDyldCache_new = remoteLoadAddress + patchedDyldInfo->loadDyldCache_function;
        uint64_t loadDyldCache_orig = remoteLoadAddress + patchedDyldInfo->loadDyldCache_trampoline;

        cs_allow_invalid(bsd_proc, false);

        int hookResult = hook_dyld_function(task, loadDyldCache_old, loadDyldCache_new, loadDyldCache_orig);
        if(hookResult != 0) {
            if (hookResult == -2) keepRemoteMapping = true;
            JBLogError("hook dyld loadDyldCache failed");
            goto failed;
        }
        keepRemoteMapping = true;

        if(task_set_dyld_info(mach_task, task, dyld_address + stockDyldInfo->all_image_info_addr, stockDyldInfo->all_image_info_size) != 0) {
            JBLogError("task_set_dyld_info failed");
            goto failed;
        }

        //destroy macho header
        kr = vm_deallocate(task, remoteLoadAddress, PAGE_SIZE);
        if(kr != KERN_SUCCESS) {
            JBLogError("vm_deallocate failed: %d,%s", kr, mach_error_string(kr));
            goto failed;
        }

        goto final;
    }

    void* new_entry = (void*)(remoteLoadAddress + patchedDyldInfo->entrypoint);

    bool reentry = false;
    uint32_t reentryThreadFlags = 0;
    struct task_dyld_info_snapshot dyldInfoSnapshot = {0};
    
    thread_act_array_t allThreads=NULL;
    mach_msg_type_number_t threadCount = 0;
    phase = "task_threads";
    kr = task_threads(task, &allThreads, &threadCount);
    if(kr != KERN_SUCCESS) {
        JBLogError("task_threads failed: %d,%s", kr, mach_error_string(kr));
        goto failed;
    }
    if(threadCount == 0) {
        JBLogError("no thread found");
        goto failed;
    }

    for(int i=0; i<threadCount; i++)
    {
        JBLogDebug("allThreads[%d/%d]=%x", i, threadCount, allThreads[i]);

        arm_thread_state64_t threadState={0};
        mach_msg_type_number_t threadStateCount = ARM_THREAD_STATE64_COUNT;
        phase = "thread_get_state";
        kr = thread_get_state(allThreads[i], ARM_THREAD_STATE64, (thread_state_t)&threadState, &threadStateCount);
        if(kr != KERN_SUCCESS) {
            JBLogError("thread_get_state %d,%s", kr, mach_error_string(kr));
            goto reentry_end;
        }

        arm_thread_state64_t strippedState = threadState; /* some process such as WebContent used a different pac key
         cause we can't auth-and-resign it with __darwin_arm_thread_state64_get_* in current processs (crash) , so just strip all first */
        __darwin_arm_thread_state64_ptrauth_strip(strippedState);

        uint64_t strippedPC = (uint64_t)__darwin_arm_thread_state64_get_pc(strippedState);
        uint64_t strippedSP = (uint64_t)__darwin_arm_thread_state64_get_sp(strippedState);
        uint64_t strippedFP = (uint64_t)__darwin_arm_thread_state64_get_fp(strippedState);
        uint64_t strippedLR = (uint64_t)__darwin_arm_thread_state64_get_lr(strippedState);
        phase = "entrypoint match";
        JBLogDebug("strippedState PC=%llx SP=%llx FP=%llx LR=%llx", strippedPC, strippedSP, strippedFP, strippedLR);

        if(strippedPC == dyld_entry)
        {
            JBLogDebug("dyld entrypoint found in thread[%d]:%x", i, allThreads[i]);
#ifdef __arm64e__
            reentryThreadFlags = threadState.__opaque_flags;
#else
            reentryThreadFlags = 0;
#endif

            phase = "dyld info publication";
            int dyldInfoResult = task_set_dyld_info_internal(mach_task, task,
                remoteLoadAddress + patchedDyldInfo->all_image_info_addr,
                patchedDyldInfo->all_image_info_size, &dyldInfoSnapshot);
            if (dyldInfoResult != 0) {
                char publicationMessage[192];
                snprintf(publicationMessage, sizeof(publicationMessage),
                    "dyld preparation: metadata publication child=%d result=%d", pid, dyldInfoResult);
                roothide_bootlog(publicationMessage);
                if (dyldInfoResult == -2) keepRemoteMapping = true;
                JBLogError("task_set_dyld_info failed");
                goto reentry_end;
            }

#ifdef __arm64e__
            void* savedPC = threadState.__opaque_pc;
            void* resignedPC = ptrauth_sign_unauthenticated((void*)strippedPC, ptrauth_key_process_independent_code, 0);
            __darwin_arm_thread_state64_set_pc_fptr(threadState, resignedPC);
            if(threadState.__opaque_pc != savedPC) {
                JBLogDebug("target process(%d) used a different pac key, %s", pid, proc_get_path(pid,NULL));

                cs_allow_invalid(bsd_proc, false);

                phase = "entrypoint trampoline";
                int hookResult = hook_dyld_entry(task, dyld_address, dyld_entry, (uint64_t)new_entry);
                if(hookResult != 0) {
                    if (hookResult == -2 || restore_task_dyld_info_snapshot(&dyldInfoSnapshot) != 0) {
                        keepRemoteMapping = true;
                    }
                    JBLogError("hook_dyld_entry failed");
                    goto reentry_end;
                }

                reentryRoute = "entry-trampoline";
                reentry = true;
                break;
            }
#endif

#ifdef __arm64e__
            new_entry = ptrauth_sign_unauthenticated(new_entry, ptrauth_key_process_independent_code, 0);
#endif
            arm_thread_state64_t originalThreadState = threadState;
            __darwin_arm_thread_state64_set_pc_fptr(threadState, new_entry);
            phase = "thread_set_state";
            kr = thread_set_state(allThreads[i], ARM_THREAD_STATE64, (thread_state_t)&threadState, threadStateCount);
            if(kr != KERN_SUCCESS) {
                if (restore_task_dyld_info_snapshot(&dyldInfoSnapshot) != 0) keepRemoteMapping = true;
                JBLogError("thread_set_state failed: %d,%s", kr, mach_error_string(kr));
                goto reentry_end;
            }

            phase = "old mapping release";
            kr = vm_deallocate(task, dyld_address, stockDyldInfo->vmSpaceSize);
            if(kr != KERN_SUCCESS) {
                kern_return_t restoreStateResult = thread_set_state(allThreads[i], ARM_THREAD_STATE64,
                    (thread_state_t)&originalThreadState, threadStateCount);
                int restoreInfoResult = restore_task_dyld_info_snapshot(&dyldInfoSnapshot);
                if (restoreStateResult != KERN_SUCCESS || restoreInfoResult != 0) keepRemoteMapping = true;
                JBLogError("vm_deallocate old dyld failed: %d,%s", kr, mach_error_string(kr));
                goto reentry_end;
            }

            reentryRoute = "thread-state";
            reentry = true;
            break;
        }
    }

reentry_end:
    for(int i=0; i<threadCount; i++) {
        mach_port_deallocate(mach_task_self(), allThreads[i]);
    }
    vm_deallocate(mach_task_self(), (mach_vm_address_t)allThreads, threadCount*sizeof(allThreads[0]));

    if(!reentry) {
        JBLogError("dyld entrypoint udpate failed");
        goto failed;
    }

    log_dyld_reentry_route(pid, reentryRoute, reentryThreadFlags);

    if (dyldInfoSnapshot.hasFlags && roothide_systemhook_dyld_fallback_enabled() &&
        getenv("ROOTHIDE_DYLD_FINALIZATION_TRACE")) {
        schedule_dyld_finalization_probe(pid, mach_task,
                                         dyldInfoSnapshot.flagsAddress,
                                         dyldInfoSnapshot.pairAddress,
                                         reentryRoute);
    }

    JBLogDebug("dyld all_image_info update: %p -> %p", (void*)(dyld_address + stockDyldInfo->all_image_info_addr), (void*)(remoteLoadAddress + patchedDyldInfo->all_image_info_addr));


    //patchedtest(task, remoteLoadAddress);

    JBLogDebug("dyld entrypoint updated: %p -> %p", (void*)dyld_entry, new_entry);
    goto final;

failed:
    {
        char message[192];
        snprintf(message, sizeof(message), "dyld preparation: phase=%s child=%d kr=%d", phase, pid, kr);
        roothide_bootlog(message);
    }
    ret = -1;
    if(remoteLoadAddress && !keepRemoteMapping) {
        vm_deallocate(task, remoteLoadAddress, patchedDyldInfo->vmSpaceSize);
    }

final:
    if(MACH_PORT_VALID(task)) mach_port_deallocate(mach_task_self(), task);
    return ret;
}

int proc_patch_dyld(pid_t pid)
{
    return proc_patch_dyld_internal(pid, false);
}

int proc_fix_spinlock(pid_t pid)
{
    return proc_patch_dyld_internal(pid, true);
}
