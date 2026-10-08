#include "dyld_dispatch.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <ptrauth.h>
#include "litehook.h"

bool dyld_dispatch_offset(const uint32_t *instructions, size_t count, uintptr_t address,
                          uintptr_t interface, unsigned arguments, unsigned slot,
                          uint16_t salt, size_t *offset)
{
    if (!instructions || !offset || arguments < 1 || arguments > 3 || slot > 8191 || (address & 3)) return false;
    size_t tail = arguments + 2;
    size_t tailCount = slot < 32 ? 9 : 11;
    if (count < tail + tailCount) return false;

    for (unsigned i = 0; i < arguments; i++) {
        unsigned source = arguments - i - 1;
        uint32_t move = 0xAA0003E0 | (source << 16) | (source + 1);
        if (instructions[i] != move) return false;
    }
    uint32_t adrp = instructions[arguments];
    uint32_t load = instructions[arguments + 1];
    unsigned base = adrp & 31;
    if ((adrp & 0x9F000000) != 0x90000000 || base == 31) return false;
    if ((load & 0xFFC0001F) != 0xF9400000 || ((load >> 5) & 31) != base) return false;
    uint64_t immediate = ((adrp >> 29) & 3) | (((uint64_t)(adrp >> 5) & 0x7FFFF) << 2);
    int64_t pageDelta = (int64_t)(immediate << 43) >> 43;
    uintptr_t global = ((address + arguments * 4) & ~(uintptr_t)0xFFF) + pageDelta * 4096;
    global += ((load >> 10) & 0xFFF) * 8;
    if (global != interface) return false;

    unsigned target = arguments + 1;
    unsigned temporary = arguments + 2;
    uint32_t expected[11] = {0xF9400010, 0xAA0003F1, 0xF2EC7F51, 0xDAC11A30};
    size_t index = 4;
    if (slot < 32) {
        expected[index++] = 0xF8400C00 | ((slot * 8) << 12) | (16 << 5) | target;
    } else {
        expected[index++] = 0xD2800011 | ((slot * 8) << 5);
        expected[index++] = 0x8B110210;
        expected[index++] = 0xF9400200 | target;
    }
    expected[index++] = 0xAA1003E0 | temporary;
    expected[index++] = 0xAA0003F0 | (temporary << 16);
    expected[index++] = 0xF2E00010 | ((uint32_t)salt << 5);
    expected[index++] = 0xD71F0800 | (target << 5) | 16;
    for (size_t i = 0; i < index; i++) {
        if (instructions[tail + i] != expected[i]) return false;
    }
    *offset = tail * sizeof(uint32_t);
    return true;
}

int dyld_hook_dispatch(void ***interface, const char *symbol, unsigned arguments,
                       unsigned slot, void *hook, void **original, uint16_t salt)
{
    if (!interface || !*interface || !symbol || symbol[0] != '_' || !symbol[1] || !hook || !original) return KERN_INVALID_ARGUMENT;
    // Public stubs need not appear in the shared cache's private local-symbols table.
    // Resolve them from libdyld itself so an interposing library cannot shadow the
    // public entry point with a wrapper whose instruction layout is unrelated.
    void *dyldHandle = dlopen("/usr/lib/system/libdyld.dylib", RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST);
    if (!dyldHandle) return KERN_INVALID_ADDRESS;
    void *entry = dlsym(dyldHandle, symbol + 1);
    dlclose(dyldHandle);
    if (!entry) return KERN_INVALID_ADDRESS;
    const uint32_t *instructions = ptrauth_strip(entry, ptrauth_key_function_pointer);

    vm_address_t start = (vm_address_t)instructions;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t result = vm_region_64(mach_task_self(), &start, &size, VM_REGION_BASIC_INFO_64,
                                       (vm_region_info_t)&info, &count, &object);
    if (MACH_PORT_VALID(object)) mach_port_deallocate(mach_task_self(), object);
    uintptr_t address = (uintptr_t)instructions;
    if (result != KERN_SUCCESS) return result;
    if (!(info.protection & VM_PROT_READ) || address < start || address - start >= size) return KERN_INVALID_ADDRESS;
    size_t available = (size - (address - start)) / sizeof(uint32_t);
    size_t offset = 0;
    if (!dyld_dispatch_offset(instructions, available, address, (uintptr_t)interface,
                              arguments, slot, salt, &offset)) return KERN_NOT_SUPPORTED;

    void **api = *interface;
    uint64_t objectSalt = ((uintptr_t)api & ~(0xFFFFull << 48)) | (0x63FAull << 48);
    void **table = ptrauth_auth_data(*api, ptrauth_key_process_independent_data, objectSalt);
    if (!table) return KERN_INVALID_ADDRESS;
    uint64_t methodSalt = ((uintptr_t)&table[slot] & ~(0xFFFFull << 48)) | ((uint64_t)salt << 48);
    void *method = ptrauth_auth_and_resign(table[slot], ptrauth_key_process_independent_code,
                                         methodSalt, ptrauth_key_function_pointer, 0);
    if (!method) return KERN_INVALID_ADDRESS;

    // The helper resumes peer threads before returning, so the original must already be callable.
    *original = method;
    void *tail = ptrauth_sign_unauthenticated((void *)(address + offset), ptrauth_key_function_pointer, 0);
    return litehook_hook_function(tail, hook);
}
