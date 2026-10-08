#include <assert.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <libkern/OSCacheControl.h>
#include <libjailbreak/hookd.h>
#include <libjailbreak/memory_hooks.h>

static unsigned registrationCount;

kern_return_t hookd_hook(mach_port_t task, uint64_t address, uint8_t *data, size_t size)
{
    assert(0 && "Initialization must not request a memory patch");
    return KERN_FAILURE;
}

kern_return_t mach_vm_protect_fixed(mach_port_name_t task, mach_vm_address_t address,
    mach_vm_size_t size, boolean_t maximum, vm_prot_t protection)
{
    assert(0 && "Initialization must not change memory protection");
    return KERN_FAILURE;
}

kern_return_t litehook_hook_memory_hookd(void *target, void *source, size_t size)
{
    assert(0 && "Initialization must not request an ElleKit patch");
    return KERN_FAILURE;
}

static void fixture_register_image_callback(void (*callback)(const struct mach_header *, intptr_t))
{
    const struct jb_memory_hooks *hooks = jb_get_memory_hooks(JB_MEMORY_HOOKS_VERSION);
    assert(hooks && hooks->version == JB_MEMORY_HOOKS_VERSION);
    assert(hooks->size == sizeof(*hooks));
    assert(hooks->patch_code && hooks->protect == mach_vm_protect_fixed);
    assert(callback);
    registrationCount++;
}

static bool fixture_shared_cache_contains_path(const char *path)
{
    return false;
}

#define _dyld_register_func_for_add_image fixture_register_image_callback
#define _dyld_shared_cache_contains_path fixture_shared_cache_contains_path
#include "implementation.h"

int main(void)
{
    assert(!jb_get_memory_hooks(JB_MEMORY_HOOKS_VERSION));
    assert(!jb_get_memory_hooks(0));
    assert(init_hookd_external_support() == 0);
    assert(registrationCount == 1);
    assert(jb_get_memory_hooks(JB_MEMORY_HOOKS_VERSION));
    assert(!jb_get_memory_hooks(0));
    assert(!jb_get_memory_hooks(JB_MEMORY_HOOKS_VERSION + 1));
    return 0;
}
