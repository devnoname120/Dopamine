#include "dyld_dispatch.h"
#include "litehook.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "line %d: %s\n", __LINE__, #condition); exit(1); } } while (0)

struct layout {
    uintptr_t address;
    unsigned arguments, slot;
    uint16_t salt;
    size_t count;
    uint32_t code[16];
};

static const struct layout layouts[] = {
    {0x1800e8350, 2, 13, 0xBF31, 13, {0xAA0103E2,0xAA0003E1,0x90368F28,0xF9400900,0xF9400010,0xAA0003F1,0xF2EC7F51,0xDAC11A30,0xF8468E03,0xAA1003E4,0xAA0403F0,0xF2F7E630,0xD71F0870}},
    {0x1800e87c8, 1, 17, 0xB1B6, 12, {0xAA0003E1,0x90368F28,0xF9400900,0xF9400010,0xAA0003F1,0xF2EC7F51,0xDAC11A30,0xF8488E02,0xAA1003E3,0xAA0303F0,0xF2F636D0,0xD71F0850}},
    {0x1800e8404, 3, 92, 0xD48C, 16, {0xAA0203E3,0xAA0103E2,0xAA0003E1,0x90368F28,0xF9400900,0xF9400010,0xAA0003F1,0xF2EC7F51,0xDAC11A30,0xD2805C11,0x8B110210,0xF9400204,0xAA1003E5,0xAA0503F0,0xF2FA9190,0xD71F0890}},
    {0x1800f03b4, 2, 93, 0xD2A5, 15, {0xAA0103E2,0xAA0003E1,0x90368EE8,0xF9400900,0xF9400010,0xAA0003F1,0xF2EC7F51,0xDAC11A30,0xD2805D11,0x8B110210,0xF9400203,0xAA1003E4,0xAA0403F0,0xF2FA54B0,0xD71F0870}},
    {0x1800e8444, 2, 16, 0x839D, 13, {0xAA0103E2,0xAA0003E1,0x90368F28,0xF9400900,0xF9400010,0xAA0003F1,0xF2EC7F51,0xDAC11A30,0xF8480E03,0xAA1003E4,0xAA0403F0,0xF2F073B0,0xD71F0870}},
};

static bool validate(const struct layout *layout, size_t count, uintptr_t address, uintptr_t global, size_t *offset)
{
    return dyld_dispatch_offset(layout->code, count, address, global,
                                 layout->arguments, layout->slot, layout->salt, offset);
}

static void captured_layouts(void)
{
    for (unsigned i = 0; i < sizeof(layouts) / sizeof(layouts[0]); i++) {
        const struct layout *layout = &layouts[i];
        size_t offset = SIZE_MAX;
        CHECK(validate(layout, layout->count, layout->address, 0x1ed2cc010, &offset));
        CHECK(offset == (layout->arguments + 2) * 4);
        CHECK(layout->count * 4 - offset >= 20);
        CHECK(validate(layout, layout->count, layout->address + 0xC798000, 0x1f9a64010, &offset));
        CHECK(offset == (layout->arguments + 2) * 4);
    }
}

static void changed_layouts(void)
{
    for (unsigned i = 0; i < sizeof(layouts) / sizeof(layouts[0]); i++) {
        for (size_t j = 0; j < layouts[i].count; j++) {
            struct layout copy = layouts[i];
            copy.code[j] ^= 1;
            size_t offset = SIZE_MAX;
            CHECK(!validate(&copy, copy.count, copy.address, 0x1ed2cc010, &offset));
            CHECK(offset == SIZE_MAX);
        }
        for (size_t count = 0; count < layouts[i].count; count++) {
            size_t offset = SIZE_MAX;
            CHECK(!validate(&layouts[i], count, layouts[i].address, 0x1ed2cc010, &offset));
            CHECK(offset == SIZE_MAX);
        }
    }
}

static void invalid_inputs(void)
{
    struct layout layout = layouts[0];
    size_t offset = SIZE_MAX;
    CHECK(!dyld_dispatch_offset(NULL, 16, 0, 0, 2, 13, 0xBF31, &offset));
    CHECK(!validate(&layout, layout.count, layout.address, 0x1ed2cc010, NULL));
    CHECK(!validate(&layout, layout.count, layout.address + 1, 0x1ed2cc010, &offset));
    CHECK(!validate(&layout, layout.count, layout.address, 0x1ed2cc018, &offset));
    layout.arguments = 0;
    CHECK(!validate(&layout, layout.count, layout.address, 0x1ed2cc010, &offset));
    layout.arguments = 4;
    CHECK(!validate(&layout, layout.count, layout.address, 0x1ed2cc010, &offset));
    layout.arguments = 2;
    layout.slot = 8192;
    CHECK(!validate(&layout, layout.count, layout.address, 0x1ed2cc010, &offset));
    layout.slot = 13;
    layout.salt ^= 1;
    CHECK(!validate(&layout, layout.count, layout.address, 0x1ed2cc010, &offset));
    CHECK(offset == SIZE_MAX);
}

static uint32_t *runtime_code;
static void **runtime_original;
static void *expected_method;
static void *expected_hook;
static unsigned patch_count;
static int patch_result;
static bool local_symbols_missing;
static bool exports_missing;
static bool shadow_default_exports;
static uint32_t *shadow_code;
static unsigned default_dlsym_count;
static unsigned explicit_dyld_open_count;
static unsigned explicit_dyld_close_count;
static char explicit_dyld_handle_storage;
#define EXPLICIT_DYLD_HANDLE ((void *)&explicit_dyld_handle_storage)

void *litehook_find_dsc_symbol(const char *image, const char *symbol)
{
    CHECK(!strcmp(image, "/usr/lib/system/libdyld.dylib"));
    CHECK(!strcmp(symbol, "_dlopen"));
    return local_symbols_missing ? NULL : runtime_code;
}

void *dispatch_test_dlsym(void *handle, const char *symbol)
{
    CHECK(!strcmp(symbol, "dlopen"));
    if (handle == EXPLICIT_DYLD_HANDLE) return exports_missing ? NULL : runtime_code;
    CHECK(handle == RTLD_DEFAULT);
    default_dlsym_count++;
    if (shadow_default_exports) return shadow_code;
    return exports_missing ? NULL : runtime_code;
}

void *dispatch_test_dlopen(const char *path, int mode)
{
    CHECK(!strcmp(path, "/usr/lib/system/libdyld.dylib"));
    CHECK(mode & RTLD_FIRST);
    explicit_dyld_open_count++;
    return EXPLICIT_DYLD_HANDLE;
}

int dispatch_test_dlclose(void *handle)
{
    CHECK(handle == EXPLICIT_DYLD_HANDLE);
    explicit_dyld_close_count++;
    return 0;
}

kern_return_t litehook_hook_function(void *source, void *target)
{
    CHECK(source == runtime_code + 4);
    CHECK(target == expected_hook);
    CHECK(*runtime_original == expected_method);
    patch_count++;
    return patch_result;
}

static void old_method(void) {}
static void new_method(void) {}

static void runtime_patcher(bool fail)
{
    size_t page = (size_t)getpagesize();
    char *memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    CHECK(memory != MAP_FAILED);
    runtime_code = (uint32_t *)memory;
    shadow_code = runtime_code + 64;
    shadow_code[0] = 0x14000000;
    memcpy(runtime_code, layouts[0].code, sizeof(layouts[0].code));
    void ***global = (void ***)(memory + 256);
    void **object = (void **)(memory + 512);
    void **table = (void **)(memory + page);
    *global = object;
    *object = table;
    table[13] = (void *)old_method;
    CHECK(mprotect(table, page, PROT_READ) == 0);

    intptr_t delta = ((uintptr_t)global & ~(uintptr_t)0xFFF) - ((uintptr_t)&runtime_code[2] & ~(uintptr_t)0xFFF);
    uint64_t immediate = (uint64_t)(delta / 4096) & 0x1FFFFF;
    runtime_code[2] = 0x90000008 | ((immediate & 3) << 29) | ((immediate >> 2) << 5);
    runtime_code[3] = 0xF9400100 | ((((uintptr_t)global & 0xFFF) / 8) << 10);

    void *original = NULL;
    runtime_original = &original;
    expected_method = (void *)old_method;
    expected_hook = (void *)new_method;
    patch_result = fail ? KERN_PROTECTION_FAILURE : KERN_SUCCESS;
    CHECK(dyld_hook_dispatch(global, "_dlopen", 2, 13, expected_hook, &original, 0xBF31) == patch_result);
    CHECK(patch_count == 1 && original == expected_method && table[13] == expected_method);

    runtime_code[4] ^= 1;
    original = NULL;
    CHECK(dyld_hook_dispatch(global, "_dlopen", 2, 13, expected_hook, &original, 0xBF31) == KERN_NOT_SUPPORTED);
    CHECK(original == NULL && patch_count == 1);
    CHECK(dyld_hook_dispatch(NULL, "_dlopen", 2, 13, expected_hook, &original, 0xBF31) == KERN_INVALID_ARGUMENT);
    CHECK(dyld_hook_dispatch(global, "dlopen", 2, 13, expected_hook, &original, 0xBF31) == KERN_INVALID_ARGUMENT);
    CHECK(dyld_hook_dispatch(global, "_", 2, 13, expected_hook, &original, 0xBF31) == KERN_INVALID_ARGUMENT);
    exports_missing = true;
    CHECK(dyld_hook_dispatch(global, "_dlopen", 2, 13, expected_hook, &original, 0xBF31) == KERN_INVALID_ADDRESS);
    CHECK(original == NULL && patch_count == 1);
    CHECK(munmap(memory, page * 2) == 0);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "captured")) captured_layouts();
    else if (!strcmp(argv[1], "changed")) changed_layouts();
    else if (!strcmp(argv[1], "invalid")) invalid_inputs();
    else if (!strcmp(argv[1], "runtime")) runtime_patcher(false);
    else if (!strcmp(argv[1], "backend-failure")) runtime_patcher(true);
    else if (!strcmp(argv[1], "exports-only")) {
        local_symbols_missing = true;
        runtime_patcher(false);
    }
    else if (!strcmp(argv[1], "shadowed-export")) {
        shadow_default_exports = true;
        runtime_patcher(false);
        CHECK(default_dlsym_count == 0);
        CHECK(explicit_dyld_open_count > 0);
        CHECK(explicit_dyld_close_count == explicit_dyld_open_count);
    }
    else CHECK(false);
    return 0;
}
