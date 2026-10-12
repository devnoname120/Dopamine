#include <dispatch/dispatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "../BaseBin/libjailbreak/src/jbserver_domains.h"

typedef struct { unsigned references; bool reply; int type; } FixtureObject;
typedef FixtureObject *xpc_object_t;
#define XPC_TYPE_DICTIONARY 1
#define XPC_TYPE_INT64 2
#define XPC_TYPE_BOOL 3
static FixtureObject objects[1024];
static FixtureObject statusObj = {.references = 1, .reply = true, .type = XPC_TYPE_INT64};
static FixtureObject boolObj = {.references = 1, .reply = true, .type = XPC_TYPE_BOOL};
static unsigned allocated, live, invalid_accesses, calls;
static int mode;

static void require_live(xpc_object_t object)
{
    if (!object || object->references != 1) invalid_accesses++;
}
static xpc_object_t fixture_object(bool reply)
{
    if (allocated == sizeof(objects) / sizeof(objects[0])) return NULL;
    xpc_object_t object = &objects[allocated++];
    *object = (FixtureObject){.references = 1, .reply = reply, .type = XPC_TYPE_DICTIONARY};
    live++;
    return object;
}
static xpc_object_t xpc_dictionary_create_empty(void) { return fixture_object(false); }
static void xpc_release(xpc_object_t object)
{
    require_live(object);
    if (object && object->references) { object->references--; live--; }
}
static void xpc_dictionary_set_uint64(xpc_object_t object, const char *key, uint64_t value) { require_live(object); }
static void xpc_dictionary_set_string(xpc_object_t object, const char *key, const char *value) { require_live(object); }
static void xpc_dictionary_set_bool(xpc_object_t object, const char *key, bool value) { require_live(object); }
static int64_t xpc_dictionary_get_int64(xpc_object_t object, const char *key)
{
    require_live(object);
    if (!object->reply || strcmp(key, "result")) invalid_accesses++;
    return mode == 2 ? -17 : 0;
}
static bool xpc_dictionary_get_bool(xpc_object_t object, const char *key)
{
    require_live(object);
    if (!object->reply) invalid_accesses++;
    return true;
}
static int xpc_get_type(xpc_object_t object) { require_live(object); return object->type; }
static xpc_object_t xpc_dictionary_get_value(xpc_object_t object, const char *key)
{
    require_live(object);
    if (!object->reply) invalid_accesses++;
    if (!strcmp(key, "result")) return &statusObj;
    if (!strcmp(key, "blacklisted")) return &boolObj;
    invalid_accesses++;
    return NULL;
}
static int64_t xpc_int64_get_value(xpc_object_t object)
{
    require_live(object);
    return mode == 2 ? -17 : 0;
}
static bool xpc_bool_get_value(xpc_object_t object)
{
    require_live(object);
    return true;
}
static xpc_object_t jbserver_xpc_send_dict(xpc_object_t request)
{
    require_live(request);
    if (request->reply) invalid_accesses++;
    calls++;
    return mode == 1 ? NULL : fixture_object(true);
}

#include "implementation.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    mode = !strcmp(argv[1], "success") ? 0 : !strcmp(argv[1], "transport-failure") ? 1 : 2;
    bool expected = mode == 0;
    int expected_setter = mode == 0 ? 0 : mode == 1 ? -1 : -17;
    unsigned result_failures = 0;
    for (unsigned i = 0; i < 16; i++) {
        result_failures += jbclient_roothide_jailbroken() != expected;
        result_failures += jbclient_palehide_present() != expected;
        result_failures += jbclient_blacklist_check_pid(123) != expected;
        result_failures += jbclient_blacklist_check_path("/fixture/path") != expected;
        result_failures += jbclient_blacklist_check_bundle("fixture.bundle") != expected;
        result_failures += jbclient_set_dyld_patch(true) != expected_setter;
    }
    result_failures += jbclient_dyld_patch_enabled() != expected;
    result_failures += jbclient_dyld_patch_enabled() != expected;
    printf("7 request ownership paths, %u live objects; calls=%u invalid=%u result_failures=%u\n",
           live, calls, invalid_accesses, result_failures);
    return live || invalid_accesses || result_failures || calls != 97 ? 1 : 0;
}
