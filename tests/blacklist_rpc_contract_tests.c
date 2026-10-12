#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(cond) do { if (!(cond)) { fprintf(stderr, "failed at line %d\n", __LINE__); return 1; } } while (0)
#define JBS_DOMAIN_ROOTHIDE 5
#define JBS_ROOTHIDE_BLACKLIST_CHECK 3
#define XPC_TYPE_DICTIONARY 1
#define XPC_TYPE_INT64 2
#define XPC_TYPE_BOOL 3

typedef struct { int type; int64_t code; bool value; } object;
typedef object *xpc_object_t;
static object args = {.type = XPC_TYPE_DICTIONARY}, reply = {.type = XPC_TYPE_DICTIONARY};
static object status = {.type = XPC_TYPE_INT64}, flag = {.type = XPC_TYPE_BOOL};
static int mode;

static xpc_object_t xpc_dictionary_create_empty(void) { return &args; }
static void xpc_dictionary_set_string(xpc_object_t obj, const char *key, const char *val)
{ (void)obj; (void)key; (void)val; }
static xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t obj)
{ (void)domain; (void)action; (void)obj; return mode == 1 ? NULL : &reply; }
static void xpc_release(xpc_object_t obj) { (void)obj; }
static int xpc_get_type(xpc_object_t obj) { return obj->type; }
static xpc_object_t xpc_dictionary_get_value(xpc_object_t obj, const char *key)
{
    (void)obj;
    if (strcmp(key, "result") == 0) return mode == 3 ? NULL : &status;
    if (strcmp(key, "blacklisted") == 0) return mode == 5 ? NULL : &flag;
    return NULL;
}
static int64_t xpc_int64_get_value(xpc_object_t obj) { return obj->code; }
static bool xpc_bool_get_value(xpc_object_t obj) { return obj->value; }

#include "implementation.h"

int main(void)
{
    bool value = true;
    CHECK(jbclient_blacklist_check_path_checked(NULL, &value) != 0 && value);
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", NULL) != 0);

    mode = 0; status.code = 0; flag.value = false;
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", &value) == 0 && !value);
    flag.value = true;
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", &value) == 0 && value);

    mode = 1;
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", &value) != 0 && value);
    mode = 2; status.code = -1;
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", &value) != 0 && value);
    status.code = 0; mode = 3;
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", &value) != 0 && value);
    mode = 4; status.type = XPC_TYPE_BOOL;
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", &value) != 0 && value);
    status.type = XPC_TYPE_INT64; mode = 5;
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", &value) != 0 && value);
    mode = 6; flag.type = XPC_TYPE_INT64;
    CHECK(jbclient_blacklist_check_path_checked("/fixture/app", &value) != 0 && value);

    puts("10 blacklist RPC contract cases passed");
    return 0;
}
