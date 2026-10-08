#include <xpc/xpc.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

static xpc_object_t observed_reply;
static unsigned handler_calls, collection_calls, trustcache_calls, synthetic_get_calls;
static int collection_result, trustcache_result;
static uintptr_t observed[8];
static const char *scenario;

static bool roothide_handle_xpc_msg(xpc_object_t message) { return false; }
static xpc_object_t (*real_dictionary_get_value)(xpc_object_t, const char *) = xpc_dictionary_get_value;
static xpc_object_t fixture_dictionary_get_value(xpc_object_t message, const char *name)
{
    if (!strcmp(name, "caller-token") || !strcmp(name, "output")) synthetic_get_calls++;
    return real_dictionary_get_value(message, name);
}
static void fixture_audit_token(xpc_object_t message, audit_token_t *token) { memset(token, 0, sizeof(*token)); }
static xpc_object_t fixture_create_reply(xpc_object_t message) { return xpc_dictionary_create_empty(); }
static int fixture_send_reply(xpc_object_t reply)
{
    if (observed_reply) xpc_release(observed_reply);
    observed_reply = xpc_retain(reply);
    return 0;
}
static mach_port_t fixture_extract_port(xpc_object_t message, const char *name) { return MACH_PORT_NULL; }
static void fixture_set_port(xpc_object_t message, const char *name, mach_port_t port) {}
#define xpc_dictionary_get_audit_token fixture_audit_token
#define xpc_dictionary_get_value fixture_dictionary_get_value
#define xpc_dictionary_create_reply fixture_create_reply
#define xpc_pipe_routine_reply fixture_send_reply
#define xpc_dictionary_extract_mach_recv fixture_extract_port
#define xpc_dictionary_copy_mach_send fixture_extract_port
#define xpc_dictionary_set_mach_recv fixture_set_port
#define xpc_dictionary_set_mach_send fixture_set_port
#define JBLogError(...) ((void)0)
#define JBLogDebug(...) ((void)0)

typedef uint8_t cdhash_t[20];
static int recurse_collect_untrusted_cdhashes(const char *path, const char *image, const char *executable,
                                              const char *cwd, void *arch, cdhash_t **hashes, uint32_t *count)
{
    collection_calls++;
    *hashes = NULL;
    *count = 0;
    if (collection_result != 0) return collection_result;
    if (!strcmp(scenario, "arch-collected-hash")) {
        *hashes = calloc(1, sizeof(cdhash_t));
        if (!*hashes) return -1;
        *count = 1;
    }
    return 0;
}
static int jb_trustcache_add_cdhashes(cdhash_t *hashes, uint32_t count)
{
    trustcache_calls++;
    return trustcache_result;
}
static bool isBlacklistedPid(pid_t pid) { return pid == 42; }
static bool isBlacklistedPath(const char *path) { return !strcmp(path, "/fixture"); }
static bool isBlacklistedApp(const char *bundle) { return !strcmp(bundle, "fixture.bundle"); }

#include "implementation.h"

static int handler(void *a0, void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
{
    handler_calls++;
    void *values[] = {a0, a1, a2, a3, a4, a5, a6, a7};
    for (unsigned i = 0; i < 8; i++) observed[i] = (uintptr_t)values[i];
    if (!strcmp(scenario, "data-output-followed-by-integer")) {
        *(void **)a0 = strdup("abc");
        *(size_t *)a1 = 3;
        *(uint64_t *)a2 = 99;
    }
    return 0;
}

static int dispatch_case(void)
{
    jbserver_arg descriptions[9] = {{.name = "value", .type = JBS_TYPE_STRING}};
    struct {
        bool (*permissionHandler)(audit_token_t);
        struct jbserver_action actions[2];
    } domain = {.actions = {{.handler = handler, .args = descriptions}, {0}}};
    struct jbserver_domain *domains[] = {(struct jbserver_domain *)&domain, NULL};
    struct jbserver_impl server = {.maxDomain = 1, .domains = domains};
    xpc_object_t message = xpc_dictionary_create_empty();
    xpc_dictionary_set_uint64(message, "jb-domain", 1);
    xpc_dictionary_set_uint64(message, "action", 1);
    bool valid = false;
    int expected_error = EINVAL;
    bool envelope_error = false;

    if (!strcmp(scenario, "wrong-string")) xpc_dictionary_set_uint64(message, "value", 7);
    else if (!strcmp(scenario, "wrong-bool")) {
        descriptions[0].type = JBS_TYPE_BOOL;
        xpc_dictionary_set_string(message, "value", "yes");
    } else if (!strcmp(scenario, "wrong-integer")) {
        descriptions[0].type = JBS_TYPE_UINT64;
        xpc_dictionary_set_int64(message, "value", -1);
    } else if (!strcmp(scenario, "wrong-array")) {
        descriptions[0].type = JBS_TYPE_ARRAY;
        xpc_dictionary_set_string(message, "value", "[]");
    } else if (!strcmp(scenario, "wrong-dictionary")) {
        descriptions[0].type = JBS_TYPE_DICTIONARY;
        xpc_dictionary_set_string(message, "value", "{}");
    } else if (!strcmp(scenario, "wrong-data")) {
        descriptions[0].type = JBS_TYPE_DATA;
        xpc_dictionary_set_string(message, "value", "abc");
    } else if (!strcmp(scenario, "missing-generic")) descriptions[0].type = JBS_TYPE_XPC_GENERIC;
    else if (!strcmp(scenario, "valid-scalars")) {
        descriptions[0].type = JBS_TYPE_BOOL;
        descriptions[1] = (jbserver_arg){.name = "integer", .type = JBS_TYPE_UINT64};
        xpc_dictionary_set_bool(message, "value", false);
        xpc_dictionary_set_uint64(message, "integer", 0);
        valid = true;
    } else if (!strcmp(scenario, "optional-absent")) {
#ifdef FIXTURE_HAS_OPTIONAL
        descriptions[0].optional = true;
#endif
        valid = true;
    } else if (!strcmp(scenario, "data-followed-by-bool")) {
        descriptions[0].type = JBS_TYPE_DATA;
        descriptions[1] = (jbserver_arg){.name = "attach", .type = JBS_TYPE_BOOL};
        xpc_dictionary_set_data(message, "value", "abc", 3);
        xpc_dictionary_set_bool(message, "attach", true);
        valid = true;
    } else if (!strcmp(scenario, "data-output-followed-by-integer")) {
        descriptions[0].type = JBS_TYPE_DATA;
        descriptions[0].out = true;
        descriptions[1] = (jbserver_arg){.name = "tail", .type = JBS_TYPE_UINT64, .out = true};
        valid = true;
    } else if (!strcmp(scenario, "caller-token-no-lookup")) {
        descriptions[0] = (jbserver_arg){.name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN};
        valid = true;
    } else if (!strcmp(scenario, "output-no-lookup")) {
        descriptions[0] = (jbserver_arg){.name = "output", .type = JBS_TYPE_UINT64, .out = true};
        valid = true;
    } else if (!strcmp(scenario, "data-capacity") || !strcmp(scenario, "eight-slots")) {
        static const char *names[] = {"a", "b", "c", "d", "e", "f", "g", "h"};
        for (unsigned i = 0; i < 8; i++) {
            descriptions[i] = (jbserver_arg){.name = names[i], .type = JBS_TYPE_UINT64};
            xpc_dictionary_set_uint64(message, names[i], i + 1);
        }
        valid = !strcmp(scenario, "eight-slots");
        if (!valid) {
            descriptions[7].type = JBS_TYPE_DATA;
            xpc_dictionary_set_data(message, "h", "abc", 3);
            expected_error = E2BIG;
        }
    } else if (!strcmp(scenario, "unknown-action")) {
        xpc_dictionary_set_uint64(message, "action", 2);
        expected_error = ENOTSUP;
    } else if (!strcmp(scenario, "wrong-domain-type")) {
        xpc_dictionary_set_string(message, "jb-domain", "1");
        envelope_error = true;
    } else if (!strcmp(scenario, "wrong-action-type")) {
        xpc_dictionary_set_string(message, "action", "1");
        envelope_error = true;
    }

    int result = jbserver_received_xpc_message(&server, message);
    unsigned failures = 0;
    if (envelope_error) failures += result != -1 || handler_calls != 0;
    else {
        failures += result != 0 || handler_calls != (unsigned)valid || !observed_reply;
        if (observed_reply) {
            failures += xpc_dictionary_get_int64(observed_reply, "result") != (valid ? 0 : -1);
            if (!valid) failures += xpc_dictionary_get_int64(observed_reply, "error-number") != expected_error;
        }
    }
    if (!strcmp(scenario, "data-followed-by-bool")) failures += observed[1] != 3 || observed[2] != 1;
    if (!strcmp(scenario, "caller-token-no-lookup") || !strcmp(scenario, "output-no-lookup")) failures += synthetic_get_calls != 0;
    if (!strcmp(scenario, "eight-slots")) failures += observed[7] != 8;
    if (!strcmp(scenario, "data-output-followed-by-integer") && observed_reply) {
        size_t length = 0;
        const void *data = xpc_dictionary_get_data(observed_reply, "value", &length);
        failures += !data || length != 3 || memcmp(data, "abc", 3);
        failures += xpc_dictionary_get_uint64(observed_reply, "tail") != 99;
    }
    printf("%s: result=%d handler_calls=%u failures=%u\n", scenario, result, handler_calls, failures);
    if (observed_reply) xpc_release(observed_reply);
    xpc_release(message);
    return failures ? 1 : 0;
}

static int blacklist_case(void)
{
    const char *kind = "pid";
    xpc_object_t value = xpc_uint64_create(42);
    bool valid = !strncmp(scenario, "valid-", 6);
    if (!strcmp(scenario, "missing-blacklist-type")) kind = NULL;
    else if (!strcmp(scenario, "wrong-blacklist-pid")) {
        xpc_release(value);
        value = xpc_string_create("42");
    } else if (!strcmp(scenario, "oversized-blacklist-pid")) {
        xpc_release(value);
        value = xpc_uint64_create(UINT64_C(0x10000002a));
    } else if (!strcmp(scenario, "wrong-blacklist-path")) kind = "path";
    else if (!strcmp(scenario, "valid-blacklist-path")) {
        kind = "path";
        xpc_release(value);
        value = xpc_string_create("/fixture");
    } else if (!strcmp(scenario, "unknown-blacklist-type")) kind = "unknown";
    bool blacklisted = false;
    int result = roothide_blacklist_check(NULL, kind, value, &blacklisted);
    unsigned failures = valid ? result != 0 || !blacklisted : result == 0;
    xpc_release(value);
    printf("%s: result=%d failures=%u\n", scenario, result, failures);
    return failures ? 1 : 0;
}

static int arch_case(void)
{
    xpc_object_t array = xpc_array_create_empty();
    unsigned count = 1;
    bool valid = false;
    bool expect_failure = false;
    if (!strcmp(scenario, "arch-collector-failure")) {
        collection_result = EIO;
        valid = true;
        expect_failure = true;
    } else if (!strcmp(scenario, "arch-collected-hash")) {
        valid = true;
    } else if (!strcmp(scenario, "arch-absent")) {
        xpc_release(array);
        array = NULL;
        count = 0;
        valid = true;
    } else if (!strcmp(scenario, "arch-empty")) { count = 0; valid = true; }
    else if (!strcmp(scenario, "arch-valid")) valid = true;
    else if (!strcmp(scenario, "arch-limit")) { count = 64; valid = true; }
    else if (!strcmp(scenario, "arch-over-limit")) count = 65;
    else if (!strcmp(scenario, "arch-wrong-container")) {
        xpc_release(array);
        array = xpc_dictionary_create_empty();
        count = 0;
    }
    for (unsigned i = 0; i < count; i++) {
        xpc_object_t arch = xpc_dictionary_create_empty();
        xpc_dictionary_set_uint64(arch, "type", 0x100000c);
        xpc_dictionary_set_uint64(arch, "subtype", UINT32_MAX);
        if (!strcmp(scenario, "arch-wrong-element")) {
            xpc_release(arch);
            arch = xpc_uint64_create(7);
        } else if (!strcmp(scenario, "arch-wrong-type")) xpc_dictionary_set_string(arch, "type", "arm64");
        else if (!strcmp(scenario, "arch-missing-subtype")) xpc_dictionary_set_value(arch, "subtype", NULL);
        else if (!strcmp(scenario, "arch-overflow")) xpc_dictionary_set_uint64(arch, "type", UINT64_C(0x10100000c));
        xpc_array_append_value(array, arch);
        xpc_release(arch);
    }
    int result = trust_macho_recurse("/fixture", NULL, "/fixture", NULL, array);
    unsigned failures = 0;
    if (expect_failure) {
        failures += result == 0 || collection_calls != 1;
        if (!strcmp(scenario, "arch-collector-failure")) failures += trustcache_calls != 0;
    } else {
        failures += valid ? result != 0 || collection_calls != 1 : result == 0 || collection_calls != 0;
        if (!strcmp(scenario, "arch-collected-hash")) failures += trustcache_calls != 0;
    }
    printf("%s: result=%d collection_calls=%u trustcache_calls=%u failures=%u\n", scenario, result, collection_calls, trustcache_calls, failures);
    if (array) xpc_release(array);
    return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    scenario = argv[1];
    if (!strncmp(scenario, "arch-", 5)) return arch_case();
    if (strstr(scenario, "blacklist")) return blacklist_case();
    return dispatch_case();
}
