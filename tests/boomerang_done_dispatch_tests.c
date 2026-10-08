#include <xpc/xpc.h>
#include <mach/mach.h>
#include <bsm/audit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define JBS_DOMAIN_ROOT 3
#define JBS_BOOMERANG_DONE 42

struct jbserver_impl { int unused; };

static unsigned generic_calls;
static unsigned reply_calls;
static xpc_object_t observed_reply;

static int jbserver_received_xpc_message(struct jbserver_impl *server, xpc_object_t message)
{
    (void)server;
    (void)message;
    generic_calls++;
    /* The current generic dispatcher replies ENOTSUP itself and reports handled. */
    return 0;
}

static bool fixture_boomerang_domain_allowed(audit_token_t token)
{
    (void)token;
    return true;
}

static void fixture_get_audit_token(xpc_object_t message, audit_token_t *token)
{
    (void)message;
    memset(token, 0, sizeof(*token));
}

static xpc_object_t fixture_create_reply(xpc_object_t message)
{
    (void)message;
    return xpc_dictionary_create(NULL, NULL, 0);
}

static int fixture_send_reply(xpc_object_t reply)
{
    reply_calls++;
    if (observed_reply) xpc_release(observed_reply);
    observed_reply = xpc_retain(reply);
    return 0;
}

#define boomerang_domain_allowed fixture_boomerang_domain_allowed
#define xpc_dictionary_get_audit_token fixture_get_audit_token
#define xpc_dictionary_create_reply fixture_create_reply
#define xpc_pipe_routine_reply fixture_send_reply
#include "implementation.h"
#undef xpc_pipe_routine_reply
#undef xpc_dictionary_create_reply
#undef xpc_dictionary_get_audit_token
#undef boomerang_domain_allowed

int main(void)
{
    struct jbserver_impl server = {0};
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(message, "jb-domain", JBS_DOMAIN_ROOT);
    xpc_dictionary_set_uint64(message, "action", JBS_BOOMERANG_DONE);

    int result = jbserver_received_boomerang_xpc_message(&server, message);
    unsigned failures = 0;
    failures += result != JBS_BOOMERANG_DONE;
    failures += generic_calls != 0;
    failures += reply_calls != 1;
    failures += !observed_reply;
    if (observed_reply) {
        failures += xpc_dictionary_get_int64(observed_reply, "result") != 0;
        xpc_release(observed_reply);
    }
    xpc_release(message);

    printf("result=%d generic_calls=%u reply_calls=%u failures=%u\n",
           result, generic_calls, reply_calls, failures);
    return failures ? 1 : 0;
}
