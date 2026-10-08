#include "jbserver.h"
#include "util.h"
#include <errno.h>

#include "roothider.h"

static int jbserver_reply_error(xpc_object_t message, int error)
{
	xpc_object_t reply = xpc_dictionary_create_reply(message);
	if (!reply) return -1;
	xpc_dictionary_set_int64(reply, "result", -1);
	xpc_dictionary_set_int64(reply, "error-number", error);
	xpc_pipe_routine_reply(reply);
	xpc_release(reply);
	return 0;
}

static bool jbserver_argument_valid(const jbserver_arg *argument, xpc_object_t value)
{
	if (argument->out || argument->type == JBS_TYPE_CALLER_TOKEN) return true;
	if (!value) return argument->optional;
	xpc_type_t type = xpc_get_type(value);
	switch (argument->type) {
		case JBS_TYPE_BOOL: return type == XPC_TYPE_BOOL;
		case JBS_TYPE_UINT64: return type == XPC_TYPE_UINT64;
		case JBS_TYPE_STRING: return type == XPC_TYPE_STRING;
		case JBS_TYPE_DATA: return type == XPC_TYPE_DATA;
		case JBS_TYPE_ARRAY: return type == XPC_TYPE_ARRAY;
		case JBS_TYPE_DICTIONARY: return type == XPC_TYPE_DICTIONARY;
		case JBS_TYPE_FD: return type == XPC_TYPE_FD;
		case JBS_TYPE_MACH_RECV:
		case JBS_TYPE_MACH_SEND:
		case JBS_TYPE_XPC_GENERIC: return true;
		default: return false;
	}
}

int jbserver_received_xpc_message(struct jbserver_impl *server, xpc_object_t xmsg)
{
	if (xpc_get_type(xmsg) != XPC_TYPE_DICTIONARY) return -1;

/**********************************************/
	if(roothide_handle_xpc_msg(xmsg)) return -2;
/*********************************************/

		xpc_object_t domainValue = xpc_dictionary_get_value(xmsg, "jb-domain");
		xpc_object_t actionValue = xpc_dictionary_get_value(xmsg, "action");
		if (!domainValue || xpc_get_type(domainValue) != XPC_TYPE_UINT64) return -1;
		if (!actionValue || xpc_get_type(actionValue) != XPC_TYPE_UINT64) return -1;

	uint64_t domainIdx = xpc_dictionary_get_uint64(xmsg, "jb-domain");
	if (domainIdx == 0) return -1;
	struct jbserver_domain *domain = server->domains[0];
		for (uint64_t i = 1; i < domainIdx && domain; i++) {
		domain = server->domains[i];
	}
	if (!domain) return -1;

	audit_token_t clientToken = { 0 };
	xpc_dictionary_get_audit_token(xmsg, &clientToken);

	if (domain->permissionHandler) {
		if (!domain->permissionHandler(clientToken)) return -2;
	}

	uint64_t actionIdx = xpc_dictionary_get_uint64(xmsg, "action");
	if (actionIdx == 0) return -1;
	struct jbserver_action *action = &domain->actions[0];
		for (uint64_t i = 1; i < actionIdx && action->handler; i++) {
			action = &domain->actions[i];
		}
		if (!action->handler) return jbserver_reply_error(xmsg, ENOTSUP);

		unsigned slotCount = 0;
		for (unsigned d = 0; d < 8 && action->args[d].name; d++) {
			jbserver_arg *argDesc = &action->args[d];
			unsigned width = argDesc->type == JBS_TYPE_DATA ? 2 : 1;
			if (width > 8 - slotCount) return jbserver_reply_error(xmsg, E2BIG);
			slotCount += width;
			xpc_object_t argValue = NULL;
			if (!argDesc->out && argDesc->type != JBS_TYPE_CALLER_TOKEN) {
				argValue = xpc_dictionary_get_value(xmsg, argDesc->name);
			}
			if (!jbserver_argument_valid(argDesc, argValue)) {
				return jbserver_reply_error(xmsg, EINVAL);
			}
		}

		xpc_object_t xreply = xpc_dictionary_create_reply(xmsg);
		if (!xreply) return -1;

	int (*handler)(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8) = action->handler;
	void *args[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	void *argsOut[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };

		for (unsigned d = 0, i = 0; d < 8 && action->args[d].name; d++) {
			jbserver_arg *argDesc = &action->args[d];
		if (!argDesc->out) {
			switch (argDesc->type) {
				case JBS_TYPE_BOOL:
				args[i] = (void *)xpc_dictionary_get_bool(xmsg, argDesc->name);
				break;
				case JBS_TYPE_UINT64:
				args[i] = (void *)xpc_dictionary_get_uint64(xmsg, argDesc->name);
				break;
				case JBS_TYPE_FD:
				args[i] = (void *)(int64_t)xpc_dictionary_dup_fd(xmsg, argDesc->name);
				break;
				case JBS_TYPE_MACH_RECV:
				args[i] = (void *)(int64_t)xpc_dictionary_extract_mach_recv(xmsg, argDesc->name);
				break;
				case JBS_TYPE_MACH_SEND:
				args[i] = (void *)(int64_t)xpc_dictionary_copy_mach_send(xmsg, argDesc->name);
				break;
				case JBS_TYPE_STRING:
				args[i] = (void *)xpc_dictionary_get_string(xmsg, argDesc->name);
				break;
					case JBS_TYPE_DATA: {
						args[i] = (void *)xpc_dictionary_get_data(xmsg, argDesc->name, (size_t *)&args[i+1]);
					break;
				}
				case JBS_TYPE_ARRAY:
				args[i] = (void *)xpc_dictionary_get_array(xmsg, argDesc->name);
				break;
				case JBS_TYPE_DICTIONARY:
				args[i] = (void *)xpc_dictionary_get_dictionary(xmsg, argDesc->name);
				break;
				case JBS_TYPE_XPC_GENERIC:
				args[i] = (void *)xpc_dictionary_get_value(xmsg, argDesc->name);
				break;
				case JBS_TYPE_CALLER_TOKEN:
				args[i] = (void *)&clientToken;
				break;
			}
		}
			else {
				args[i] = &argsOut[i];
				if (argDesc->type == JBS_TYPE_DATA) args[i+1] = &argsOut[i+1];
			}
			i += argDesc->type == JBS_TYPE_DATA ? 2 : 1;
		}

	errno = 0;
	int result = handler(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
	int handlerErrno = errno;

		for (unsigned d = 0, i = 0; d < 8 && action->args[d].name; d++) {
			jbserver_arg *argDesc = &action->args[d];
		if (argDesc->out) {
			switch (argDesc->type) {
				case JBS_TYPE_BOOL:
				xpc_dictionary_set_bool(xreply, argDesc->name, (bool)argsOut[i]);
				break;
				case JBS_TYPE_UINT64:
				xpc_dictionary_set_uint64(xreply, argDesc->name, (uint64_t)argsOut[i]);
				break;
				case JBS_TYPE_FD: {
					xpc_dictionary_set_fd(xreply, argDesc->name, (int)(int64_t)argsOut[i]);
					close((int)(int64_t)argsOut[i]);
					break;
				}
				case JBS_TYPE_MACH_RECV: {
					xpc_dictionary_set_mach_recv(xreply, argDesc->name, (mach_port_t)(uint64_t)argsOut[i]);
					break;
				}
				case JBS_TYPE_MACH_SEND: {
					xpc_dictionary_set_mach_send(xreply, argDesc->name, (mach_port_t)(uint64_t)argsOut[i]);
					break;
				}
				case JBS_TYPE_STRING: {
					if (argsOut[i]) {
						xpc_dictionary_set_string(xreply, argDesc->name, (char *)argsOut[i]);
						free(argsOut[i]);
					}
					break;
				}
					case JBS_TYPE_DATA: {
						if (argsOut[i]) {
							xpc_dictionary_set_data(xreply, argDesc->name, (const void *)argsOut[i], (size_t)argsOut[i+1]);
							free(argsOut[i]);
					}
					break;
				}
				case JBS_TYPE_ARRAY:
				case JBS_TYPE_DICTIONARY:
				case JBS_TYPE_XPC_GENERIC: {
					if (argsOut[i]) {
						xpc_dictionary_set_value(xreply, argDesc->name, (xpc_object_t)argsOut[i]);
						xpc_release((xpc_object_t)argsOut[i]);
					}
					break;
				}
				default:
				break;
			}
		}
		else {
				if (argDesc->type == JBS_TYPE_FD) {
					close((int)(int64_t)args[i]);
				}
			}
			i += argDesc->type == JBS_TYPE_DATA ? 2 : 1;
		}
	xpc_dictionary_set_int64(xreply, "result", result);
	if (result != 0) xpc_dictionary_set_int64(xreply, "error-number", handlerErrno);
	xpc_pipe_routine_reply(xreply);
	xpc_release(xreply);

	return 0;
}
