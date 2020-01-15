/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *	Author: Mohamed Kallel <mohamed.kallel@pivasoftware.com>
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 */

#include <libubus.h>
#include "dmubus.h"
#include "dmmem.h"
#include "dmcommon.h"

#define UBUS_BUFFEER_SIZE 1024 * 8

struct dmubus_ctx dmubus_ctx;

#if DM_USE_LIBUBUS
static struct blob_buf b;
static struct ubus_context *ubus_ctx;
static int timeout = 1000;
static json_object *json_res = NULL;
#endif

static inline int ubus_arg_cmp(struct ubus_arg *src_args, int src_size, struct ubus_arg dst_args[], int dst_size)
{
	if (src_size != dst_size)
		return -1;
	int i;
	for (i = 0; i < src_size; i++) {
		if (strcmp( src_args[i].key, dst_args[i].key) != 0 || strcmp( src_args[i].val, dst_args[i].val) != 0)
			return -1;
	}
	return 0;
}

#if DM_USE_LIBUBUS

static void dm_libubus_free()
{
	if (ubus_ctx) {
		ubus_free(ubus_ctx);
		ubus_ctx = NULL;
	}

	blob_buf_free(&b);
	memset(&b, 0, sizeof(b));
}

static struct ubus_context * dm_libubus_init()
{
	return ubus_connect(NULL);
}

static void receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
	const char *str;

	if (!msg)
		return;

	str = blobmsg_format_json_indent(msg, true, -1);
	if (!str) {
		json_res = NULL;
		return;
	}

	json_res = json_tokener_parse(str);
	free((char *)str); //MEM should be free and not dmfree
	if (json_res != NULL && (is_error(json_res))) {
		json_object_put(json_res);
		json_res = NULL;
	}
}

static int __dm_ubus_call(const char *obj, const char *method, const struct ubus_arg u_args[], int u_args_size)
{
	uint32_t id;
	int i = 0;
	int rc = 0;

	json_res = NULL;

	if (ubus_ctx == NULL) {
		ubus_ctx = dm_libubus_init();
		if (ubus_ctx == NULL)
			return -1;
	}

	blob_buf_init(&b, 0);
	for (i = 0; i < u_args_size; i++)
		blobmsg_add_string(&b, u_args[i].key, u_args[i].val);

	if (!ubus_lookup_id(ubus_ctx, obj, &id))
		rc = ubus_invoke(ubus_ctx, id, method, b.head, receive_call_result_data, NULL, timeout);
	else
		rc = -1;

	return rc;
}

#else
static void dm_libubus_free() {}
#endif

int dmubus_call_set(char *obj, char *method, struct ubus_arg u_args[], int u_args_size)
{
#if !DM_USE_LIBUBUS
	char bufargs[256], *p;
	int i;
	p = bufargs;

	if (u_args_size) {
		sprintf(p, "{");
		for (i = 0; i < u_args_size; i++) {
			p += strlen(p);
			if (i == 0) {
				if(u_args[i].type != Integer)
					sprintf(p, "\"%s\": \"%s\"", u_args[i].key, u_args[i].val);
				else
					sprintf(p, "\"%s\": %s", u_args[i].key, u_args[i].val);
			} else {
				if(u_args[i].type != Integer)
					sprintf(p, ", \"%s\": \"%s\"", u_args[i].key, u_args[i].val);
				else
					sprintf(p, ", \"%s\": %s", u_args[i].key, u_args[i].val);
			}
		}
		p += strlen(p);
		sprintf(p, "}");
		DMCMD("ubus", 7, "-S", "-t", "1", "call", obj, method, bufargs);
	} else {
		DMCMD("ubus", 6, "-S", "-t", "1", "call", obj, method);
	}
	return 0;
#else
	int rc = __dm_ubus_call(obj, method, u_args, u_args_size);

	if (json_res != NULL) {
		json_object_put(json_res);
		json_res = NULL;
	}
	return rc;
#endif
}

static inline json_object *ubus_call_req(char *obj, char *method, struct ubus_arg u_args[], int u_args_size)
{
#if !DM_USE_LIBUBUS
	json_object *res = NULL;
	char *ubus_return, bufargs[256], *p;
	int i, pp = 0;
	p = bufargs;

	if (u_args_size) {
		sprintf(p, "{");
		for (i = 0; i < u_args_size; i++) {
			p += strlen(p);
			if (i == 0) {
				if(u_args[i].type != Integer)
					sprintf(p, "\"%s\": \"%s\"", u_args[i].key, u_args[i].val);
				else
					sprintf(p, "\"%s\": %s", u_args[i].key, u_args[i].val);
			} else {
				if(u_args[i].type != Integer)
					sprintf(p, ", \"%s\": \"%s\"", u_args[i].key, u_args[i].val);
				else
					sprintf(p, ", \"%s\": %s", u_args[i].key, u_args[i].val);
			}
		}
		p += strlen(p);
		sprintf(p, "}");
		pp = dmcmd("ubus", 7, "-S", "-t", "3", "call", obj, method, bufargs);
	} else {
		pp = dmcmd("ubus", 6, "-S", "-t", "3", "call", obj, method);
	}
	if (pp) {
		dmcmd_read_alloc(pp, &ubus_return);
		close(pp);
		if (ubus_return) {
			res = json_tokener_parse(ubus_return);
			if (res != NULL && (is_error(res))) {
				json_object_put(res);
				res = NULL;
			}
		}
	}
	return res;

#else
	__dm_ubus_call(obj, method, u_args, u_args_size);
	return json_res;
#endif
}

int dmubus_call(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
{
	struct ubus_obj *i = NULL;
	struct ubus_meth *j = NULL;
	struct ubus_msg *k = NULL;
	json_object **jr;
	bool found = false;

	*req_res = NULL;
	list_for_each_entry(i, &dmubus_ctx.obj_head, list) {
		if (strcmp(obj, i->name) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		i = dmcalloc(1, sizeof(struct ubus_obj));
		//init method head
		INIT_LIST_HEAD(&i->method_head);
		i->name = dmstrdup(obj);
		list_add(&i->list, &dmubus_ctx.obj_head);
	}
	found = false;
	list_for_each_entry(j, &i->method_head, list) {
		if (strcmp(method, j->name) == 0) {
			*req_res = j->res;
			found = true;
			break;
		}
	}
	if (!found) {
		j = dmcalloc(1, sizeof(struct ubus_meth));
		//init message head
		INIT_LIST_HEAD(&j->msg_head);
		j->name = dmstrdup(method);
		list_add(&j->list, &i->method_head);
		jr = &j->res;
	}
	// Arguments
	if (u_args_size != 0) {
		found = false;
		list_for_each_entry(k, &j->msg_head, list) {
			if (ubus_arg_cmp(k->ug, k->ug_size, u_args, u_args_size) == 0) {
				*req_res = k->res;
				found = true;
				break;
			}
		}
		if (!found) {
			k = dmcalloc(1, sizeof(struct ubus_msg));
			list_add(&k->list, &j->msg_head);
			k->ug = dmcalloc(u_args_size, sizeof(struct ubus_arg));
			k->ug_size = u_args_size;
			jr = &k->res;
			int c;
			for (c = 0; c < u_args_size; c++) {
				k->ug[c].key = dmstrdup(u_args[c].key);
				k->ug[c].val = dmstrdup(u_args[c].val);
			}
		}
	}
	if (!found) {
		*jr = ubus_call_req(obj, method, u_args, u_args_size);
		*req_res = *jr;
	}
	return 0;
}

void dmubus_ctx_free(struct dmubus_ctx *ctx)
{
	struct ubus_obj *i, *_i;
	struct ubus_meth *j, *_j;
	struct ubus_msg *k, *_k;

	list_for_each_entry_safe(i, _i, &ctx->obj_head, list) {
		list_for_each_entry_safe(j, _j, &i->method_head, list) {
			list_for_each_entry_safe(k, _k, &j->msg_head, list) {
				if (k->ug_size != 0) {
					int c;
					for (c = 0; c < k->ug_size; c++) {
						dmfree(k->ug[c].key);
						dmfree(k->ug[c].val);
					}
					dmfree(k->ug);
				}
				list_del(&k->list);
				if (k->res)
					json_object_put(k->res);
				dmfree(k);
			}
			list_del(&j->list);
			if (j->res)
				json_object_put(j->res);
			dmfree(j->name);
			dmfree(j);
		}
		list_del(&i->list);
		dmfree(i->name);
		dmfree(i);
	}
	dm_libubus_free();
}
