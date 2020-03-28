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

#include <json-c/json.h>
#include <libubus.h>
#include "dmubus.h"
#include "dmmem.h"
#include "dmcommon.h"

static LIST_HEAD(dmubus_cache);

struct dm_ubus_cache_entry {
	struct list_head list;
	json_object *data;
	unsigned hash;
};

struct dm_ubus_req {
	const char *obj;
	const char *method;
	struct ubus_arg *args;
	unsigned n_args;
};

#if DM_USE_LIBUBUS
static struct blob_buf b;
static struct ubus_context *ubus_ctx;
static int timeout = 1000;
static json_object *json_res = NULL;

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
	for (i = 0; i < u_args_size; i++) {
		if (u_args[i].type != Integer)
			blobmsg_add_string(&b, u_args[i].key, u_args[i].val);
		else
			blobmsg_add_u32(&b, u_args[i].key, atoi(u_args[i].val));
	}

	if (!ubus_lookup_id(ubus_ctx, obj, &id))
		rc = ubus_invoke(ubus_ctx, id, method, b.head,
				receive_call_result_data, NULL, timeout);
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
		if (ubus_return)
			res = json_tokener_parse(ubus_return);
	}
	return res;

#else
	__dm_ubus_call(obj, method, u_args, u_args_size);
	return json_res;
#endif
}

/* Based on an efficient hash function published by D. J. Bernstein
 */
static unsigned int djbhash(unsigned hash, const char *data, unsigned len)
{
	unsigned  i;

	for (i = 0; i < len; i++)
		hash = ((hash << 5) + hash) + data[i];

	return (hash & 0x7FFFFFFF);
}

static unsigned dm_ubus_req_hash(const struct dm_ubus_req *req)
{
	unsigned hash = 5381;
	unsigned i;

	hash = djbhash(hash, req->obj, strlen(req->obj));
	hash = djbhash(hash, req->method, strlen(req->method));

	for (i = 0; i < req->n_args; i++) {
		hash = djbhash(hash, req->args[i].key, strlen(req->args[i].key));
		hash = djbhash(hash, req->args[i].val, strlen(req->args[i].val));
	}
	return hash;
}

static const struct dm_ubus_cache_entry * dm_ubus_cache_lookup(unsigned hash)
{
	const struct dm_ubus_cache_entry *entry;
	const struct dm_ubus_cache_entry *entry_match = NULL;

	list_for_each_entry(entry, &dmubus_cache, list) {
		if (entry->hash == hash) {
			entry_match = entry;
			break;
		}
	}
	return entry_match;
}

static void dm_ubus_cache_entry_new(unsigned hash, json_object *data)
{
	struct dm_ubus_cache_entry *entry = malloc(sizeof(*entry));

	if (entry) {
		entry->data = data;
		entry->hash = hash;
		list_add_tail(&entry->list, &dmubus_cache);
	}
}

static void dm_ubus_cache_entry_free(struct dm_ubus_cache_entry *entry)
{
	list_del(&entry->list);
	json_object_put(entry->data);
	free(entry);
}

int dmubus_call(char *obj, char *method, struct ubus_arg u_args[], int u_args_size, json_object **req_res)
{
	const struct dm_ubus_req req = {
		.obj = obj,
		.method = method,
		.args = u_args,
		.n_args = u_args_size
	};
	const unsigned hash = dm_ubus_req_hash(&req);
	const struct dm_ubus_cache_entry *entry = dm_ubus_cache_lookup(hash);
	json_object *res;

	if (entry) {
		res = entry->data;
	} else {
		res = ubus_call_req(obj, method, u_args, u_args_size);
		dm_ubus_cache_entry_new(hash, res);
	}

	*req_res = res;
	return 0;
}

void dmubus_free()
{
	struct dm_ubus_cache_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &dmubus_cache, list)
		dm_ubus_cache_entry_free(entry);

	dm_libubus_free();
}
