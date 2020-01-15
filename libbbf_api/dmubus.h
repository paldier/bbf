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

#ifndef __DMUBUS_H
#define __DMUBUS_H

#include <json-c/json.h>

#define UBUS_ARGS (struct ubus_arg[])

enum ubus_arg_type {
	String,
	Integer,
};

struct ubus_arg {
	const char *key;
	const char *val;
	enum ubus_arg_type type;
};

#define dm_ubus_get_value(jobj,ARGC,args...) \
		dmjson_get_value(jobj, ARGC, ##args)

int dmubus_call(char *obj, char *method, struct ubus_arg u_args[],
		int u_args_size, json_object **req_res);
int dmubus_call_set(char *obj, char *method, struct ubus_arg u_args[], int u_args_size);
void dmubus_free();

#endif
