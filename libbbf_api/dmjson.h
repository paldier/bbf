/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *
 */

#ifndef __DMJSON_H
#define __DMJSON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include "dmbbf.h"
#include "dmmem.h"

struct dmjson_arg {
	char *key;
	char *val;
};

#define DMJSON_ARGS (struct dmjson_arg[])

void dm_add_json_obj(json_object *json_obj_out, char *object, char *string);
void dmjson_printf(int argc, struct dmjson_arg dmarg[]);
void dmjson_fprintf(FILE *fp, int argc, struct dmjson_arg dmarg[]);
void bbf_api_dmjson_parse_init(char *msg);
void bbf_api_dmjson_parse_fini(void);
void bbf_api_dmjson_get_var(char *jkey, char **jval);
json_object *bbf_api_dmjson_select_obj(json_object * jobj, char *argv[]);
json_object *__dmjson_get_obj(json_object *mainjobj, int argc, ...);
char *____dmjson_get_value_in_obj(json_object *mainjobj, char *argv[]);
char *__dmjson_get_value_in_obj(json_object *mainjobj, int argc, ...);
char *__dmjson_get_value_in_array_idx(json_object *mainjobj, json_object **arrobj, char *defret, int index, int argc, ...);
json_object *__dmjson_select_obj_in_array_idx(json_object *mainjobj, json_object **arrobj, int index, int argc, ...);
const char * __dmjson_get_string(json_object *jobj, const char *name);

char *____dmjson_get_value_array_all(json_object *mainjobj, char *delim, char *argv[]);
char *__dmjson_get_value_array_all(json_object *mainjobj, char *delim, int argc, ...);

#define dmjson_get_value(JOBJ,ARGC,args...) \
	__dmjson_get_value_in_obj(JOBJ, ARGC, ##args)
#define dmjson_get_obj(JOBJ,ARGC,args...) \
	__dmjson_get_obj(JOBJ, ARGC, ##args)

#define dmjson_get_value_in_array_idx(MAINJOBJ,INDEX,ARGC,args...) \
	__dmjson_get_value_in_array_idx(MAINJOBJ, NULL, "", INDEX, ARGC, ##args)

#define dmjson_select_obj_in_array_idx(MAINJOBJ,INDEX,ARGC,args...) \
	__dmjson_select_obj_in_array_idx(MAINJOBJ, NULL, INDEX, ARGC, ##args)

#define dmjson_get_value_array_all(MAINJOBJ,DELIM,ARGC,args...) \
	__dmjson_get_value_array_all(MAINJOBJ, DELIM, ARGC, ##args);

#define dmjson_foreach_obj_in_array(MAINJOBJ,ARROBJ,OBJ,INDEX,ARGC,args...) \
	for (INDEX = 0, ARROBJ = NULL, OBJ = __dmjson_select_obj_in_array_idx(MAINJOBJ, &(ARROBJ), INDEX, ARGC, ##args);\
		OBJ; \
		OBJ = __dmjson_select_obj_in_array_idx(MAINJOBJ, &(ARROBJ), ++INDEX, 0))

#define dmjson_foreach_value_in_array(MAINJOBJ,ARROBJ,VAL,INDEX,ARGC,args...) \
	for (INDEX = 0, ARROBJ = NULL, VAL = __dmjson_get_value_in_array_idx(MAINJOBJ, &(ARROBJ), NULL, INDEX, ARGC, ##args);\
		VAL; \
		VAL = __dmjson_get_value_in_array_idx(MAINJOBJ, &(ARROBJ), NULL, ++INDEX, 0))

#endif
