/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *    Author Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include <libbbf_api/dmcommon.h>

extern int end_session_flag;
extern unsigned int upnp_in_user_mask;
extern struct list_head list_execute_end_session;

int bbfdmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value);
void bbf_apply_end_session(void);
int set_bbfdatamodel_type(int bbf_type);
int bbf_set_ip_version(int ipversion);
void bbf_del_list_parameter(struct dm_parameter *dm_parameter);
int dm_update_file_enabled_notify(char *param, char *new_value);
void dmjson_parse_init(char *msg);
void dmjson_parse_fini(void);
json_object *dmjson_select_obj(json_object * jobj, char *argv[]);
void del_list_fault_param(struct param_fault *param_fault);
int copy_temporary_file_to_original_file(char *f1, char *f2);
void dmjson_get_var(char *jkey, char **jval);
void dm_update_enabled_notify(struct dm_enabled_notify *p, char *new_value);
struct list_head get_bbf_list_enabled_lw_notify(void);


void apply_end_session(void);
int dm_add_end_session(struct dmctx *ctx, void(*function)(struct execute_end_session *), int action, void *data);
void cwmp_set_end_session (unsigned int flag);
