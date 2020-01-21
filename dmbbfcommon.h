/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include <libbbf_api/dmbbf.h>
#include <libbbf_api/dmuci.h>
#include <libbbf_api/dmubus.h>
#include <libbbf_api/dmjson.h>
#include <libbbf_api/dmcommon.h>

int bbfdmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value);
void bbf_apply_end_session(void);
int set_bbfdatamodel_type(int bbf_type);
int set_upnp_in_user_mask(unsigned int upnp_user_mask);
int bbf_set_ip_version(int ipversion);
int set_bbf_end_session_flag(int flag);
int reset_bbf_end_session_flag(void);
void bbf_del_list_parameter(struct dm_parameter *dm_parameter);
void bbf_cwmp_set_end_session (unsigned int flag);
int bbfdm_update_file_enabled_notify(char *param, char *new_value);
void bbfdmjson_parse_init(char *msg);
void bbfdmjson_parse_fini(void);
json_object *bbfdmjson_select_obj(json_object * jobj, char *argv[]);
void bbf_del_list_fault_param(struct param_fault *param_fault);
int dm_copy_temporary_file_to_original_file(char *f1, char *f2);
void bbfdmjson_get_var(char *jkey, char **jval);
void bbfdm_update_enabled_notify(struct dm_enabled_notify *p, char *new_value);
struct list_head get_bbf_list_enabled_lw_notify(void);

