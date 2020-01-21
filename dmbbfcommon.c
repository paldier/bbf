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

#include "dmbbfcommon.h"

int bbfdmuci_lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, char *package, char *section, char *option, char *value)
{
	return dmuci_lookup_ptr(ctx, ptr, package, section, option, value);
}

void bbf_apply_end_session(void)
{
	apply_end_session();
}

int set_bbfdatamodel_type(int bbf_type)
{
	bbfdatamodel_type = bbf_type;
	return 0;
}

int set_upnp_in_user_mask(unsigned int upnp_user_mask)
{
	upnp_in_user_mask = upnp_user_mask;
	return 0;
}

int bbf_set_ip_version(int ipversion)
{
	ip_version = ipversion;
	return 0;
}

int set_bbf_end_session_flag(int flag)
{
	return (end_session_flag &= flag);
}

int reset_bbf_end_session_flag(void)
{
	end_session_flag = 0;
	return 0;
}

void bbf_del_list_parameter(struct dm_parameter *dm_parameter)
{
	del_list_parameter(dm_parameter);
}

void bbf_cwmp_set_end_session (unsigned int flag)
{
	cwmp_set_end_session (flag);
}

int bbfdm_update_file_enabled_notify(char *param, char *new_value)
{
	return dm_update_file_enabled_notify(param, new_value);
}

void bbfdmjson_parse_init(char *msg)
{
	dmjson_parse_init(msg);
}

void bbfdmjson_parse_fini(void)
{
	dmjson_parse_fini();
}

json_object *bbfdmjson_select_obj(json_object * jobj, char *argv[])
{
	return (dmjson_select_obj(jobj, argv));
}

void bbf_del_list_fault_param(struct param_fault *param_fault)
{
	del_list_fault_param(param_fault);
}

int dm_copy_temporary_file_to_original_file(char *f1, char *f2)
{
	return copy_temporary_file_to_original_file(f1, f2);
}

void bbfdmjson_get_var(char *jkey, char **jval)
{
	dmjson_get_var(jkey, jval);
}

void bbfdm_update_enabled_notify(struct dm_enabled_notify *p, char *new_value)
{
	dm_update_enabled_notify(p, new_value);
}

struct list_head get_bbf_list_enabled_lw_notify(void)
{
	return list_enabled_lw_notify;
}
