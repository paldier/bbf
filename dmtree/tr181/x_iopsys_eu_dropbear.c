/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#include "x_iopsys_eu_dropbear.h"


int browseXIopsysEuDropbear(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *idropbear = NULL, *idropbear_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dropbear", "dropbear", "dmmap_dropbear", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		idropbear =  handle_update_instance(1, dmctx, &idropbear_last, update_instance_alias_bbfdm, 3, p->dmmap_section, "dropbearinstance", "dropbearalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, idropbear) == DM_STOP)
			break;
	}
	return 0;
}

/************************************************************************************* 
**** function ****
**************************************************************************************/
static int get_x_iopsys_eu_dropbear_password_auth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "PasswordAuth", "1");
	*value = ((strcmp(res, "on") == 0) || *res == '1') ? "1" : "0";
	return 0;
}

static int set_x_iopsys_eu_dropbear_password_auth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "PasswordAuth", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_root_password_auth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "RootPasswordAuth", "1");
	*value = ((strcmp(res, "on") == 0) || *res == '1') ? "1" : "0";
	return 0;
}

static int set_x_iopsys_eu_dropbear_root_password_auth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "RootPasswordAuth", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "Port", "22");
	return 0;
}

static int set_x_iopsys_eu_dropbear_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "Port", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_root_login(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "RootLogin", value);
	if ((*value)[0] == '\0' || ((*value)[0] == 'o' && (*value)[1] == 'n') || (*value)[0] == '1' )
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_x_iopsys_eu_dropbear_root_login(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "RootLogin", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_verbose(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "verbose", "0");
	return 0;
}

static int set_x_iopsys_eu_dropbear_verbose(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "verbose", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_gateway_ports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "GatewayPorts", "0");
	return 0;
}

static int set_x_iopsys_eu_dropbear_gateway_ports(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "GatewayPorts", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "Interface", value);
	return 0;
}

static int set_x_iopsys_eu_dropbear_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "Interface", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_rsakeyfile(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "rsakeyfile", value);
	return 0;
}

static int set_x_iopsys_eu_dropbear_rsakeyfile(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "rsakeyfile", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_dsskeyfile(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dsskeyfile", value);
	return 0;
}

static int set_x_iopsys_eu_dropbear_dsskeyfile(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dsskeyfile", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_ssh_keepalive(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "SSHKeepAlive", "300");
	return 0;
}

static int set_x_iopsys_eu_dropbear_ssh_keepalive(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (strcmp(value, "300") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "SSHKeepAlive", "");
			else
				dmuci_set_value_by_section((struct uci_section *)data, "SSHKeepAlive", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_idle_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "IdleTimeout", "300");
	return 0;
}

static int set_x_iopsys_eu_dropbear_idle_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (value[0] == '0')
				dmuci_set_value_by_section((struct uci_section *)data, "IdleTimeout", "");
			else
				dmuci_set_value_by_section((struct uci_section *)data, "IdleTimeout", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_dropbear_banner_file(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "BannerFile", value);
	return 0;
}

static int set_x_iopsys_eu_dropbear_banner_file(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "BannerFile", value);
			return 0;
	}
	return 0;
}

////////////////////////SET AND GET ALIAS/////////////////////////////////

static int get_x_iopsys_eu_dropbear_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_dropbear", "dropbear", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "dropbearalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_x_iopsys_eu_dropbear_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dropbear", "dropbear", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "dropbearalias", value);
			return 0;
	}
	return 0;
}

/***** ADD DEL OBJ *******/
int add_dropbear_instance(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *value, *v, *instance;
	struct uci_section *dropbear_sec = NULL, *dmmap_sec= NULL;

	check_create_dmmap_package("dmmap_dropbear");
	instance = get_last_instance_bbfdm("dmmap_dropbear", "dropbear", "dropbearinstance");

	dmuci_add_section("dropbear", "dropbear", &dropbear_sec, &value);
	dmuci_set_value_by_section(dropbear_sec, "verbose", "0");
	dmuci_set_value_by_section(dropbear_sec, "Port", "22");
	dmuci_set_value_by_section(dropbear_sec, "RootLogin", "1");
	dmuci_set_value_by_section(dropbear_sec, "GatewayPorts", "0");
	dmuci_set_value_by_section(dropbear_sec, "SSHKeepAlive", "300");
	dmuci_set_value_by_section(dropbear_sec, "IdleTimeout", "0");

	dmuci_add_section_bbfdm("dmmap_dropbear", "dropbear", &dmmap_sec, &v);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(dropbear_sec));
	*instancepara = update_instance_bbfdm(dmmap_sec, instance, "dropbearinstance");
	return 0;
}

int delete_dropbear_instance(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if(is_section_unnamed(section_name((struct uci_section *)data))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_dropbear", "dropbear", "dropbearinstance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "dropbearinstance", "dmmap_dropbear", "dropbear");
				dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_dropbear", "dropbear", section_name((struct uci_section *)data), &dmmap_section);
				dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("dropbear", "dropbear", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_dropbear", "dropbear", section_name(ss), &dmmap_section);
					if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_dropbear", "dropbear", section_name(ss), &dmmap_section);
				if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
		return 0;
	}
	return 0;
}

/*** DMROOT.X_IOPSYS_EU_Dropbear.{i}. ****/
DMLEAF X_IOPSYS_EU_DropbearParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_x_iopsys_eu_dropbear_alias, set_x_iopsys_eu_dropbear_alias, NULL, NULL, BBFDM_BOTH},
{"PasswordAuth", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_dropbear_password_auth, set_x_iopsys_eu_dropbear_password_auth, NULL, NULL, BBFDM_BOTH},
{"RootPasswordAuth", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_dropbear_root_password_auth, set_x_iopsys_eu_dropbear_root_password_auth, NULL, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_x_iopsys_eu_dropbear_port, set_x_iopsys_eu_dropbear_port, NULL, NULL, BBFDM_BOTH},
{"RootLogin", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_dropbear_root_login, set_x_iopsys_eu_dropbear_root_login, NULL, NULL, BBFDM_BOTH},
{"GatewayPorts", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_dropbear_gateway_ports, set_x_iopsys_eu_dropbear_gateway_ports, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_x_iopsys_eu_dropbear_interface, set_x_iopsys_eu_dropbear_interface, NULL, NULL, BBFDM_BOTH},
{"RSAKeyFile", &DMWRITE, DMT_STRING, get_x_iopsys_eu_dropbear_rsakeyfile, set_x_iopsys_eu_dropbear_rsakeyfile, NULL, NULL, BBFDM_BOTH},
{"DSSKeyFile", &DMWRITE, DMT_STRING, get_x_iopsys_eu_dropbear_dsskeyfile, set_x_iopsys_eu_dropbear_dsskeyfile, NULL, NULL, BBFDM_BOTH},
{"SSHKeepAlive", &DMWRITE, DMT_UNINT, get_x_iopsys_eu_dropbear_ssh_keepalive, set_x_iopsys_eu_dropbear_ssh_keepalive, NULL, NULL, BBFDM_BOTH},
{"IdleTimeout", &DMWRITE, DMT_UNINT, get_x_iopsys_eu_dropbear_idle_timeout, set_x_iopsys_eu_dropbear_idle_timeout, NULL, NULL, BBFDM_BOTH},
{"Verbose", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_dropbear_verbose, set_x_iopsys_eu_dropbear_verbose, NULL, NULL, BBFDM_BOTH},
{"BannerFile", &DMWRITE, DMT_STRING, get_x_iopsys_eu_dropbear_banner_file, set_x_iopsys_eu_dropbear_banner_file, NULL, NULL, BBFDM_BOTH},
{0}
};
