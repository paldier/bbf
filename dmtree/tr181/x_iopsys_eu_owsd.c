/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "x_iopsys_eu_owsd.h"

static int browseXIopsysEuOWSDVirtualHost(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *iowsd_listen = NULL, *iowsd_listen_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("owsd", "owsd-listen", "dmmap_owsd", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		iowsd_listen =  handle_update_instance(1, dmctx, &iowsd_listen_last, update_instance_alias_bbfdm, 3, p->dmmap_section, "olisteninstance", "olistenalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, iowsd_listen) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/************************************************************************************* 
**** function related to owsd_origin ****
**************************************************************************************/
static int get_x_iopsys_eu_owsd_global_sock(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("owsd", "global", "sock", value);
	return 0;
}

static int set_x_iopsys_eu_owsd_global_sock(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("owsd", "global", "sock", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_global_redirect(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("owsd", "global", "redirect", value);
	return 0;
}

static int set_x_iopsys_eu_owsd_global_redirect(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("owsd", "global", "redirect", value);
			return 0;
	}
	return 0;
}

/*************************************************************************************
**** function related to owsd_websocket_interface ****
**************************************************************************************/
static int get_x_iopsys_eu_owsd_virtualhost_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "port", "");
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "port", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_virtualhost_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *iface;

	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &iface);
	if (iface[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), iface, value); // MEM WILL BE FREED IN DMMEMCLEAN
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmuci_set_value_by_section((struct uci_section *)data, "interface", linker);
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_virtualhost_ipv6_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *res = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "ipv6", "1");
	*value = (strcmp(res, "on") == 0) ? "1" : "0";
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_ipv6_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "ipv6", b ? "on" : "off");
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_virtualhost_whitelist_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "whitelist_interface_as_origin", "0");
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_whitelist_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "whitelist_interface_as_origin", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_virtualhost_whitelist_dhcp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "whitelist_dhcp_domains", "0");
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_whitelist_dhcp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "whitelist_dhcp_domains", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_virtualhost_origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val;

	dmuci_get_value_by_section_list((struct uci_section *)data, "origin", &val);
	if (val)
		*value = dmuci_list_to_string(val, " ");
	else
		*value = "";
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *pch, *spch;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_delete_by_section((struct uci_section *)data, "origin", NULL);
			value = dmstrdup(value);
			pch = strtok_r(value, " ", &spch);
			while (pch != NULL) {
				dmuci_add_list_value_by_section((struct uci_section *)data, "origin", pch);
				pch = strtok_r(NULL, " ", &spch);
			}
			dmfree(value);
			return 0;
	}
	return 0;
}

////////////////////////SET AND GET ALIAS/////////////////////////////////
static int get_x_iopsys_eu_owsd_virtualhost_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_owsd", "owsd-listen", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "olistenalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_owsd", "owsd-listen", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "olistenalias", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_ubus_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("owsd","ubusproxy","enable", value);
	return 0;
}

static int set_x_iopsys_eu_owsd_ubus_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("owsd", "ubusproxy", "enable", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_ubus_proxy_cert(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("owsd","ubusproxy","peer_cert", value);
	return 0;
}

static int set_x_iopsys_eu_owsd_ubus_proxy_cert(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("owsd", "ubusproxy", "peer_cert", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_ubus_proxy_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("owsd","ubusproxy","peer_key", value);
	return 0;
}

static int set_x_iopsys_eu_owsd_ubus_proxy_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("owsd", "ubusproxy", "peer_key", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_ubus_proxy_ca(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("owsd","ubusproxy","peer_ca", value);
	return 0;
}

static int set_x_iopsys_eu_owsd_ubus_proxy_ca(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("owsd", "ubusproxy", "peer_ca", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_virtualhost_certificate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "cert", value);
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_certificate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "cert", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_virtualhost_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "key", value);

	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "key", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_owsd_virtualhost_ca(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ca", value);
	return 0;
}

static int set_x_iopsys_eu_owsd_virtualhost_ca(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ca", value);
			return 0;
	}
	return 0;
}

/***** ADD DEL OBJ *******/
static int add_owsd_listen(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *value, *v, *instance;
	struct uci_section *listen_sec = NULL, *dmmap_sec = NULL;

	check_create_dmmap_package("dmmap_owsd");
	instance = get_last_instance_bbfdm("dmmap_owsd", "owsd-listen", "olisteninstance");

	dmuci_add_section("owsd", "owsd-listen", &listen_sec, &value);
	dmuci_set_value_by_section(listen_sec, "ipv6", "on");
	dmuci_set_value_by_section(listen_sec, "whitelist_interface_as_origin", "1");
	dmuci_add_list_value_by_section(listen_sec, "origin", "*");

	dmuci_add_section_bbfdm("dmmap_owsd", "owsd-listen", &dmmap_sec, &v);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(listen_sec));
	*instancepara = update_instance_bbfdm(dmmap_sec, instance, "olisteninstance");

	return 0;
}

static int delete_owsd_listen_instance(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;

	int found = 0;
	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name((struct uci_section *)data))) {
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_owsd", "owsd-listen", "olisteninstance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "olisteninstance", "dmmap_owsd", "owsd-listen");
				dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_owsd", "owsd-listen", section_name((struct uci_section *)data), &dmmap_section);
				if (dmmap_section)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("owsd", "owsd-listen", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_owsd", "listen", section_name(s), &dmmap_section);
					if (dmmap_section)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_owsd", "listen", section_name(ss), &dmmap_section);
				if (dmmap_section)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

/*** DMROOT.X_IOPSYS_EU_OWSD. ***/
DMLEAF X_IOPSYS_EU_OWSDParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"UnixSocket", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_global_sock, set_x_iopsys_eu_owsd_global_sock, NULL, NULL, BBFDM_BOTH},
{"URLRedirect", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_global_redirect, set_x_iopsys_eu_owsd_global_redirect, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ X_IOPSYS_EU_OWSDObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"UbusProxy", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, UbusProxyParams, NULL, BBFDM_BOTH},
{"VirtualHost", &DMWRITE, add_owsd_listen, delete_owsd_listen_instance, NULL, browseXIopsysEuOWSDVirtualHost, NULL, NULL, NULL, NULL, VirtualHostParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF UbusProxyParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_owsd_ubus_proxy_enable, set_x_iopsys_eu_owsd_ubus_proxy_enable, NULL, NULL, BBFDM_BOTH},
{"PeerCertificate", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_ubus_proxy_cert, set_x_iopsys_eu_owsd_ubus_proxy_cert, NULL, NULL, BBFDM_BOTH},
{"PeerKey", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_ubus_proxy_key, set_x_iopsys_eu_owsd_ubus_proxy_key, NULL, NULL, BBFDM_BOTH},
{"PeerCA", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_ubus_proxy_ca, set_x_iopsys_eu_owsd_ubus_proxy_ca, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF VirtualHostParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_virtualhost_alias, set_x_iopsys_eu_owsd_virtualhost_alias, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_virtualhost_interface, set_x_iopsys_eu_owsd_virtualhost_interface, NULL, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_x_iopsys_eu_owsd_virtualhost_port, set_x_iopsys_eu_owsd_virtualhost_port, NULL, NULL, BBFDM_BOTH},
{"IPv6Enable", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_owsd_virtualhost_ipv6_enable, set_x_iopsys_eu_owsd_virtualhost_ipv6_enable, NULL, NULL, BBFDM_BOTH},
{"AllowInterfaceIPAddressAsOrigin", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_owsd_virtualhost_whitelist_interface, set_x_iopsys_eu_owsd_virtualhost_whitelist_interface, NULL, NULL, BBFDM_BOTH},
{"AllowDHCPDomainsAsOrigin", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_owsd_virtualhost_whitelist_dhcp, set_x_iopsys_eu_owsd_virtualhost_whitelist_dhcp, NULL, NULL, BBFDM_BOTH},
{"AllowedOrigins", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_virtualhost_origin, set_x_iopsys_eu_owsd_virtualhost_origin, NULL, NULL, BBFDM_BOTH},
{"Certificate", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_virtualhost_certificate, set_x_iopsys_eu_owsd_virtualhost_certificate, NULL, NULL, BBFDM_BOTH},
{"Key", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_virtualhost_key, set_x_iopsys_eu_owsd_virtualhost_key, NULL, NULL, BBFDM_BOTH},
{"CA", &DMWRITE, DMT_STRING, get_x_iopsys_eu_owsd_virtualhost_ca, set_x_iopsys_eu_owsd_virtualhost_ca, NULL, NULL, BBFDM_BOTH},
{0}
};
