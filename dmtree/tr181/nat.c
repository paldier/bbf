/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "nat.h"


/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_NAT_InterfaceSetting(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value, *v, *inst, name[16];
	struct uci_section *s = NULL, *dmmap_firewall = NULL;

	check_create_dmmap_package("dmmap_firewall");
	inst = get_last_instance_bbfdm("dmmap_firewall", "zone", "interface_setting_instance");
	snprintf(name, sizeof(name), "iface_set_%d", inst ? (atoi(inst)+1) : 1);
	dmuci_add_section_and_rename("firewall", "zone", &s, &value);
	dmuci_set_value_by_section(s, "input", "REJECT");
	dmuci_set_value_by_section(s, "output", "ACCEPT");
	dmuci_set_value_by_section(s, "forward", "REJECT");
	dmuci_set_value_by_section(s, "name", name);

	dmuci_add_section_bbfdm("dmmap_firewall", "zone", &dmmap_firewall, &v);
	dmuci_set_value_by_section(dmmap_firewall, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_firewall, inst, "interface_setting_instance");
	return 0;

}

static int delete_NAT_InterfaceSetting(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_firewall = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_firewall", "zone", section_name((struct uci_section *)data), &dmmap_firewall);
			if (dmmap_firewall)
				dmuci_delete_by_section(dmmap_firewall, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("firewall", "zone", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_firewall", "zone", section_name(ss), &dmmap_firewall);
					if (dmmap_firewall)
						dmuci_delete_by_section(dmmap_firewall, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_firewall", "zone", section_name(ss), &dmmap_firewall);
				if(dmmap_firewall)
					dmuci_delete_by_section(dmmap_firewall, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

static int add_NAT_PortMapping(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value, *v, *inst, name[16];
	struct uci_section *s = NULL, *dmmap_firewall = NULL;

	check_create_dmmap_package("dmmap_firewall");
	inst = get_last_instance_bbfdm("dmmap_firewall", "redirect", "port_mapping_instance");
	snprintf(name, sizeof(name), "port_map_%d", inst ? (atoi(inst)+1) : 1);
	dmuci_add_section_and_rename("firewall", "redirect", &s, &value);
	dmuci_set_value_by_section(s, "name", name);
	dmuci_set_value_by_section(s, "src", "wan");
	dmuci_set_value_by_section(s, "target", "DNAT");
	dmuci_set_value_by_section(s, "dest", "lan");

	dmuci_add_section_bbfdm("dmmap_firewall", "redirect", &dmmap_firewall, &v);
	dmuci_set_value_by_section(dmmap_firewall, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_firewall, inst, "port_mapping_instance");
	return 0;

}

static int delete_NAT_PortMapping(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_firewall = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_firewall", "redirect", section_name((struct uci_section *)data), &dmmap_firewall);
			if (dmmap_firewall)
				dmuci_delete_by_section(dmmap_firewall, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("firewall", "redirect", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_firewall", "redirect", section_name(ss), &dmmap_firewall);
					if (dmmap_firewall)
						dmuci_delete_by_section(dmmap_firewall, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_firewall", "redirect", section_name(ss), &dmmap_firewall);
				if (dmmap_firewall)
					dmuci_delete_by_section(dmmap_firewall, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.NAT.InterfaceSettingNumberOfEntries!UCI:firewall/zone/*/
static int get_nat_interface_setting_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("firewall", "zone", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.NAT.PortMappingNumberOfEntries!UCI:firewall/redirect/*/
static int get_nat_port_mapping_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("firewall", "redirect", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.NAT.InterfaceSetting.{i}.Enable!UCI:firewall/zone,@i-1/masq*/
static int get_nat_interface_setting_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "masq", &val);
	*value = (*val == '1') ? "1" : "0";
	return 0;
}

static int set_nat_interface_setting_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "masq", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.NAT.InterfaceSetting.{i}.Status!UCI:firewall/zone,@i-1/masq*/
static int get_nat_interface_setting_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "masq", &val);
	*value = (*val == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_nat_interface_setting_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_firewall", "zone", section_name((struct uci_section *)data), &dmmap_section);
	if (dmmap_section)
		dmuci_get_value_by_section_string(dmmap_section, "interface_setting_alias", value);
	return 0;
}

static int set_nat_interface_setting_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_firewall", "zone", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(dmmap_section, "interface_setting_alias", value);
			return 0;
	}
	return 0;
}

static int get_nat_interface_setting_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *v;
	struct uci_element *e;
	char *ifaceobj, buf[256] = "";

	*value = "";
	dmuci_get_value_by_section_list((struct uci_section *)data, "network", &v);
	if (v == NULL)
		return 0;
	uci_foreach_element(v, e) {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), e->name, &ifaceobj); // MEM WILL BE FREED IN DMMEMCLEAN
		if (ifaceobj == NULL)
			continue;
		if (*buf != '\0')
			strcat(buf, ",");
		strcat(buf, ifaceobj);
	}
	*value = dmstrdup(buf);
	return 0;
}

static int set_nat_interface_setting_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *iface, *pch, *pchr, buf[256] = "";

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			strcpy(buf, value);
			dmuci_set_value_by_section((struct uci_section *)data, "network", "");
			for(pch = strtok_r(buf, ",", &pchr); pch != NULL; pch = strtok_r(NULL, ",", &pchr)) {
				adm_entry_get_linker_value(ctx, pch, &iface);
				if (iface) {
					dmuci_add_list_value_by_section((struct uci_section *)data, "network", iface);
					dmfree(iface);
				}
			}
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Enable!UCI:firewall/redirect,@i-1/enabled*/
static int get_nat_port_mapping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &val);
	*value = (*val == '1') ? "1" : "0";
	return 0;
}

static int set_nat_port_mapping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Status!UCI:firewall/redirect,@i-1/enabled*/
static int get_nat_port_mapping_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &val);
	*value = (*val == '1') ? "Enabled" : "Disabled";
	return 0;
}

static int get_nat_port_mapping_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_firewall", "redirect", section_name((struct uci_section *)data), &dmmap_section);
	if (dmmap_section)
		dmuci_get_value_by_section_string(dmmap_section, "port_mapping_alias", value);
	return 0;
}

static int set_nat_port_mapping_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_firewall", "redirect", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(dmmap_section, "port_mapping_alias", value);
			return 0;
	}
	return 0;
}

static int get_nat_port_mapping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	struct uci_list *v;
	struct uci_element *e;
	char *zone, *name, *ifaceobj, buf[256] = "";

	dmuci_get_value_by_section_string((struct uci_section *)data, "src", &zone);
	uci_foreach_sections("firewall", "zone", s) {
		dmuci_get_value_by_section_string(s, "name", &name);
		if (strcmp(zone, name) == 0) {
			dmuci_get_value_by_section_list(s, "network", &v);
			break;
		}
	}
	if (v == NULL)
		return 0;
	uci_foreach_element(v, e) {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), e->name, &ifaceobj); // MEM WILL BE FREED IN DMMEMCLEAN
		if (ifaceobj == NULL)
			continue;
		if (*buf != '\0')
			strcat(buf, ",");
		strcat(buf, ifaceobj);
	}
	*value = dmstrdup(buf);
	return 0;
}

static int set_nat_port_mapping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *iface, *network, *zone;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &iface);
			if (iface[0] != '\0') {
				uci_foreach_sections("firewall", "zone", s) {
					dmuci_get_value_by_section_string(s, "network", &network);
					if (is_strword_in_optionvalue(network, iface)) {
						dmuci_get_value_by_section_string(s, "name", &zone);
						dmuci_set_value_by_section((struct uci_section *)data, "src", zone);
						break;
					}
				}
			}
			break;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.RemoteHost!UCI:firewall/redirect,@i-1/src_dip*/
static int get_nat_port_mapping_remote_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "src_dip", value);
	return 0;
}

static int set_nat_port_mapping_remote_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "src_dip", value);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.ExternalPort!UCI:firewall/redirect,@i-1/src_dport*/
static int get_nat_port_mapping_external_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dport, *tmp;
	dmuci_get_value_by_section_string((struct uci_section *)data, "src_dport", &dport);
	if (*dport == '\0') {
		*value = "0";
		return 0;
	}
	tmp = strchr(dport, ':');
	if (tmp)
		*tmp = '\0';
	*value = dport;
	return 0;
}

static int set_nat_port_mapping_external_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dport, buffer[64];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, "0", "65535"))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "src_dport", &dport);
			dport = strchr(dport, ':');
			if (dport == NULL)
				snprintf(buffer, sizeof(buffer), "%s", value);
			else
				snprintf(buffer, sizeof(buffer), "%s%s", value, dport);
			dmuci_set_value_by_section((struct uci_section *)data, "src_dport", buffer);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.ExternalPortEndRange!UCI:firewall/redirect,@i-1/src_dport*/
static int get_nat_port_mapping_external_port_end_range(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dport, *tmp;
	dmuci_get_value_by_section_string((struct uci_section *)data, "src_dport", &dport);
	tmp = strchr(dport, ':');
	*value = (tmp) ? tmp+1 : "0";
	return 0;
}

static int set_nat_port_mapping_external_port_end_range(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dport, *tmp, buffer[64];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, "0", "65535"))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "src_dport", &dport);
			tmp = strchr(dport, ':');
			if (tmp)
				*tmp = '\0';
			if (*value == '0')
				snprintf(buffer, sizeof(buffer), "%s", dport);
			else
				snprintf(buffer, sizeof(buffer), "%s:%s", dport, value);
			dmuci_set_value_by_section((struct uci_section *)data, "src_dport", buffer);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.InternalPort!UCI:firewall/redirect,@i-1/dest_port*/
static int get_nat_port_mapping_internal_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dest_port", value);
	return 0;
}

static int set_nat_port_mapping_internal_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, "0", "65535"))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dest_port", value);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Protocol!UCI:firewall/redirect,@i-1/proto*/
static int get_nat_port_mapping_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto;
	dmuci_get_value_by_section_string((struct uci_section *)data, "proto", &proto);
	if (strcmp(proto, "tcp") == 0)
		*value = "TCP";
	else if (strcmp(proto, "udp") == 0)
		*value = "UDP";
	else
		*value = "TCP/UDP";
	return 0;
}

static int set_nat_port_mapping_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, NATProtocol, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcasecmp("TCP", value) == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "proto", "tcp");
			else if (strcasecmp("UDP", value) == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "proto", "udp");
			else
				dmuci_set_value_by_section((struct uci_section *)data, "proto", "tcpudp");
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.InternalClient!UCI:firewall/redirect,@i-1/dest_ip*/
static int get_nat_port_mapping_internal_client(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dest_ip", value);
	return 0;
}

static int set_nat_port_mapping_internal_client(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dest_ip", value);
			return 0;
	}
	return 0;
}

/*#Device.NAT.PortMapping.{i}.Description!UCI:firewall/redirect,@i-1/name*/
static int get_nat_port_mapping_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

static int set_nat_port_mapping_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "name", value);
			return 0;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.NAT.InterfaceSetting.{i}.!UCI:firewall/zone/dmmap_firewall*/
static int browseInterfaceSettingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *nati, *nati_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("firewall", "zone", "dmmap_firewall", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		nati =  handle_update_instance(1, dmctx, &nati_last, update_instance_alias, 3, p->dmmap_section, "interface_setting_instance", "interface_setting_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, nati) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.NAT.PortMapping.{i}.!UCI:firewall/redirect/dmmap_firewall*/
static int browsePortMappingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *natp, *natp_last = NULL, *target;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("firewall", "redirect", "dmmap_firewall", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "target", &target);
		if (*target != '\0' && strcmp(target, "DNAT") != 0)
			continue;
		natp =  handle_update_instance(1, dmctx, &natp_last, update_instance_alias, 3, p->dmmap_section, "port_mapping_instance", "port_mapping_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, natp) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/* *** Device.NAT. *** */
DMOBJ tNATObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"InterfaceSetting", &DMWRITE, add_NAT_InterfaceSetting, delete_NAT_InterfaceSetting, NULL, browseInterfaceSettingInst, NULL, NULL, NULL, NULL, tNATInterfaceSettingParams, NULL, BBFDM_BOTH},
{"PortMapping", &DMWRITE, add_NAT_PortMapping, delete_NAT_PortMapping, NULL, browsePortMappingInst, NULL, NULL, NULL, NULL, tNATPortMappingParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tNATParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceSettingNumberOfEntries", &DMREAD, DMT_UNINT, get_nat_interface_setting_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"PortMappingNumberOfEntries", &DMREAD, DMT_UNINT, get_nat_port_mapping_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.NAT.InterfaceSetting.{i}. *** */
DMLEAF tNATInterfaceSettingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_nat_interface_setting_enable, set_nat_interface_setting_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMWRITE, DMT_STRING, get_nat_interface_setting_status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_nat_interface_setting_alias, set_nat_interface_setting_alias, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_nat_interface_setting_interface, set_nat_interface_setting_interface, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.NAT.PortMapping.{i}. *** */
DMLEAF tNATPortMappingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_nat_port_mapping_enable, set_nat_port_mapping_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMWRITE, DMT_STRING, get_nat_port_mapping_status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_nat_port_mapping_alias, set_nat_port_mapping_alias, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_nat_port_mapping_interface, set_nat_port_mapping_interface, NULL, NULL, BBFDM_BOTH},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_nat_port_mapping_all_interface, set_nat_port_mapping_all_interface, NULL, NULL, BBFDM_BOTH},
//{"LeaseDuration", &DMWRITE, DMT_UNINT, get_nat_port_mapping_lease_duration, set_nat_port_mapping_lease_duration, NULL, NULL, BBFDM_BOTH},
{"RemoteHost", &DMWRITE, DMT_STRING, get_nat_port_mapping_remote_host, set_nat_port_mapping_remote_host, NULL, NULL, BBFDM_BOTH},
{"ExternalPort", &DMWRITE, DMT_UNINT, get_nat_port_mapping_external_port, set_nat_port_mapping_external_port, NULL, NULL, BBFDM_BOTH},
{"ExternalPortEndRange", &DMWRITE, DMT_UNINT, get_nat_port_mapping_external_port_end_range, set_nat_port_mapping_external_port_end_range, NULL, NULL, BBFDM_BOTH},
{"InternalPort", &DMWRITE, DMT_UNINT, get_nat_port_mapping_internal_port, set_nat_port_mapping_internal_port, NULL, NULL, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_STRING, get_nat_port_mapping_protocol, set_nat_port_mapping_protocol, NULL, NULL, BBFDM_BOTH},
{"InternalClient", &DMWRITE, DMT_STRING, get_nat_port_mapping_internal_client, set_nat_port_mapping_internal_client, NULL, NULL, BBFDM_BOTH},
{"Description", &DMWRITE, DMT_STRING, get_nat_port_mapping_description, set_nat_port_mapping_description, NULL, NULL, BBFDM_BOTH},
{0}
};
