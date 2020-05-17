/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "ethernet.h"

struct eth_port_args
{
	struct uci_section *eth_port_sec;
	char *ifname;
};

/*************************************************************
* INIT
**************************************************************/
static inline int init_eth_port(struct eth_port_args *args, struct uci_section *s, char *ifname)
{
	args->eth_port_sec = s;
	args->ifname = ifname;
	return 0;
}

/*************************************************************
* COMMON Functions
**************************************************************/
static int eth_iface_sysfs(const struct dm_args *args, const char *name, char **value)
{
	char *device;

	dmuci_get_value_by_section_string(args->section, "device", &device);
	return get_net_device_sysfs(device, name, value);
}

static int eth_port_sysfs(const struct eth_port_args *args, const char *name, char **value)
{
	return get_net_device_sysfs(args->ifname, name, value);
}

static int is_device_exist(char *device)
{
	struct uci_section *s = NULL;
	char *dev;

	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {
		dmuci_get_value_by_section_string(s, "device", &dev);
		char *p = strtok(dev, ".");
		if (p != NULL) {
			if (strcmp(p, device) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

static void create_link(char *ifname)
{
	char *macaddr, *v, *device;
	struct uci_section *dmmap = NULL;

	macaddr = get_macaddr(ifname);
	if (macaddr[0] == '\0')
		return;

	device = get_device(ifname);
	if (device[0] == '\0')
		return;

	/* Interfaces might share the same mac address */
	if (is_mac_exist(macaddr))
		return;

	/* For all the Ethernet link objects pointing to same Ethernet Interface,
	 * we can omit creating multiple Ethernet link entries.*/
	char intf[250] = {0};
	strncpy(intf, device, sizeof(intf) - 1);
	char *p = strtok(intf, ".");
	if (p != NULL) {
		if (is_device_exist(p))
			return;
	}

	/* Check if section_name exists or not, if yes then do not add section just update
	 * the params else add section and update the params. */
	struct uci_section *s = NULL;
	char *sec_name;
	int ret = 1;

	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {
		dmuci_get_value_by_section_string(s, "section_name", &sec_name);
		if (strcmp(ifname, sec_name) == 0) {
			dmuci_set_value_by_section(s, "mac", macaddr);
			dmuci_set_value_by_section(s, "device", device);
			dmuci_set_value_by_section(s, "section_name", ifname);
			ret = 0;
			break;
		} else {
			ret = 1;
		}
	}

	if (ret == 1 ) {
		dmuci_add_section_bbfdm(DMMAP, "link", &dmmap, &v);
		dmuci_set_value_by_section(dmmap, "mac", macaddr);
		dmuci_set_value_by_section(dmmap, "device", device);
		dmuci_set_value_by_section(dmmap, "section_name", ifname);
	}
}

static int dmmap_synchronizeEthernetLink(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *ifname, *proto;

	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &proto);

		if (strcmp(section_name(s), "loopback") == 0 || *proto == '\0')
			continue;

		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (*ifname == '\0' || *ifname == '@')
			continue;

		create_link(section_name(s));
	}
	return 0;
}

static char *get_vlan_last_instance_bbfdm(char *package, char *section, char *opt_inst)
{
	struct uci_section *s, *confsect;
	char *inst = NULL, *last_inst = NULL, *type, *sect_name, *name;

	uci_path_foreach_sections(bbfdm, package, section, s) {
		dmuci_get_value_by_section_string(s, "section_name", &sect_name);
		get_config_section_of_dmmap_section("network", "device", sect_name, &confsect);
		dmuci_get_value_by_section_string(confsect, "type", &type);
		dmuci_get_value_by_section_string(confsect, "name", &name);
		if (strcmp(type, "untagged") == 0 || (*name != '\0' && !is_vlan_termination_section(name))) {
			dmuci_set_value_by_section(s, "vlan_term_instance", "");
			continue;
		}
		inst = update_instance_bbfdm(s, last_inst, opt_inst);
		if(last_inst)
			dmfree(last_inst);
		last_inst = dmstrdup(inst);
	}
	return inst;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Ethernet.Interface.{i}.!UCI:ports/ethport/dmmap_ports*/
static int browseEthernetInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *int_num = NULL, *int_num_last = NULL, *ifname;
	struct eth_port_args curr_eth_port_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ports", "ethport", "dmmap_ports", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		init_eth_port(&curr_eth_port_args, p->config_section, ifname);
		int_num =  handle_update_instance(1, dmctx, &int_num_last, update_instance_alias, 3, p->dmmap_section, "eth_port_instance", "eth_port_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_eth_port_args, int_num) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseEthernetLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dm_args args = {0};
	struct uci_section *s = NULL;
	char *id_last = NULL, *id = NULL;

	dmmap_synchronizeEthernetLink(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {
		args.section = s;
		id = handle_update_instance(1, dmctx, &id_last, update_instance_alias_bbfdm, 3, s, "link_instance", "link_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&args, id) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.!UCI:network/device/dmmap_network*/
static int browseEthernetVLANTerminationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *type, *name, *vlan_term = NULL, *vlan_term_last = NULL;
	struct dm_args curr_vlan_term_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "device", "dmmap_network", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "type", &type);
		dmuci_get_value_by_section_string(p->config_section, "name", &name);
		if (strcmp(type, "untagged") == 0 || (*name != '\0' && !is_vlan_termination_section(name)))
			continue;
		curr_vlan_term_args.section = p->config_section;
		vlan_term = handle_update_instance(1, dmctx, &vlan_term_last, update_instance_alias, 3, p->dmmap_section, "vlan_term_instance", "vlan_term_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_vlan_term_args, vlan_term) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
* LINKER
**************************************************************/
static int get_linker_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct eth_port_args *)data)->ifname)
		*linker = ((struct eth_port_args *)data)->ifname;
	else
		*linker = "";
	return 0;
}

static int get_linker_link(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "mac", linker);
	return 0;
}

static int get_linker_vlan_term(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if(data && ((struct dm_args *)data)->section)
		dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "name", linker);
	else
		*linker = "";
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
**************************************************************/
static int addObjEthernetLink(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *v;
	struct uci_section *dmmap_network= NULL;

	inst = get_last_instance_bbfdm(DMMAP, "link", "link_instance");
	dmuci_add_section_bbfdm(DMMAP, "link", &dmmap_network, &v);
	*instance = update_instance_bbfdm(dmmap_network, inst, "link_instance");
	return 0;
}

static int del_ethernet_link_instance(char *sect_name)
{
	char intf_tag[50] = {0};
	struct uci_section  *s = NULL, *intf_s = NULL, *prev_s = NULL, *dev_s = NULL;
	int ret = 0;

	/* Get the upstream interface. */
	get_upstream_interface(intf_tag, sizeof(intf_tag));

	/* Create untagged upstream interface. */
	if (intf_tag[0] != '\0')
		strcat(intf_tag, ".1");

	/* Get section from section_name.*/
	uci_foreach_sections("network", "interface", intf_s) {
		if (strcmp(section_name(intf_s), sect_name) == 0) {
			char *intf;
			dmuci_get_value_by_section_string(intf_s, "ifname", &intf);

			/* If ifname is same as of WAN port then delete the interface
			 * section and the device section.*/
			if (strncmp(intf_tag, intf, sizeof(intf_tag)) == 0) {
				prev_s = intf_s;
				ret = 1;
			} else {
				char *proto;
				dmuci_get_value_by_section_string(intf_s, "proto", &proto);
				dmuci_delete_by_section(intf_s, "proto", proto);
			}
			break;
		}
	}

	if (ret == 1) {
		/* Remove the section from UCI. */
		if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);

		/* Remove the device section from the UCI. */
		uci_foreach_option_eq("network", "device", "name", intf_tag, s) {
			dev_s = s;
			break;
		}
		if (dev_s) dmuci_delete_by_section(dev_s, NULL, NULL);
	}

	/* Remove the Link section from dmmap. */
	struct uci_section *dmmap_section = NULL;
	get_dmmap_section_of_config_section("dmmap", "link", sect_name, &dmmap_section);
	if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);

	return 0;
}

static int delObjEthernetLink(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	char *sect_name = NULL;
	struct uci_section *s = NULL;

	switch (del_action) {
		case DEL_INST:
			/* Deletion of EthernetLink to support L2 VLAN deployments. */
			dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "section_name", &sect_name);
			get_config_section_of_dmmap_section("network", "interface", sect_name, &s);
			if(!s) {
				dmuci_delete_by_section(((struct dm_args *)data)->section, NULL, NULL);
			} else {
				del_ethernet_link_instance(sect_name);
			}
			return 0;
		case DEL_ALL:
			return FAULT_9005;
	}

	return 0;
}

static int addObjEthernetVLANTermination(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *device_name, *val, *v;
	struct uci_section *s = NULL, *dmmap_network = NULL;

	check_create_dmmap_package("dmmap_network");
	inst = get_vlan_last_instance_bbfdm("dmmap_network", "device", "vlan_term_instance");
	dmasprintf(&device_name, "vlan_ter_%d", inst ? atoi(inst)+1 : 1);

	// Add device section
	dmuci_add_section("network", "device", &s, &val);
	dmuci_rename_section_by_section(s, device_name);
	dmuci_set_value_by_section(s, "type", "8021q");

	// Add device section in dmmap_network file
	dmuci_add_section_bbfdm("dmmap_network", "device", &dmmap_network, &v);
	dmuci_set_value_by_section(dmmap_network, "section_name", device_name);
	*instance = update_instance_bbfdm(dmmap_network, inst, "vlan_term_instance");
	return 0;
}

static int delObjEthernetVLANTermination(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section = NULL, *s_dev = NULL, *sdevtmp = NULL;
	char *name, *type;

	switch (del_action) {
	case DEL_INST:
		// Remove device section
		dmuci_delete_by_section(((struct dm_args *)data)->section, NULL, NULL);

		// Remove device section in dmmap_network file
		get_dmmap_section_of_config_section("dmmap_network", "device", section_name(((struct dm_args *)data)->section), &dmmap_section);
		dmuci_delete_by_section(dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections_safe("network", "device", sdevtmp, s_dev) {
			dmuci_get_value_by_section_string(s_dev, "type", &type);
			dmuci_get_value_by_section_string(s_dev, "name", &name);
			if (strcmp(type, "untagged") == 0 || (name && !is_vlan_termination_section(name)))
				continue;

			// Remove device section in dmmap_network file
			get_dmmap_section_of_config_section("dmmap_network", "device", section_name(s_dev), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);

			// Remove device section
			dmuci_delete_by_section(s_dev, NULL, NULL);
		}
		break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.Ethernet.InterfaceNumberOfEntries!UCI:ports/ethport/*/
static int get_Ethernet_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("ports", "ethport", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_Ethernet_LinkNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	dmmap_synchronizeEthernetLink(ctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Ethernet.VLANTerminationNumberOfEntries!UCI:network/device/*/
static int get_Ethernet_VLANTerminationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *type, *name;
	int cnt = 0;

	uci_foreach_sections("network", "device", s) {
		dmuci_get_value_by_section_string(s, "type", &type);
		dmuci_get_value_by_section_string(s, "name", &name);
		if (strcmp(type, "untagged") == 0 || !is_vlan_termination_section(name))
			continue;
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Enable!UCI:ports/ethport,@i-1/enabled*/
static int get_EthernetInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "enabled", value);
	return 0;
}

static int set_EthernetInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "enabled", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Status!SYSFS:/sys/class/net/@Name/operstate*/
static int get_EthernetInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_net_device_sysfs(((struct eth_port_args *)data)->ifname, "operstate", value);
	if (strcmp(*value, "up") == 0)
		*value = "Up";
	else if (strcmp(*value, "down") == 0)
		*value = "Down";
	else
		*value = "Unknown";
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Alias!UCI:dmmap_ports/ethport,@i-1/eth_port_alias*/
static int get_EthernetInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_ports", "ethport", section_name(((struct eth_port_args *)data)->eth_port_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "eth_port_alias", value);
	if ((*value)[0] == '\0') {
		dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "name", value);
		dmuci_set_value_by_section(dmmap_section, "eth_port_alias", *value);
	}
	return 0;
}

static int set_EthernetInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_ports", "ethport", section_name(((struct eth_port_args *)data)->eth_port_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "eth_port_alias", value);
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Name!UCI:ports/ethport,@i-1/ifname*/
static int get_EthernetInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "ifname", value);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_EthernetInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	struct uci_section *s = NULL;
	char *ifname;

	*value ="0";
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (strstr(ifname, ((struct eth_port_args *)data)->ifname)) {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
			DM_ASSERT(res, *value = "0");
			*value = dmjson_get_value(res, 1, "uptime");
			if((*value)[0] == '\0')
				*value = "0";
			break;
		}
	}
	return 0;
}

static int get_EthernetInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_EthernetInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Upstream!UCI:ports/ethport,@i-1/uplink*/
static int get_EthernetInterface_Upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "uplink", value);
	if ((*value)[0] == '\0')
		*value = "0";
	return 0;
}

/*#Device.Ethernet.Interface.{i}.MACAddress!SYSFS:/sys/class/net/@Name/address*/
static int get_EthernetInterface_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "address", value);
}

/*#Device.Ethernet.Interface.{i}.MaxBitRate!UBUS:network.device/status/name,@Name/link-supported*/
static int get_EthernetInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *link_supported = NULL;
	int rate = 0;
	char *max_link, *autoneg;

	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct eth_port_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "-1");
	autoneg = dmjson_get_value(res, 1, "autoneg");
	if (strcmp(autoneg, "true") == 0) {
		*value = "-1";
	} else {
		json_object_object_get_ex(res, "link-supported", &link_supported);
		if (link_supported) {
			max_link = dmjson_get_value_in_array_idx(link_supported, json_object_array_length(link_supported) - 1, 0);
			sscanf(max_link, "%d%*s", &rate);
			dmasprintf(value, "%d", rate);
		}
	}
	return 0;
}

static int set_EthernetInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "-1") == 0)
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "autoneg", "1");
			else {
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "autoneg", "0");
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "speed", value);
			}
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.CurrentBitRate!UBUS:network.device/status/name,@Name/speed*/
static int get_EthernetInterface_CurrentBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	int speed = 0;

	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct eth_port_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "speed");
	sscanf(*value, "%d%*c", &speed);
	dmasprintf(value, "%d", speed);
	return 0;
}

/*#Device.Ethernet.Interface.{i}.DuplexMode!UBUS:network.device/status/name,@Name/speed*/
static int get_EthernetInterface_DuplexMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char mode, *speed, *autoneg;

	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct eth_port_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "Auto");
	autoneg = dmjson_get_value(res, 1, "autoneg");
	if (strcmp(autoneg, "true") == 0) {
		*value = "Auto";
	} else {
		speed = dmjson_get_value(res, 1, "speed");
		sscanf(speed, "%*d%c", &mode);
		*value = (mode == 'F') ? "Full" : "Half";
	}
	return 0;
}

static int set_EthernetInterface_DuplexMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DuplexMode, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Auto") == 0)
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "autoneg", "1");
			else {
				dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "autoneg", "0");
				if (strcmp(value, "Full") == 0)
					dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "duplex", "full");
				else
					dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "duplex", "half");
			}
			return 0;
	}
	return 0;
}

static int get_EthernetInterface_EEECapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*#Device.Ethernet.Interface.{i}.EEEEnable!UCI:ports/ethport,@i-1/eee*/
static int get_EthernetInterface_EEEEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct eth_port_args *)data)->eth_port_sec, "eee", value);
	return 0;
}

static int set_EthernetInterface_EEEEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct eth_port_args *)data)->eth_port_sec, "eee", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.Ethernet.Interface.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_EthernetInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.BytesReceived!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_EthernetInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_EthernetInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_EthernetInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_EthernetInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_EthernetInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/rx_errors", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_EthernetInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_EthernetInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/rx_dropped", value);
}

/*#Device.Ethernet.Interface.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_EthernetInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_port_sysfs(data, "statistics/multicast", value);
}

static int get_EthernetLink_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_EthernetLink_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_EthernetLink_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

static int get_EthernetLink_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "link_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_EthernetLink_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dm_args *)data)->section, "link_alias", value);
			break;
	}
	return 0;
}

static int get_EthernetLink_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "device", value);
	return 0;
}

static int get_EthernetLink_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *interface;

	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "section_name", &interface);
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	if((*value)[0] == '\0')
		*value = "0";
	return 0;
}

static int get_EthernetLink_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *link_mac, *proto, *type, *ifname, *mac;

	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "mac", &link_mac);
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (strcmp(section_name(s), "loopback") == 0 || *proto == '\0')
			continue;

		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (*ifname == '\0' || *ifname == '@')
			continue;

		mac = get_macaddr(section_name(s));
		if (mac[0] == '\0' || strcasecmp(mac, link_mac) != 0)
			continue;

		dmuci_get_value_by_section_string(s, "type", &type);
		if (strcmp(type, "bridge") == 0) {
			struct uci_section *dmmap_section, *port;
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(s), &dmmap_section);
			if (dmmap_section != NULL) {
				char *br_inst, *mg;
				dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &br_inst);
				uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, port) {
					dmuci_get_value_by_section_string(port, "management", &mg);
					if (strcmp(mg, "1") == 0) {
						char *device, linker[512] = "";
						dmuci_get_value_by_section_string(port, "device", &device);
						snprintf(linker, sizeof(linker), "br_%s:%s+%s", br_inst, section_name(port), device);
						adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
						if (*value == NULL)
							*value = "";
						break;
					}
				}
			}
		} else {
			/* For upstream interface, set the lowerlayer to wan port of Ethernet.Interface */
			char intf_tag[50] = {0};

			/* Get the upstream interface. */
			get_upstream_interface(intf_tag, sizeof(intf_tag));

			if (intf_tag[0] != '\0') {
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), intf_tag, value);
				if (*value == NULL)
					*value = "";
			}
		}
		break;
	}
	return 0;
}

static int set_ethlink_lowerlayer_bridge(char *lower_layer, char *instance)
{
	int len = 0, i = 0;
	char new_if[250] = {0}, key[10] = {0};
	struct uci_section *s = NULL, *intf_s = NULL;
	char *sec_name;
	char *p = strstr(lower_layer, "Port");
	if (p) {
		/* Get the bridge_key. */
		len = strlen(p);
		for (i = 0; i < strlen(lower_layer) - len; i++) {
			new_if[i] = lower_layer[i];
		}

		char br_key = new_if[strlen(new_if) - 2];
		snprintf(key, sizeof(key), "%c", br_key);

		/* Find out bridge section name using bridge key. */
		uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "bridge_instance", key, s) {
			dmuci_get_value_by_section_string(s, "section_name", &sec_name);
			break;
		}

		/* Check if section name is present in network UCI wd type as bridge
		 * and ifname not empty, if yes then update
		 * the section with proto 'dhcp' else do nothing. */
		uci_foreach_sections("network", "interface", intf_s) {
			char  sec[20] = {0};
			strncpy(sec, section_name(intf_s), sizeof(sec) - 1);

			if (strncmp(sec, sec_name, sizeof(sec)) == 0) {
				char *type, *ifname;
				dmuci_get_value_by_section_string(intf_s, "type", &type);
				if (*type == '\0' || strcmp(type, "bridge") != 0)
					return -1;

				dmuci_get_value_by_section_string(intf_s, "ifname", &ifname);
				if (*ifname == '\0')
					return -1;

				/* Add ethernet link params to dmmap link section. */
				uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {
					char *inst;
					char link_inst[10] = {0};
					dmuci_get_value_by_section_string(s, "link_instance", &inst);
					strncpy(link_inst, instance, sizeof(link_inst) - 1);

					/* Check if the link instance are same or not. */
					if (strncmp(link_inst, inst, sizeof(link_inst)) == 0) {
						dmuci_set_value_by_section(s, "section_name", section_name(intf_s));
						break;
					}
				}

				/* Set the value of proto to the section. */
				dmuci_set_value_by_section(intf_s, "proto", "dhcp");
			}
		}
	}

	return 0;
}

static int check_set_linker_in_uci(char *intf, char *instance, char *mac_addr)
{
	struct uci_section *s = NULL, *link_s = NULL, *mac_s = NULL, *prev_s = NULL;
	int mac_present = 0;
	uci_foreach_option_eq("network", "interface", "ifname", intf, s) {
		/* Fetch the mac address of the interface. */
		char *macaddr = get_macaddr(section_name(s));

		/* Check if mac is present in dmmap link section. */
		uci_path_foreach_option_eq(bbfdm, DMMAP, "link", "mac", macaddr, mac_s) {
			/* Get the link instance of the section. */
			char *link;
			dmuci_get_value_by_section_string(mac_s, "link_instance", &link);

			/* Check if the link instance are same or not. */
			if (strcmp(link, instance) != 0) {
				/* Delete the new link inst as mac already exists. */
				uci_path_foreach_option_eq(bbfdm, DMMAP, "link", "link_instance", instance, link_s) {
					prev_s = link_s;
				}
				if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
			}
			mac_present = 1;
			break;
		}

		if (mac_present == 1) {
			dmuci_set_value_by_section(s, "proto", "dhcp");
			return 1;
		} else {
			/* Add section name and mac in dmmap link section if
			 * link instances are same. */
			uci_path_foreach_sections(bbfdm, DMMAP, "link", link_s) {
				char *inst;
				char link_inst[10] = {0};
				dmuci_get_value_by_section_string(link_s, "link_instance", &inst);
				strncpy(link_inst, instance, sizeof(link_inst) - 1);

				/* Check if the link instance are same or not. */
				if (strncmp(link_inst, inst, sizeof(link_inst)) == 0) {
					dmuci_set_value_by_section(link_s, "section_name", section_name(s));
					dmuci_set_value_by_section(link_s, "mac", mac_addr);
					break;
				}
			}
			dmuci_set_value_by_section(s, "proto", "dhcp");
			return 1;
		}
	}
	return 0;
}

static int set_lowerlayer_in_uci(char *mac_addr, char *instance, char *intf, char *linker)
{
	int val_present = 0;
	char *val;
	struct uci_section *s = NULL, *link_s = NULL, *mac_s = NULL, *prev_s = NULL;

	dmuci_add_section_and_rename("network", "interface", &s, &val);

	/* Check if mac is present in dmmap link section. */
	uci_path_foreach_option_eq(bbfdm, DMMAP, "link", "mac", mac_addr, mac_s) {
		/* Get the link instance of the section. */
		char *link;
		dmuci_get_value_by_section_string(mac_s, "link_instance", &link);

		/* Check if the link instance are same or not. */
		if (strcmp(link, instance) != 0) {
			/* Delete the new link inst as mac already exists. */
			uci_path_foreach_option_eq(bbfdm, DMMAP, "link", "link_instance", instance, link_s) {
				prev_s = link_s;
			}
			if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
		}
		val_present = 1;
		break;
	}

	if (val_present == 0) {
		/* Add ethernet link params to dmmap link section. */
		uci_path_foreach_sections(bbfdm, DMMAP, "link", link_s) {
			char *inst;
			char link_inst[10] = {0};
			dmuci_get_value_by_section_string(link_s, "link_instance", &inst);
			strncpy(link_inst, instance, sizeof(link_inst) - 1);

			/* Check if the link instance are same or not. */
			if (strncmp(link_inst, inst, sizeof(link_inst)) == 0) {
				dmuci_set_value_by_section(link_s, "section_name", section_name(s));
				dmuci_set_value_by_section(link_s, "mac", mac_addr);
				break;
			}
		}
	}

	dmuci_set_value_by_section(s, "proto", "dhcp");
	dmuci_set_value_by_section(s, "ifname", intf);

	/* Add config device section. */
	struct uci_section *dev_s;
	dmuci_add_section_and_rename("network", "device", &dev_s, &val);
	dmuci_set_value_by_section(dev_s, "type", "untagged");
	char *tok = strtok(linker, ".");
	dmuci_set_value_by_section(dev_s, "ifname", tok);
	dmuci_set_value_by_section(dev_s, "name", intf);
	dmuci_set_value_by_section(dev_s, "macaddr", mac_addr);

	return 0;
}

static int set_ethlink_lowerlayer_eth_intf(char *lower_layer, char *instance, char *linker)
{

	/* Get the upstream interface. */
	char intf_tag[50] = {0};

	/* Get the upstream interface. */
	get_upstream_interface(intf_tag, sizeof(intf_tag));

	/* Fetch the macaddress of upstream interface. */
	char *mac = get_macaddr_from_device(intf_tag);

	/* Create a mac address for the tagged upstream interfaces
	 * using the base mac address. */
	char mac_addr[25] = {0};
	create_mac_addr_upstream_intf(mac_addr, mac, sizeof(mac_addr));

	/* Create untagged upstream interface. */
	if (intf_tag[0] != '\0')
		strcat(intf_tag, ".1");

	char intf[20] = {0};
	if (strcmp(linker, intf_tag) == 0)
		strncpy(intf, linker, sizeof(intf) - 1);
	else {
		snprintf(intf, sizeof(intf), "%s.%s", linker, "1");
		if (strcmp(intf, intf_tag) != 0)
			return -1;
	}

	/* Check if linker is present in network UCI, if yes the update
	 * the proto, else create a interface and device section. */
	int ret = check_set_linker_in_uci(intf, instance, mac_addr);

	/* Linker is not present in the UCI. */
	if (ret == 0) {
		set_lowerlayer_in_uci(mac_addr, instance, intf, linker);
	}

	return 0;
}

static int set_EthernetLink_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer[250] = {0};

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (value[strlen(value)-1] != '.')
				snprintf(lower_layer, sizeof(lower_layer), "%s.", value);
			else
				strncpy(lower_layer, value, sizeof(lower_layer) - 1);

			/* Check if the value is valid or not. */
			if (strncmp(lower_layer, "Device.Bridging.Bridge.", 23) == 0) {
				set_ethlink_lowerlayer_bridge(lower_layer, instance);
			} else if (strncmp(lower_layer, "Device.Ethernet.Interface.", 26) == 0) {
				/* Find the linker of the lowerlayer value to be set. */
				char *linker;
				adm_entry_get_linker_value(ctx, lower_layer, &linker);
				set_ethlink_lowerlayer_eth_intf(lower_layer, instance, linker);
			}
			break;
	}
	return 0;
}

static int get_EthernetLink_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "mac", value);
	return 0;
}

static int get_EthernetLinkStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_bytes", value);
}

static int get_EthernetLinkStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_bytes", value);
}

static int get_EthernetLinkStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_packets", value);
}

static int get_EthernetLinkStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_packets", value);
}

static int get_EthernetLinkStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_errors", value);
}

static int get_EthernetLinkStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_errors", value);
}

static int get_EthernetLinkStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_dropped", value);
}

static int get_EthernetLinkStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_dropped", value);
}

static int get_EthernetLinkStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/multicast", value);
}

static int get_EthernetVLANTermination_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_EthernetVLANTermination_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_EthernetVLANTermination_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.Alias!UCI:dmmap_network/device,@i-1/vlan_term_alias*/
static int get_EthernetVLANTermination_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "device", section_name(((struct dm_args *)data)->section), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "vlan_term_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_EthernetVLANTermination_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "device", section_name(((struct dm_args *)data)->section), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "vlan_term_alias", value);
			return 0;
	}
	return 0;
}

static int get_EthernetVLANTermination_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name(((struct dm_args *)data)->section));
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_EthernetVLANTermination_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	struct uci_section *s = NULL;
	char *devname;

	*value = "0";
	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "name", &devname);
	uci_foreach_option_eq("network", "interface", "ifname", devname, s) {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
		DM_ASSERT(res, *value = "0");
		*value = dmjson_get_value(res, 1, "uptime");
		if((*value)[0] == '\0')
			*value = "0";
		break;
	}
	return 0;
}

static int get_EthernetVLANTermination_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *macaddr, *devname, *linker = "";

	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "name", &devname);
	if (*devname != '\0') {
		macaddr = get_macaddr_from_device(devname);
		if (macaddr[0] != '\0' && is_mac_exist(macaddr))
			linker = macaddr;
		else {
			char intf_tag[64] = {0};
			get_upstream_interface(intf_tag, sizeof(intf_tag));
			if (intf_tag[0] != '\0') {
				strcat(intf_tag, ".1");
				linker = get_macaddr_from_device(intf_tag);
			}
		}

		if (linker[0] != '\0') {
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
			if (*value == NULL)
				*value = "";
		}
	}
	return 0;
}

static int set_EthernetVLANTermination_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer[256] = {0};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (value[strlen(value)-1] != '.')
				snprintf(lower_layer, sizeof(lower_layer), "%s.", value);
			else
				strncpy(lower_layer, value, sizeof(lower_layer) - 1);

			if (strncmp(lower_layer, "Device.Ethernet.Link.", 21) == 0) {
				char new_name[16] = {0}, *linker = NULL, *device, *vid, *curr_name;

				adm_entry_get_linker_value(ctx, lower_layer, &linker);
				if (linker == NULL || *linker == '\0')
					return -1;

				struct uci_section *dmmap_s = NULL;
				get_dmmap_section_of_config_section_eq("dmmap", "link", "mac", linker, &dmmap_s);
				dmuci_get_value_by_section_string(dmmap_s, "device", &device);
				dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "name", &curr_name);

				if (*device != '\0') {
					char *p = strtok(device, ".");
					dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "vid", &vid);
					if (*vid != '\0')
						snprintf(new_name, sizeof(new_name), "%s.%s", (p)?p:device, vid);
					else
						snprintf(new_name, sizeof(new_name), "%s", (p)?p:device);

					dmuci_set_value_by_section(((struct dm_args *)data)->section, "ifname", (p)?p:device);
					dmuci_set_value_by_section(((struct dm_args *)data)->section, "name", new_name);
				}

				if (*curr_name != '\0') {
					// Update interface section corresponding to this device if it exists
					struct uci_section *s = NULL;
					uci_foreach_option_eq("network", "interface", "ifname", curr_name, s) {
						dmuci_set_value_by_section(s, "ifname", new_name);
					}
				}
			}
			break;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.VLANID!UCI:network/device,@i-1/vid*/
static int get_EthernetVLANTermination_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "vid", value);
	return 0;
}

static int set_EthernetVLANTermination_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *ifname, *name, *curr_ifname;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "ifname", &ifname);
			if (*ifname != '\0') {
				dmasprintf(&name, "%s.%s", ifname, value);

				// set ifname option of the corresponding interface section
				dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "name", &curr_ifname);
				uci_foreach_option_eq("network", "interface", "ifname", curr_ifname, s) {
					dmuci_set_value_by_section(s, "ifname", name);
				}

				// set name option of the device section
				dmuci_set_value_by_section(((struct dm_args *)data)->section, "name", name);
				dmfree(name);
			}

			// set vid option of the device section
			dmuci_set_value_by_section(((struct dm_args *)data)->section, "vid", value);
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.TPID!UCI:network/device,@i-1/type*/
static int get_EthernetVLANTermination_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dm_args *)data)->section, "type", value);
	if (strcmp(*value, "8021q") == 0)
		*value = "33024";
	else if (strcmp(*value, "8021ad") == 0)
		*value = "34984";
	else
		*value = "37120";
	return 0;
}

static int set_EthernetVLANTermination_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "33024") == 0)
				dmuci_set_value_by_section(((struct dm_args *)data)->section, "type", "8021q");
			else if (strcmp(value, "34984") == 0)
				dmuci_set_value_by_section(((struct dm_args *)data)->section, "type", "8021ad");
			return 0;
	}
	return 0;
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.BytesSent!SYSFS:/sys/class/net/@Name/statistics/tx_bytes*/
static int get_EthernetVLANTerminationStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.BytesReceived!SYSFS:/sys/class/net/@Name/statistics/rx_bytes*/
static int get_EthernetVLANTerminationStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.PacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_packets*/
static int get_EthernetVLANTerminationStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.PacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_packets*/
static int get_EthernetVLANTerminationStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.ErrorsSent!SYSFS:/sys/class/net/@Name/statistics/tx_errors*/
static int get_EthernetVLANTerminationStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.ErrorsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_errors*/
static int get_EthernetVLANTerminationStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_errors", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.DiscardPacketsSent!SYSFS:/sys/class/net/@Name/statistics/tx_dropped*/
static int get_EthernetVLANTerminationStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.DiscardPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/rx_dropped*/
static int get_EthernetVLANTerminationStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/rx_dropped", value);
}

/*#Device.Ethernet.VLANTermination.{i}.Stats.MulticastPacketsReceived!SYSFS:/sys/class/net/@Name/statistics/multicast*/
static int get_EthernetVLANTerminationStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return eth_iface_sysfs(data, "statistics/multicast", value);
}

/* *** Device.Ethernet. *** */
DMOBJ tEthernetObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseEthernetInterfaceInst, NULL, NULL, NULL, tEthernetInterfaceObj, tEthernetInterfaceParams, get_linker_interface, BBFDM_BOTH},
{"Link", &DMWRITE, addObjEthernetLink, delObjEthernetLink, NULL, browseEthernetLinkInst, NULL, NULL, NULL, tEthernetLinkObj, tEthernetLinkParams, get_linker_link, BBFDM_BOTH},
{"VLANTermination", &DMWRITE, addObjEthernetVLANTermination, delObjEthernetVLANTermination, NULL, browseEthernetVLANTerminationInst, NULL, NULL, NULL, tEthernetVLANTerminationObj, tEthernetVLANTerminationParams, get_linker_vlan_term, BBFDM_BOTH},
{0}
};

DMLEAF tEthernetParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_InterfaceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"LinkNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_LinkNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"VLANTerminationNumberOfEntries", &DMREAD, DMT_UNINT, get_Ethernet_VLANTerminationNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Interface.{i}. *** */
DMOBJ tEthernetInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetInterfaceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tEthernetInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetInterface_Enable, set_EthernetInterface_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetInterface_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetInterface_Alias, set_EthernetInterface_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetInterface_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetInterface_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetInterface_LowerLayers, set_EthernetInterface_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"Upstream", &DMREAD, DMT_BOOL, get_EthernetInterface_Upstream, NULL, NULL, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_EthernetInterface_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxBitRate", &DMWRITE, DMT_INT, get_EthernetInterface_MaxBitRate, set_EthernetInterface_MaxBitRate, NULL, NULL, BBFDM_BOTH},
{"CurrentBitRate", &DMREAD, DMT_UNINT, get_EthernetInterface_CurrentBitRate, NULL, NULL, NULL, BBFDM_BOTH},
{"DuplexMode", &DMWRITE, DMT_STRING, get_EthernetInterface_DuplexMode, set_EthernetInterface_DuplexMode, NULL, NULL, BBFDM_BOTH},
{"EEECapability", &DMREAD, DMT_BOOL, get_EthernetInterface_EEECapability, NULL, NULL, NULL, BBFDM_BOTH},
{"EEEEnable", &DMWRITE, DMT_BOOL, get_EthernetInterface_EEEEnable, set_EthernetInterface_EEEEnable, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Interface.{i}.Stats. *** */
DMLEAF tEthernetInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetInterfaceStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetInterfaceStats_UnknownProtoPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Link.{i}. *** */
DMOBJ tEthernetLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetLinkStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tEthernetLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetLink_Enable, set_EthernetLink_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetLink_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetLink_Alias, set_EthernetLink_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetLink_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetLink_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetLink_LowerLayers, set_EthernetLink_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_EthernetLink_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.Link.{i}.Stats. *** */
DMLEAF tEthernetLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetLinkStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetLinkStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetLinkStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetLinkStats_UnknownProtoPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.VLANTermination.{i}. *** */
DMOBJ tEthernetVLANTerminationObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetVLANTerminationStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tEthernetVLANTerminationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_EthernetVLANTermination_Enable, set_EthernetVLANTermination_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_EthernetVLANTermination_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_EthernetVLANTermination_Alias, set_EthernetVLANTermination_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_EthernetVLANTermination_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_EthernetVLANTermination_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_EthernetVLANTermination_LowerLayers, set_EthernetVLANTermination_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_UNINT, get_EthernetVLANTermination_VLANID, set_EthernetVLANTermination_VLANID, NULL, NULL, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_EthernetVLANTermination_TPID, set_EthernetVLANTermination_TPID, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Ethernet.VLANTermination.{i}.Stats. *** */
DMLEAF tEthernetVLANTerminationStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_EthernetVLANTerminationStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_EthernetVLANTerminationStats_UnknownProtoPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
