/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "bridging.h"

struct bridge_args
{
	struct uci_section *bridge_sec;
	char *br_key;
	char *ifname;
	char *br_inst;
};

struct bridge_port_args
{
	struct uci_section *bridge_port_sec;
	struct uci_section *bridge_sec;
	char *ifname;
	char *br_inst;
};

struct bridge_vlanport_args
{
	struct uci_section *bridge_vlanport_sec;
	struct uci_section *bridge_sec;
	char *vlan_port;
	char *br_inst;
};

struct bridge_vlan_args
{
	struct uci_section *bridge_vlan_sec;
	struct uci_section *bridge_sec;
	char *vlan_inst;
	char *br_inst;
};

/**************************************************************************
* LINKER FUNCTIONS
***************************************************************************/
static int get_linker_br_port(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct bridge_port_args *)data)->bridge_port_sec)
		dmasprintf(linker, "br_%s:%s+%s", ((struct bridge_port_args *)data)->br_inst, section_name(((struct bridge_port_args *)data)->bridge_port_sec), ((struct bridge_port_args *)data)->ifname);
	else
		*linker = "";
	return 0;
}

static int get_linker_br_vlan(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data&& ((struct bridge_vlan_args *)data)->bridge_vlan_sec) {
		char *vid;
		dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &vid);
		dmasprintf(linker, "br_%s:vlan_%s", ((struct bridge_vlan_args *)data)->br_inst, vid);
	} else
		*linker = "";
	return 0;
}

/**************************************************************************
* INIT FUNCTIONS
***************************************************************************/
static inline int init_bridging_args(struct bridge_args *args, struct uci_section *s, char *last_instance, char *ifname, char *br_instance)
{
	args->bridge_sec = s;
	args->br_key = last_instance;
	args->ifname = ifname;
	args->br_inst = br_instance;
	return 0;
}

static inline int init_bridge_port_args(struct bridge_port_args *args, struct uci_section *s, struct uci_section *bs, char *ifname, char *br_inst)
{
	args->bridge_port_sec = s;
	args->bridge_sec = bs;
	args->ifname = ifname;
	args->br_inst = br_inst;
	return 0;
}

static inline int init_bridge_vlanport_args(struct bridge_vlanport_args *args, struct uci_section *s, struct uci_section *bs, char *vlan_port, char *br_inst)
{
	args->bridge_vlanport_sec = s;
	args->bridge_sec = bs;
	args->vlan_port = vlan_port;
	args->br_inst = br_inst;
	return 0;
}

static inline int init_bridge_vlan_args(struct bridge_vlan_args *args, struct uci_section *s, struct uci_section *bs, char *vlan_inst, char *br_inst)
{
	args->bridge_vlan_sec = s;
	args->bridge_sec = bs;
	args->vlan_inst = vlan_inst;
	args->br_inst = br_inst;
	return 0;
}

/**************************************************************************
* COMMON FUNCTIONS
***************************************************************************/
static int check_port_with_ifname(char *ifname, struct uci_section **ss)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("ports", "ethport", "ifname", ifname, s) {
		*ss = s;
		return 0;
	}

	uci_foreach_option_eq("wireless", "wifi-iface", "ifname", ifname, s) {
		*ss = s;
		return 0;
	}

	uci_foreach_option_eq("network", "device", "name", ifname, s) {
		*ss = s;
		return 0;
	}

	return 0;
}

static int get_last_inst(char *config, char *section, char *option1, char *option2, char *br_inst)
{
	struct uci_section *s = NULL;
	int instance, max = 0;
	char *tmp;

	uci_path_foreach_option_eq(bbfdm, config, section, option1, br_inst, s) {
		dmuci_get_value_by_section_string(s, option2, &tmp);
		if (tmp[0] == '\0')
			continue;
		instance = atoi(tmp);
		if (instance > max) max = instance;
	}
	return max;
}

static int check_ifname_exist_in_br_ifname_list(char *ifname, char *s_name)
{
	char *br_ifname_list, *pch, *spch;
	struct uci_section *s;

	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		if (strcmp(section_name(s), s_name) != 0)
			continue;

		dmuci_get_value_by_section_string(s, "ifname", &br_ifname_list);
		if (br_ifname_list[0] == '\0')
			return 0;

		for (pch = strtok_r(br_ifname_list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			if (strncmp(ifname, pch, 4) == 0) {
				return 1;
			}
		}
	}
	return 0;
}

static int remove_bridge_sections(char *config, char *section, char *option, char *br_inst)
{
	struct uci_section *s = NULL, *prev_s = NULL;

	uci_path_foreach_option_eq(bbfdm, config, section, option, br_inst, s) {
		if (prev_s)
			dmuci_delete_by_section(prev_s, NULL, NULL);
		prev_s = s;
	}
	if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
	return 0;
}

static int update_bridge_ifname(struct uci_section *br_sec, struct uci_section *sec, int status)
{
	char ifname_dup[128], *ptr, *baseifname, *ifname, *start, *end;
	int pos = 0;

	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	dmuci_get_value_by_section_string(sec, "name", &baseifname);
	ptr = ifname_dup;
	dmstrappendstr(ptr, ifname);
	dmstrappendend(ptr);

	if (status) {
		if (is_strword_in_optionvalue(ifname_dup, baseifname)) return 0;
		if (ifname_dup[0] != '\0') dmstrappendchr(ptr, ' ');
		dmstrappendstr(ptr, baseifname);
		dmstrappendend(ptr);
	} else {
		if (is_strword_in_optionvalue(ifname_dup, baseifname)) {
			start = strstr(ifname_dup, baseifname);
			end = start + strlen(baseifname);
			if (start != ifname_dup) {
				start--;
				pos=1;
			}
			memmove(start, start + strlen(baseifname)+pos, strlen(end) + 1);
		}
	}

	dmuci_set_value_by_section(br_sec, "ifname", ifname_dup);
	return 0;
}

static int remove_ifname_from_bridge_section(struct uci_section *br_sec, char *baseifname)
{
	char ifname_dup[128], *ptr, *ifname, *start, *end;
	int pos = 0;

	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	ptr = ifname_dup;
	dmstrappendstr(ptr, ifname);
	dmstrappendend(ptr);

	if (is_strword_in_optionvalue(ifname_dup, baseifname)) {
		start = strstr(ifname_dup, baseifname);
		end = start + strlen(baseifname);
		if (start != ifname_dup) {
			start--;
			pos=1;
		}
		memmove(start, start + strlen(baseifname)+pos, strlen(end) + 1);
	}

	dmuci_set_value_by_section(br_sec, "ifname", ifname_dup);
	return 0;
}

static int add_new_ifname_to_bridge_section(struct uci_section *br_sec, char *new_ifname)
{
	char ifname_dup[128], *ptr, *ifname;

	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	ptr = ifname_dup;
	dmstrappendstr(ptr, ifname);
	dmstrappendend(ptr);

	if (is_strword_in_optionvalue(ifname_dup, new_ifname)) return 0;
	if (ifname_dup[0] != '\0') dmstrappendchr(ptr, ' ');
	dmstrappendstr(ptr, new_ifname);
	dmstrappendend(ptr);

	dmuci_set_value_by_section(br_sec, "ifname", ifname_dup);
	return 0;
}

static char *get_section_name_from_config_section(char *config, char *section, char *option, char *ifname)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq(config, section, option, ifname, s) {
		return dmstrdup(section_name(s));
	}
	return "";
}

static int is_vlan_exist(char *br_inst, char *vid)
{
	struct uci_section *s = NULL;

	uci_path_foreach_sections(bbfdm, "dmmap_network", "bridge_vlan", s) {
		char *s_br_inst, *s_vid;
		dmuci_get_value_by_section_string(s, "br_inst", &s_br_inst);
		dmuci_get_value_by_section_string(s, "vid", &s_vid);
		if ((strcmp(s_br_inst, br_inst) == 0) && (strcmp(s_vid, vid) == 0))
			return 1;
	}
	return 0;
}

static int dmmap_synchronizeBridgingBridgeVLAN(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *stmp = NULL;
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	int found;

	check_create_dmmap_package("dmmap_network");
	uci_path_foreach_option_eq_safe(bbfdm, "dmmap_network", "bridge_vlan", "br_inst", br_args->br_inst, stmp, s) {
		char *vlan_section_name;
		dmuci_get_value_by_section_string(s, "name", &vlan_section_name);
		found = 0;
		struct uci_section *ss = NULL;
		uci_foreach_sections("network", "interface", ss) {
			if (strcmp(section_name(ss), vlan_section_name) == 0) {
				found = 1;
				break;
			}
		}
		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}

	if (br_args->ifname[0] == '\0')
		return 0;

	char *br_ifname = NULL, *pch = NULL, *spch = NULL;
	br_ifname = dmstrdup(br_args->ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		uci_foreach_option_eq("network", "device", "name", pch, s) {
			char *vid;
			dmuci_get_value_by_section_string(s, "vid", &vid);
			if (vid[0] == '\0') vid = "1";
			if (is_vlan_exist(br_args->br_inst, vid))
				break;
			struct uci_section *sbr_vlan = NULL;
			char *name;
			dmuci_add_section_bbfdm("dmmap_network", "bridge_vlan", &sbr_vlan, &name);
			dmuci_set_value_by_section(sbr_vlan, "vid", vid);
			dmuci_set_value_by_section(sbr_vlan, "br_inst", br_args->br_inst);
			dmuci_set_value_by_section(sbr_vlan, "name", section_name(br_args->bridge_sec));
		}
	}
	dmfree(br_ifname);
	return 0;
}

static int remove_ifname_vlanid_from_ifname_list(char *s_name, char *curr_vid)
{
	struct uci_section *s = NULL;

	uci_foreach_sections("network", "interface", s) {
		if (strcmp(section_name(s), s_name) == 0) {
			char *ifname, *pch, *spch;
			dmuci_get_value_by_section_string(s, "ifname", &ifname);
			char *br_ifname = dmstrdup(ifname);
			for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
				char *vid = strchr(pch, '.');
				if (vid && strcmp(vid+1, curr_vid) == 0)
					remove_ifname_from_bridge_section(s, pch);
			}
			dmfree(br_ifname);
			break;
		}
	}
	return 0;
}

static void set_bridge_port_parameters(struct uci_section *dmmap_section, char* bridge_key)
{
	dmuci_set_value_by_section_bbfdm(dmmap_section, "bridge_key", bridge_key);
	dmuci_set_value_by_section_bbfdm(dmmap_section, "mg_port", "false");
	dmuci_set_value_by_section_bbfdm(dmmap_section, "is_dmmap", "false");
}

/*************************************************************
* ADD DELETE OBJECT
**************************************************************/
static int addObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char bridge_name[32], inst_br[16], *last_inst, *v, *p = bridge_name;
	struct uci_section *dmmap_bridge = NULL;

	last_inst = get_last_instance_lev2_bbfdm("network", "interface", "dmmap_network", "bridge_instance", "type", "bridge");
	snprintf(inst_br, sizeof(inst_br), "%d", last_inst ? atoi(last_inst)+1 : 1);
	dmstrappendstr(p, "bridge_");
	dmstrappendstr(p, inst_br);
	dmstrappendend(p);

	// Add interface bridge section
	dmuci_set_value("network", bridge_name, "", "interface");
	dmuci_set_value("network", bridge_name, "type", "bridge");

	// Add dmmap section
	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_bridge, &v);
	dmuci_set_value_by_section(dmmap_bridge, "section_name", bridge_name);
	*instance = update_instance_bbfdm(dmmap_bridge, last_inst, "bridge_instance");

	// Add dmmap management section
	update_section_list("dmmap_bridge_port","bridge_port", "bridge_key", 1, inst_br, "mg_port", "true", "bridge_port_instance", "1");
	return 0;
}

static int delObjBridgingBridge(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *bridge_s = NULL, *dmmap_section = NULL;
	char *bridgekey = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridge_args *)data)->bridge_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "bridge_instance", "");
			dmuci_set_value_by_section(dmmap_section, "ip_int_instance", "");
			dmuci_set_value_by_section(dmmap_section, "ipv4_instance", "");
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "type", "");
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "ifname", "");
			remove_bridge_sections("dmmap_bridge_port", "bridge_port", "bridge_key", ((struct bridge_args *)data)->br_key);
			remove_bridge_sections("dmmap_network", "bridge_vlan", "br_inst", ((struct bridge_args *)data)->br_key);
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "device", "br_inst", ((struct bridge_args *)data)->br_key, s) {
				dmuci_set_value_by_section(s, "bridge_vlanport_instance", "");
				dmuci_set_value_by_section(s, "br_inst", "");
			}
			break;
		case DEL_ALL:
			uci_foreach_option_eq("network", "interface", "type", "bridge", bridge_s) {
				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(bridge_s), &dmmap_section);
				dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &bridgekey);
				dmuci_set_value_by_section(dmmap_section, "bridge_instance", "");
				dmuci_set_value_by_section(dmmap_section, "ip_int_instance", "");
				dmuci_set_value_by_section(dmmap_section, "ipv4_instance", "");
				dmuci_set_value_by_section(bridge_s, "type", "");
				dmuci_set_value_by_section(bridge_s, "ifname", "");
				remove_bridge_sections("dmmap_bridge_port", "bridge_port", "bridge_key", bridgekey);
				remove_bridge_sections("dmmap_network", "bridge_vlan", "br_inst", bridgekey);
				uci_path_foreach_option_eq(bbfdm, "dmmap_network", "device", "br_inst", bridgekey, s) {
					dmuci_set_value_by_section(s, "bridge_vlanport_instance", "");
					dmuci_set_value_by_section(s, "br_inst", "");
				}
			}
			break;
	}
	return 0;
}

static int addObjBridgingBridgePort(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *br_port_s;
	char *v;

	int inst = get_last_inst("dmmap_bridge_port", "bridge_port", "bridge_key", "bridge_port_instance", ((struct bridge_args *)data)->br_key);
	dmasprintf(instance, "%d", inst+1);

	// Add dmmap section
	dmuci_add_section_bbfdm("dmmap_bridge_port", "bridge_port", &br_port_s, &v);
	dmuci_set_value_by_section(br_port_s, "bridge_key", ((struct bridge_args *)data)->br_key);
	dmuci_set_value_by_section(br_port_s, "bridge_port_instance", *instance);
	dmuci_set_value_by_section(br_port_s, "mg_port", "false");
	return 0;
}

static int delObjBridgingBridgePort(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *prev_s = NULL, *dmmap_section= NULL;

	switch (del_action) {
	case DEL_INST:
		get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridge_port_args *)data)->bridge_port_sec), &dmmap_section);
		if (!dmmap_section) {
			// Remove only dmmap section
			dmmap_section = ((struct bridge_port_args *)data)->bridge_port_sec;
			dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
		} else {
			// Remove ifname from ifname list fo bridge section
			char new_ifname[128], *ifname;
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_sec, "ifname", &ifname);
			if (ifname[0] != '\0') {
				remove_interface_from_ifname(((struct bridge_port_args *)data)->ifname, ifname, new_ifname);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_sec, "ifname", new_ifname);
			}

			// Remove dmmap section
			dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", ((struct bridge_port_args *)data)->br_inst, s) {
			if (prev_s)
				dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
			prev_s = s;
		}
		if (prev_s)
			dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
		dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "ifname", "");
		break;
	}
	return 0;
}

static int addObjBridgingBridgeVLANPort(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char intf_tag[64] = {0}, *name, *device_name, *vid, *val, *v;
	struct uci_section *s = NULL, *br_vlanport_s = NULL;

	int inst = get_last_inst("dmmap_network", "device", "br_inst", "bridge_vlanport_instance", ((struct bridge_args *)data)->br_key);
	get_upstream_interface(intf_tag, sizeof(intf_tag));
	dmasprintf(instance, "%d", inst+1);
	dmasprintf(&vid, "%d", inst+5);
	dmasprintf(&device_name, "vlanport_%s", vid);
	dmasprintf(&name, "%s.%s", intf_tag, vid);

	// Add device section
	dmuci_add_section("network", "device", &s, &val);
	dmuci_rename_section_by_section(s, device_name);
	dmuci_set_value_by_section(s, "type", "8021q");
	dmuci_set_value_by_section(s, "ifname", intf_tag);
	dmuci_set_value_by_section(s, "vid", vid);
	dmuci_set_value_by_section(s, "name", name);

	// Add device section in dmmap_network file
	dmuci_add_section_bbfdm("dmmap_network", "device", &br_vlanport_s, &v);
	dmuci_set_value_by_section(br_vlanport_s, "br_inst", ((struct bridge_args *)data)->br_key);
	dmuci_set_value_by_section(br_vlanport_s, "bridge_vlanport_instance", *instance);
	dmuci_set_value_by_section(br_vlanport_s, "section_name", device_name);

	// Update ifname in bridge section
	add_new_ifname_to_bridge_section(((struct bridge_args *)data)->bridge_sec, name);

	dmfree(vid);
	dmfree(device_name);
	dmfree(name);
	return 0;
}

static int delObjBridgingBridgeVLANPort(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *dmmap_section= NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_network", "device", section_name(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec), &dmmap_section);
			// Remove instance from dmmap section
			dmuci_set_value_by_section(dmmap_section, "bridge_vlanport_instance", "");

			// Remove ifname from ifname list fo bridge section
			char new_ifname[128], *ifname, *name;
			dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_sec, "ifname", &ifname);
			if (ifname[0] != '\0') {
				dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", &name);
				remove_interface_from_ifname(name, ifname, new_ifname);
				dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_sec, "ifname", new_ifname);
			}
			break;
		case DEL_ALL:
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "device", "br_inst", ((struct bridge_vlanport_args *)data)->br_inst, s) {
				// Remove instance from dmmap section
				dmuci_set_value_by_section(s, "bridge_vlanport_instance", "");
			}
			dmuci_set_value_by_section(((struct bridge_args *)data)->bridge_sec, "ifname", "");
			break;
		}

	return 0;
}

static int addObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *br_vlan_s = NULL;
	char *v;

	int inst = get_last_inst("dmmap_network", "bridge_vlan", "br_inst", "bridge_vlan_instance", ((struct bridge_args *)data)->br_key);
	dmasprintf(instance, "%d", inst+1);
	DMUCI_ADD_SECTION(bbfdm, "dmmap_network", "bridge_vlan", &br_vlan_s, &v);
	dmuci_set_value_by_section(br_vlan_s, "br_inst", ((struct bridge_args *)data)->br_key);
	dmuci_set_value_by_section(br_vlan_s, "bridge_vlan_instance", *instance);
	dmuci_set_value_by_section(br_vlan_s, "name", section_name(((struct bridge_args *)data)->bridge_sec));
	return 0;
}

static int delObjBridgingBridgeVLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *prev_s = NULL;
	char *vid;

	switch (del_action) {
	case DEL_INST:
		dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &vid);
		if (vid[0] == '\0') {
			// Remove only dmmap section
			dmuci_delete_by_section_unnamed_bbfdm(((struct bridge_vlan_args *)data)->bridge_vlan_sec, NULL, NULL);
		} else {
			// Remove all ifname that have vid from ifname list fo bridge section
			char *s_name;
			dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "name", &s_name);
			remove_ifname_vlanid_from_ifname_list(s_name, vid);

			// Remove only dmmap section
			dmuci_delete_by_section_unnamed_bbfdm(((struct bridge_vlan_args *)data)->bridge_vlan_sec, NULL, NULL);
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_network", "bridge_vlan", "br_inst", ((struct bridge_vlan_args *)data)->br_inst, s) {
			// Remove all ifname that have vid from ifname list fo bridge section
			dmuci_get_value_by_section_string(s, "vid", &vid);
			if (vid[0] != '\0') {
				char *s_name;
				dmuci_get_value_by_section_string(s, "name", &s_name);
				remove_ifname_vlanid_from_ifname_list(s_name, vid);
			}

			// Remove all dmmap section
			if (prev_s)
				dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
			prev_s = s;
		}
		if (prev_s)
			dmuci_delete_by_section_bbfdm(prev_s, NULL, NULL);
		break;
	}
	return 0;
}

/**************************************************************************
*SET & GET PARAMETERS
***************************************************************************/
static int get_Bridging_MaxBridgeEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_MaxDBridgeEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_MaxQBridgeEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_MaxVLANEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Bridging_MaxProviderBridgeEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int get_Bridging_get_Bridging_MaxFilterEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

/*#Device.Bridging.BridgeNumberOfEntries!UCI:network/interface/*/
static int get_Bridging_BridgeNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Enable!UBUS:network.interface/status/interface,@Name/up*/
static int get_BridgingBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct bridge_args *)data)->bridge_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "false");
	*value = dmjson_get_value(res, 1, "up");
	return 0;
}

static int set_BridgingBridge_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmubus_call_set("network.interface", b ? "up" : "down", UBUS_ARGS{{"interface", section_name(((struct bridge_args *)data)->bridge_sec), String}}, 1);
			return 0;
	}
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Status!UBUS:network.interface/status/interface,@Name/up*/
static int get_BridgingBridge_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_BridgingBridge_Enable(refparam, ctx, data, instance, value);
	*value = (strcmp(*value, "true") == 0) ? "Enabled" : "Disabled";
	return 0;
}

static int get_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridge_args *)data)->bridge_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "bridge_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridge_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridge_args *)data)->bridge_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "bridge_alias", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridge_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "802.1Q-2011";
	return 0;
}

static int set_BridgingBridge_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, BridgeStandard, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_BridgingBridge_PortNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", instance, s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_BridgingBridge_VLANNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "bridge_vlan", "br_inst", instance, s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_BridgingBridge_VLANPortNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *br_ifname = NULL, *pch = NULL, *spch = NULL;
	struct uci_section *s = NULL;
	int cnt = 0;

	br_ifname = dmstrdup(((struct bridge_port_args *)data)->ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		uci_foreach_option_eq("network", "device", "name", pch, s) {
			cnt++;
		}
	}
	dmasprintf(value, "%d", cnt);
	dmfree(br_ifname);
	return 0;
}

static int get_BridgingBridgePort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;
	char *package;

	get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridge_port_args *)data)->bridge_port_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "package", &package);
	if (strcmp(package, "wireless") == 0) {
		// wifi-iface wireless section
		char *val;
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "disabled", &val);
		*value = (val[0] == '1') ? "0" : "1";
	} else if (strcmp(package, "ports") == 0) {
		// ethport ports section
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "enabled", value);
	} else
		*value = "1";
	return 0;
}

static int set_BridgingBridgePort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;
	char *package;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridge_port_args *)data)->bridge_port_sec), &dmmap_section);
			dmuci_get_value_by_section_string(dmmap_section, "package", &package);

			if (strcmp(package, "wireless") == 0) {
				// wifi-iface wireless section
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "disabled", b ? "0" : "1");
			} else if (strcmp(package, "ports") == 0) {
				// ethport ports section
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "enabled", b ? "1" : "0");
			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_BridgingBridgePort_Enable(refparam, ctx, data, instance, value);
	*value = (strcmp(*value, "1") == 0) ? "Up" : "Down";
	return 0;
}

static int get_BridgingBridgePort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridge_port_args *)data)->bridge_port_sec), &dmmap_section);
	if (!dmmap_section) {
		// Management Port
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "bridge_port_alias", value);
		goto end;
	}

	// Other Ports
	dmuci_get_value_by_section_string(dmmap_section, "bridge_port_alias", value);
	if ((*value)[0] == '\0') {
		char *package;
		dmuci_get_value_by_section_string(dmmap_section, "package", &package);
		if (strcmp(package, "ports") == 0) {
			// ethport ports section
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "name", value);
		}
		dmuci_set_value_by_section(dmmap_section, "bridge_port_alias", *value);
	}

end:
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridgePort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridge_port_args *)data)->bridge_port_sec), &dmmap_section);
			if (!dmmap_section) dmmap_section = ((struct bridge_port_args *)data)->bridge_port_sec;
			dmuci_set_value_by_section(dmmap_section, "bridge_port_alias", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct bridge_port_args *)data)->ifname);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_BridgingBridgePort_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct bridge_port_args *)data)->bridge_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	if((*value)[0] == '\0')
		*value = "0";
	return 0;
}

static int get_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mg_port, *ifname, *linker = "";

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "mg_port", &mg_port);
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_sec, "ifname", &ifname);
	if (ifname[0] != '\0' && strcmp(mg_port, "true") ==  0) {
		char *pch, *spch, *p, plinker[32], lbuf[512] = { 0, 0 };
		struct uci_section *s = NULL;
		char *ifname_dup = dmstrdup(ifname);
		p = lbuf;
		for (pch = strtok_r(ifname_dup, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			check_port_with_ifname(pch, &s);
			if (s == NULL)
				continue;
			snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", ((struct bridge_port_args *)data)->br_inst, section_name(s), pch);
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), plinker, value);
			if (*value == NULL)
				*value = "";
			dmstrappendstr(p, *value);
			dmstrappendchr(p, ',');
		}
		p = p -1;
		dmstrappendend(p);
		*value = dmstrdup(lbuf);
		dmfree(ifname_dup);
		return 0;
	} else
		dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &linker);

	adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx,dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cATM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cPTM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);

	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_BridgingBridgePort_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer[256] = {0}, *mg_port = "false";
	struct uci_section *dmmap_section= NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridge_port_args *)data)->bridge_port_sec), &dmmap_section);
			dmuci_get_value_by_section_string(dmmap_section, "mg_port", &mg_port);
			if (strcmp(mg_port, "true") == 0)
				return 0;

			if (value[strlen(value)-1] != '.')
				snprintf(lower_layer, sizeof(lower_layer), "%s.", value);
			else
				strncpy(lower_layer, value, sizeof(lower_layer) - 1);

			char *package, *section;
			dmuci_get_value_by_section_string(dmmap_section, "package", &package);
			dmuci_get_value_by_section_string(dmmap_section, "section", &section);

			char *linker = NULL;
			adm_entry_get_linker_value(ctx, lower_layer, &linker);
			if (!linker || linker[0] == '\0')
				return 0;

			if (check_ifname_exist_in_br_ifname_list(linker, section_name(((struct bridge_port_args *)data)->bridge_sec)))
				return 0;

			if (strncmp(lower_layer, "Device.Ethernet.Interface.", 26) == 0) {
				if (strcmp(package, "ports") == 0 && strcmp(section, "ethport") == 0) {
					char *ifname;
					dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &ifname);
					remove_ifname_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, ifname);
					add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);
					char *section_name = get_section_name_from_config_section("ports", "ethport", "ifname", linker);
					dmuci_set_value_by_section(dmmap_section, "section_name", section_name);
				} else if (strcmp(package, "wireless") == 0 && strcmp(section, "wifi-iface") == 0) {
					char *ifname;
					dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &ifname);
					remove_ifname_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, ifname);
					add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);
					dmuci_set_value_by_section(dmmap_section, "package", "ports");
					dmuci_set_value_by_section(dmmap_section, "section", "ethport");
					char *section_name = get_section_name_from_config_section("ports", "ethport", "ifname", linker);
					dmuci_set_value_by_section(dmmap_section, "section_name", section_name);
				} else {
					char *new_name, *vid;
					dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "vid", &vid);
					dmasprintf(&new_name, "%s.%s", linker, vid);
					update_bridge_ifname(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->bridge_port_sec, 0);
					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", linker);
					dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "name", new_name);
					update_bridge_ifname(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->bridge_port_sec, 1);
					dmfree(new_name);
				}
			} else if (strncmp(lower_layer, "Device.WiFi.SSID.", 17) == 0) {
				char *ifname;
				if (strcmp(package, "network") == 0 && strcmp(section, "device") == 0)
					dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "name", &ifname);
				else
					dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &ifname);
				remove_ifname_from_bridge_section(((struct bridge_port_args *)data)->bridge_sec, ifname);
				add_new_ifname_to_bridge_section(((struct bridge_port_args *)data)->bridge_sec, linker);
				dmuci_set_value_by_section(dmmap_section, "package", "wireless");
				dmuci_set_value_by_section(dmmap_section, "section", "wifi-iface");
				char *section_name = get_section_name_from_config_section("wireless", "wifi-iface", "ifname", linker);
				dmuci_set_value_by_section(dmmap_section, "section_name", section_name);
			}
			return 0;
		}
	return 0;
}

static int get_BridgingBridgePort_ManagementPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridge_port_args *)data)->bridge_port_sec), &dmmap_section);
	if (!dmmap_section) dmmap_section = ((struct bridge_port_args *)data)->bridge_port_sec;
	dmuci_get_value_by_section_string(dmmap_section, "mg_port", value);
	return 0;
}

static int set_BridgingBridgePort_ManagementPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_DefaultUserPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "priority", value);
	return 0;
}

static int set_BridgingBridgePort_DefaultUserPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *type;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
			if (type[0] != '\0' && (strcmp(type, "untagged") == 0 || strcmp(type, "8021q") == 0))
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "priority", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_PVID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "vid", value);
	if ((*value)[0] == '\0')
		*value = "1";
	return 0;
}

static int set_BridgingBridgePort_PVID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *type;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
			if (type[0] != '\0' && (strcmp(type, "untagged") == 0 || strcmp(type, "8021q") == 0)) {
				char *ifname, *new_name;
				dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "ifname", &ifname);
				dmasprintf(&new_name, "%s.%s", ifname, value);
				update_bridge_ifname(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->bridge_port_sec, 0);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "name", new_name);
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "vid", value);
				update_bridge_ifname(((struct bridge_port_args *)data)->bridge_sec, ((struct bridge_port_args *)data)->bridge_port_sec, 1);
				dmfree(new_name);
			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgePort_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type;

	dmuci_get_value_by_section_string(((struct bridge_port_args *)data)->bridge_port_sec, "type", &type);
	if (strcmp(type, "8021q") == 0 || strcmp(type, "untagged") == 0)
		*value = "33024";
	else if (strcmp(type, "8021ad") == 0)
		*value = "34984";
	else
		*value = "37120";
	return 0;
}

static int set_BridgingBridgePort_TPID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "33024") == 0)
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "type", "8021q");
			else if (strcmp(value, "34984") == 0)
				dmuci_set_value_by_section(((struct bridge_port_args *)data)->bridge_port_sec, "type", "8021ad");
			return 0;
	}
	return 0;
}

static int br_get_sysfs(const struct bridge_port_args *br, const char *name, char **value)
{
	char *device;

	dmuci_get_value_by_section_string(br->bridge_port_sec, "ifname", &device);
	return get_net_device_sysfs(device, name, value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
static int get_BridgingBridgePortStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
static int get_BridgingBridgePortStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
static int get_BridgingBridgePortStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
static int get_BridgingBridgePortStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.ErrorsSent!UBUS:network.device/status/name,@Name/statistics.tx_errors*/
static int get_BridgingBridgePortStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.ErrorsReceived!UBUS:network.device/status/name,@Name/statistics.rx_errors*/
static int get_BridgingBridgePortStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_errors", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.DiscardPacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_dropped*/
static int get_BridgingBridgePortStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.DiscardPacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_dropped*/
static int get_BridgingBridgePortStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_dropped", value);
}

static int get_BridgingBridgePortStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/multicast", value);
}

static int get_BridgingBridgeVLAN_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_BridgingBridgeVLAN_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "bridge_vlan_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridgeVLAN_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "bridge_vlan_alias", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLAN_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "name", value);
	return 0;
}

static int set_BridgingBridgeVLAN_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *s_name;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "name", &s_name);
			uci_foreach_sections("network", "interface", s) {
				if (strcmp(section_name(s), s_name) == 0) {
					dmuci_rename_section_by_section(s, value);
					break;
				}
			}
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "name", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLAN_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", value);
	return 0;
}

static int set_BridgingBridgeVLAN_VLANID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *s_name, *curr_vid;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "name", &s_name);
			dmuci_get_value_by_section_string(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", &curr_vid);
			uci_foreach_sections("network", "interface", s) {
				if (strcmp(section_name(s), s_name) == 0) {
					char *ifname, *pch, *spch;
					dmuci_get_value_by_section_string(s, "ifname", &ifname);
					char *br_ifname = dmstrdup(ifname);
					for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
						char *vid = strchr(pch, '.');
						if (vid && strcmp(vid+1, curr_vid) == 0) {
							remove_ifname_from_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, pch);
							struct uci_section *device_s;
							char *ifname, *new_name;
							uci_foreach_option_eq("network", "device", "name", pch, device_s) {
								dmuci_get_value_by_section_string(device_s, "ifname", &ifname);
								dmasprintf(&new_name, "%s.%s", ifname, value);
								dmuci_set_value_by_section(device_s, "name", new_name);
								dmuci_set_value_by_section(device_s, "vid", value);
							}
							add_new_ifname_to_bridge_section(((struct bridge_vlan_args *)data)->bridge_sec, new_name);
							dmfree(new_name);
						}
					}
					break;
				}
			}
			dmuci_set_value_by_section(((struct bridge_vlan_args *)data)->bridge_vlan_sec, "vid", value);
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_BridgingBridgeVLANPort_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_BridgingBridgeVLANPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "device", section_name(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "bridge_vlanport_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_BridgingBridgeVLANPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "device", section_name(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "bridge_vlanport_alias", value);
			break;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char linker[32], *vid;
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", &vid);
	snprintf(linker, sizeof(linker),"br_%s:vlan_%s", ((struct bridge_vlanport_args *)data)->br_inst, (vid[0] != '\0') ? vid : "1");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_BridgingBridgeVLANPort_VLAN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer[256] = {0}, lower_layer_path[256] = {0};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (value[strlen(value)-1] != '.')
				snprintf(lower_layer, sizeof(lower_layer), "%s.", value);
			else
				strncpy(lower_layer, value, sizeof(lower_layer) - 1);

			snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.VLAN.", ((struct bridge_vlanport_args *)data)->br_inst);

			if (strncmp(lower_layer, lower_layer_path, strlen(lower_layer_path)) == 0) {

				char *linker = NULL;
				adm_entry_get_linker_value(ctx, lower_layer, &linker);
				if (!linker)
					return 0;

				char *br = strstr(linker, ":vlan_");
				if (br) {
					char *curr_ifname, *new_name, *new_vid = dmstrdup(br+6);
					dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "ifname", &curr_ifname);
					dmasprintf(&new_name, "%s.%s", curr_ifname, new_vid);
					update_bridge_ifname(((struct bridge_vlanport_args *)data)->bridge_sec, ((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, 0);
					dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", new_name);
					dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "vid", new_vid);
					update_bridge_ifname(((struct bridge_vlanport_args *)data)->bridge_sec, ((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, 1);
					dmfree(new_name);
				}
			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char plinker[32], *name;

	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "name", &name);
	snprintf(plinker, sizeof(plinker), "br_%s:%s+%s", ((struct bridge_vlanport_args *)data)->br_inst, section_name(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec), name);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), plinker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_BridgingBridgeVLANPort_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char lower_layer[256] = {0}, lower_layer_path[256] = {0};

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (value[strlen(value)-1] != '.')
				snprintf(lower_layer, sizeof(lower_layer), "%s.", value);
			else
				strncpy(lower_layer, value, sizeof(lower_layer) - 1);

			snprintf(lower_layer_path, sizeof(lower_layer_path), "Device.Bridging.Bridge.%s.VLANPort.", ((struct bridge_vlanport_args *)data)->br_inst);

			if (strncmp(lower_layer, lower_layer_path, strlen(lower_layer_path)) == 0) {

				char *linker = NULL;
				adm_entry_get_linker_value(ctx, lower_layer, &linker);
				if (!linker)
					return 0;
			}
			return 0;
	}
	return 0;
}

static int get_BridgingBridgeVLANPort_Untagged(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type;
	dmuci_get_value_by_section_string(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "type", &type);

	*value = (strcmp(type, "untagged") == 0) ? "1" : "0";
	return 0;
}

static int set_BridgingBridgeVLANPort_Untagged(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct bridge_vlanport_args *)data)->bridge_vlanport_sec, "type", (b) ? "untagged" : "8021q");
			return 0;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Bridging.Bridge.{i}.!UCI:network/interface/dmmap_network*/
static int browseBridgingBridgeInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *br_inst = NULL, *br_inst_last = NULL, *ifname;
	struct bridge_args curr_bridging_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_network", "type", "bridge", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		br_inst = handle_update_instance(1, dmctx, &br_inst_last, update_instance_alias, 3, p->dmmap_section, "bridge_instance", "bridge_alias");
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		init_bridging_args(&curr_bridging_args, p->config_section, br_inst_last, ifname, br_inst);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_args, br_inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}


static int browseBridgingBridgePortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *new_port = NULL;
	char *port = NULL, *port_last = NULL, *br_ifname = NULL, *pch = NULL, *spch = NULL, *is_dmmap;
	bool find_max = true, found = false;
	struct bridge_port_args curr_bridge_port_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	check_create_dmmap_package("dmmap_bridge_port");
	update_section_list_bbfdm("dmmap_bridge_port","bridge_port", "bridge_key", 1, br_args->br_key, "mg_port", "true", "bridge_port_instance", "1");
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", br_args->br_key, new_port) {
		dmuci_get_value_by_section_string(new_port, "is_dmmap", &is_dmmap);
		if (strcmp(is_dmmap, "false") != 0) {
			init_bridge_port_args(&curr_bridge_port_args, new_port, br_args->bridge_sec, "", br_args->br_inst);
			port = handle_update_instance(2, dmctx, &port_last, update_instance_alias_bbfdm, 5, new_port, "bridge_port_instance", "bridge_port_alias",  &find_max, br_args->br_key);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_port_args, port) == DM_STOP)
				return 0;
		}
	}

	if (br_args->ifname[0] == '\0')
		return 0;

	br_ifname = dmstrdup(br_args->ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		found = false;

		if (!found)
			found = synchronize_multi_config_sections_with_dmmap_port("ports", "ethport", "dmmap_bridge_port", "bridge_port", "ifname", pch, pch, &dup_list, br_args->br_key);

		if (!found)
			found = synchronize_multi_config_sections_with_dmmap_eq("wireless", "wifi-iface", "dmmap_bridge_port", "bridge_port", "ifname", pch, pch, &dup_list);

		if (!found)
			found = synchronize_multi_config_sections_with_dmmap_eq("network", "device", "dmmap_bridge_port", "bridge_port", "name", pch, pch, &dup_list);
	}

	list_for_each_entry(p, &dup_list, list) {
		set_bridge_port_parameters(p->dmmap_section, br_args->br_key);
		init_bridge_port_args(&curr_bridge_port_args, p->config_section, br_args->bridge_sec, (char*)p->additional_attribute, br_args->br_inst);
		port = handle_update_instance(2, dmctx, &port_last, update_instance_alias_bbfdm, 5, p->dmmap_section, "bridge_port_instance", "bridge_port_alias", &find_max, br_args->br_key);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_port_args, port) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	dmfree(br_ifname);
	return 0;
}

static int browseBridgingBridgeVLANInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct bridge_vlan_args curr_bridge_vlan_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct uci_section *s = NULL;
	char *vlan_inst = NULL, *vlan_last = NULL;

	dmmap_synchronizeBridgingBridgeVLAN(dmctx, parent_node, prev_data, prev_instance);
	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "bridge_vlan", "br_inst", br_args->br_inst, s) {
		vlan_inst = handle_update_instance(1, dmctx, &vlan_last, update_instance_alias_bbfdm, 3, s, "bridge_vlan_instance", "bridge_vlan_alias");
		init_bridge_vlan_args(&curr_bridge_vlan_args, s, br_args->bridge_sec, vlan_inst, br_args->br_inst);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_vlan_args, vlan_inst) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.Bridging.Bridge.{i}.VLANPort.!UCI:network/device/dmmap_network*/
static int browseBridgingBridgeVLANPortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *vlanport_inst = NULL, *pch = NULL, *br_ifname = NULL, *spch = NULL, *vlanport_last = NULL;
	struct bridge_vlanport_args curr_bridge_vlanport_args = {0};
	struct bridge_args *br_args = (struct bridge_args *)prev_data;
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	if (br_args->ifname[0] == '\0')
		return 0;

	br_ifname = dmstrdup(br_args->ifname);
	for (pch = strtok_r(br_ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch))
		synchronize_specific_config_sections_with_dmmap_eq("network", "device", "dmmap_network", "name", pch, &dup_list);

	list_for_each_entry(p, &dup_list, list) {
		dmuci_set_value_by_section(p->dmmap_section, "br_inst", br_args->br_key);
		vlanport_inst =  handle_update_instance(2, dmctx, &vlanport_last, update_instance_alias, 3, p->dmmap_section, "bridge_vlanport_instance", "bridge_vlanport_alias");
		init_bridge_vlanport_args(&curr_bridge_vlanport_args, p->config_section, br_args->bridge_sec, vlanport_last, br_args->br_key);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridge_vlanport_args, vlanport_inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	dmfree(br_ifname);
	return 0;
}

/**********************************************************************************************************************************
*                                            OBJ & PARAM DEFINITION
***********************************************************************************************************************************/
/* *** Device.Bridging. *** */
DMOBJ tBridgingObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Bridge", &DMWRITE, addObjBridgingBridge, delObjBridgingBridge, NULL, browseBridgingBridgeInst, NULL, NULL, NULL, tBridgingBridgeObj, tBridgingBridgeParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MaxBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxBridgeEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxDBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxDBridgeEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxQBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxQBridgeEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxVLANEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxVLANEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxProviderBridgeEntries", &DMREAD, DMT_UNINT, get_Bridging_MaxProviderBridgeEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxFilterEntries", &DMREAD, DMT_UNINT, get_Bridging_get_Bridging_MaxFilterEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"BridgeNumberOfEntries", &DMREAD, DMT_UNINT, get_Bridging_BridgeNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}. ***/
DMOBJ tBridgingBridgeObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Port", &DMWRITE, addObjBridgingBridgePort, delObjBridgingBridgePort, NULL, browseBridgingBridgePortInst, NULL, NULL, NULL, tBridgingBridgePortObj, tBridgingBridgePortParams, get_linker_br_port, BBFDM_BOTH},
{"VLAN", &DMWRITE, addObjBridgingBridgeVLAN, delObjBridgingBridgeVLAN, NULL, browseBridgingBridgeVLANInst, NULL, NULL, NULL, NULL, tBridgingBridgeVLANParams, get_linker_br_vlan, BBFDM_BOTH},
{"VLANPort", &DMWRITE, addObjBridgingBridgeVLANPort, delObjBridgingBridgeVLANPort, NULL, browseBridgingBridgeVLANPortInst, NULL, NULL, NULL, NULL, tBridgingBridgeVLANPortParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridge_Enable, set_BridgingBridge_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridge_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridge_Alias, set_BridgingBridge_Alias, NULL, NULL, BBFDM_BOTH},
{"Standard", &DMWRITE, DMT_STRING, get_BridgingBridge_Standard, set_BridgingBridge_Standard, NULL, NULL, BBFDM_BOTH},
{"PortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_PortNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"VLANNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"VLANPortNumberOfEntries", &DMREAD, DMT_UNINT, get_BridgingBridge_VLANPortNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}. ***/
DMOBJ tBridgingBridgePortObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingBridgePortStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingBridgePortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_Enable, set_BridgingBridgePort_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BridgingBridgePort_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Alias, set_BridgingBridgePort_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_BridgingBridgePort_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_BridgingBridgePort_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_BridgingBridgePort_LowerLayers, set_BridgingBridgePort_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"ManagementPort", &DMWRITE, DMT_BOOL, get_BridgingBridgePort_ManagementPort, set_BridgingBridgePort_ManagementPort, NULL, NULL, BBFDM_BOTH},
//{"Type", &DMWRITE, DMT_STRING, get_BridgingBridgePort_Type, set_BridgingBridgePort_Type, NULL, NULL, BBFDM_BOTH},
{"DefaultUserPriority", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_DefaultUserPriority, set_BridgingBridgePort_DefaultUserPriority, NULL, NULL, BBFDM_BOTH},
//{"PriorityRegeneration", &DMWRITE, DMT_STRING, get_BridgingBridgePort_PriorityRegeneration, set_BridgingBridgePort_PriorityRegeneration, NULL, NULL, BBFDM_BOTH},
//{"PortState", &DMREAD, DMT_STRING, get_BridgingBridgePort_PortState, NULL, NULL, NULL, BBFDM_BOTH},
{"PVID", &DMWRITE, DMT_INT, get_BridgingBridgePort_PVID, set_BridgingBridgePort_PVID, NULL, NULL, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_BridgingBridgePort_TPID, set_BridgingBridgePort_TPID, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}.Stats. ***/
DMLEAF tBridgingBridgePortStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_BridgingBridgePortStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_BridgingBridgePortStats_UnknownProtoPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLAN.{i}. ***/
DMLEAF tBridgingBridgeVLANParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLAN_Enable, set_BridgingBridgeVLAN_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,get_BridgingBridgeVLAN_Alias, set_BridgingBridgeVLAN_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_BridgingBridgeVLAN_Name, set_BridgingBridgeVLAN_Name, NULL, NULL, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_INT, get_BridgingBridgeVLAN_VLANID, set_BridgingBridgeVLAN_VLANID, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLANPort.{i}. ***/
DMLEAF tBridgingBridgeVLANPortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Enable, set_BridgingBridgeVLANPort_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_Alias, set_BridgingBridgeVLANPort_Alias, NULL, NULL, BBFDM_BOTH},
{"VLAN", &DMWRITE, DMT_STRING,  get_BridgingBridgeVLANPort_VLAN, set_BridgingBridgeVLANPort_VLAN, NULL, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_STRING, get_BridgingBridgeVLANPort_Port, set_BridgingBridgeVLANPort_Port, NULL, NULL, BBFDM_BOTH},
{"Untagged", &DMWRITE, DMT_BOOL, get_BridgingBridgeVLANPort_Untagged, set_BridgingBridgeVLANPort_Untagged, NULL, NULL, BBFDM_BOTH},
{0}
};
