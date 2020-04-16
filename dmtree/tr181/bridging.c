/*
 * Copyright (C) 2019 iopsys Software Solutions AB
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

struct bridging_args
{
	struct uci_section *bridge_sec;
	char *br_key;
	char *ifname;
	char *br_inst;
};

struct bridging_port_args
{
	struct uci_section *bridge_port_sec;
	struct uci_section *bridge_sec;
	bool vlan;
	char *ifname;
};

struct bridging_vlan_args
{
	struct uci_section *bridge_vlan_sec;
	struct uci_section *bridge_sec;
	char *vlan_port;
	char *br_inst;
	char *ifname;
};

static char *wan_baseifname = NULL;


/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_br_port(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct bridging_port_args *)data)->bridge_port_sec)
		dmasprintf(linker, "%s+%s", section_name(((struct bridging_port_args *)data)->bridge_port_sec), ((struct bridging_port_args *)data)->ifname);
	else
		*linker = "";
	return 0;
}

static int get_linker_br_vlan(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct bridging_vlan_args *)data)->vlan_port)
		dmasprintf(linker, "vlan%s_%s", ((struct bridging_vlan_args *)data)->vlan_port, ((struct bridging_vlan_args *)data)->br_inst);
	else
		*linker = "";
	return 0;
}
/**************************************************************************
* INIT
***************************************************************************/
static inline int init_bridging_args(struct bridging_args *args, struct uci_section *s, char *last_instance, char *ifname, char *br_instance)
{
	args->bridge_sec = s;
	args->br_key = last_instance;
	args->ifname = ifname;
	args->br_inst = br_instance;
	return 0;
}

static inline int init_bridging_port_args(struct bridging_port_args *args, struct uci_section *s, struct uci_section *bs, bool vlan, char *ifname)
{
	args->bridge_port_sec = s;
	args->bridge_sec = bs;
	args->vlan = vlan;
	args->ifname = ifname;
	return 0;
}

static inline int init_bridging_vlan_args(struct bridging_vlan_args *args, struct uci_section *s, struct uci_section *bs, char *vlan_port, char *br_inst)
{
	args->bridge_vlan_sec = s;
	args->bridge_sec = bs;
	args->vlan_port = vlan_port;
	args->br_inst = br_inst;
	return 0;
}

/**************************************************************************
* INSTANCE MG
***************************************************************************/
static int check_ifname_exist_in_br_ifname_list(char *ifname, char *section)
{
	char *br_ifname_list, *pch, *spch;
	struct uci_section *s = NULL;

	uci_foreach_option_eq("network", "interface", "type", "bridge", s) {

		/* Check if both the section names are same or not, if same fetch the interface
		 * name else continue with the next section. */
		char br_sec[250] = {0};
		strncpy(br_sec, section, sizeof(br_sec) - 1);

		if (strncmp(br_sec, section_name(s), sizeof(br_sec)) != 0) {
			continue;
		}

		dmuci_get_value_by_section_string(s, "ifname", &br_ifname_list);
		if (br_ifname_list[0] == '\0')
			return 0;

		for (pch = strtok_r(br_ifname_list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			/* Check to support tagged and untagged interfaces. */
			if (strncmp(ifname, pch, 4) == 0) {
				return 1;
			}
		}
	}

	return 0;
}

static int get_br_port_last_inst(char *br_key)
{
	char *tmp;
	int instance, max = 1;
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", br_key, s) {
		dmuci_get_value_by_section_string(s, "bridge_port_instance", &tmp);
		if (tmp[0] == '\0')
			continue;
		instance = atoi(tmp);
		if (instance > max) max = instance;
	}
	return max;
}

static int reset_br_port(char *br_key)
{
	struct uci_section *s = NULL, *prev_s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", br_key, s) {
		if (prev_s)
			dmuci_delete_by_section(prev_s, NULL, NULL);
		prev_s = s;
	}
	if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
	return 0;
}

static int is_br_port_enabled(struct bridging_port_args *curr_arg)
{
	struct uci_section *vlan_sec = curr_arg->bridge_port_sec, *br_sec = curr_arg->bridge_sec;
	char *ifname, *br_ifname, *ifname_dup;

	dmuci_get_value_by_section_string(br_sec, "ifname", &br_ifname);
	dmuci_get_value_by_section_string(vlan_sec, "name", &ifname);
	ifname_dup = dmstrdup(br_ifname);
	if(ifname != NULL && ifname[0] != '\0') {
		if (is_strword_in_optionvalue(ifname_dup, ifname))
			return 1;
	}
	return 0;
}

static int update_br_port_ifname(struct bridging_port_args *curr_arg, int status)
{
	char ifname_dup[128], *ptr, *baseifname, *ifname, *start, *end;
	struct uci_section *vlan_sec = curr_arg->bridge_port_sec, *br_sec = curr_arg->bridge_sec;
	int pos=0;
	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	dmuci_get_value_by_section_string(vlan_sec, "name", &baseifname);
	ptr = ifname_dup;
	dmstrappendstr(ptr, ifname);
	dmstrappendend(ptr);
	if(status){
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

/**************************************************************************
*SET & GET BRIDGING PARAMETERS
***************************************************************************/
static int get_Max_Bridge_Entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Max_DBridge_Entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Max_QBridge_Entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Max_VLAN_Entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "20";
	return 0;
}

static int get_Max_Provider_Bridge_Entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int get_Max_Filter_Entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

/*#Device.Bridging.BridgeNumberOfEntries!UCI:network/interface/*/
static int get_Bridge_Number_Of_Entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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
static int get_br_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct bridging_args *)data)->bridge_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "false");
	*value = dmjson_get_value(res, 1, "up");
	return 0;
}

static int set_br_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmubus_call_set("network.interface", b ? "up" : "down", UBUS_ARGS{{"interface", section_name(((struct bridging_args *)data)->bridge_sec), String}}, 1);
			return 0;
	}
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Status!UBUS:network.interface/status/interface,@Name/up*/
static int get_br_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct bridging_args *)data)->bridge_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "Disabled");
	*value = dmjson_get_value(res, 1, "up");
	if (strcmp(*value, "true") == 0)
		*value = "Enabled";
	else
		*value = "Disabled";
	return 0;
}

static int get_br_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "802.1Q-2011";
	return 0;
}

static int set_br_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_br_port_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", instance, s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_br_vlan_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	/* Interface section needs to be browsed to get the vlan entries. */
	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "bridge_key", instance, s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_br_vlan_port_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = 0;
	char *br_ifname_list, *br_ifname_dup, *pch, *spch;

	dmuci_get_value_by_section_string(((struct bridging_args *)data)->bridge_sec, "ifname", &br_ifname_list);

	if(br_ifname_list[0] == '\0') {
		dmasprintf(value, "%d", cnt);
		return 0;
	}

	br_ifname_dup = dmstrdup(br_ifname_list);

	for (pch = strtok_r(br_ifname_dup, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		/* Bridge has vlan's defined as ethx.y where y is the vlan id, so, the presence
		 * of '.' in the string confirms vlan port. */
		if (strstr(pch, ".") != NULL) {
			cnt++;
		}
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_br_port_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "ifname", value);

	// wifi-iface wireless section
	if(strncmp(*value, "wl", 2) == 0 || strncmp(*value, "ra", 2) == 0 || strncmp(*value, "apclii", 6) == 0) {
		struct uci_section *wifi_device_s = NULL;
		char *val;

		uci_foreach_option_eq("wireless", "wifi-iface", "ifname", *value, wifi_device_s) {
			dmuci_get_value_by_section_string(wifi_device_s, "disabled", &val);
			*value = (val[0] == '1') ? "0" : "1";
			return 0;
		}
	}

	// ethport ports section
	char *type;
	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "type", &type);
	if (*type == '\0') {
		dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "enabled", value);
	} else {
		struct uci_section *s = NULL;
		uci_foreach_option_eq("ports", "ethport", "ifname", *value, s) {
			dmuci_get_value_by_section_string(s, "enabled", value);
			break;
		}
	}
	if ((*value)[0] == '\0') *value = "1";
	return 0;
}

static int set_br_port_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *ifname;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "ifname", &ifname);

			// wifi-iface wireless section
			if(strncmp(ifname, "wl", 2) == 0 || strncmp(ifname, "ra", 2) == 0 || strncmp(ifname, "apclii", 6) == 0) {
				struct uci_section *wifi_device_s = NULL;

				uci_foreach_option_eq("wireless", "wifi-iface", "ifname", ifname, wifi_device_s) {
					dmuci_set_value_by_section(wifi_device_s, "disabled", b ? "0" : "1");
					return 0;
				}
			}

			// ethport ports section
			char *type;
			dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "type", &type);
			if (*type == '\0') {
				dmuci_set_value_by_section(((struct bridging_port_args *)data)->bridge_port_sec, "enabled", b ? "1" : "0");
			} else {
				struct uci_section *s = NULL;
				uci_foreach_option_eq("ports", "ethport", "ifname", ifname, s) {
					dmuci_set_value_by_section(s, "enabled", b ? "1" : "0");
					break;
				}
			}
			return 0;
	}
	return 0;
}

static int get_br_port_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	get_br_port_enable(refparam, ctx, data, instance, value);
	string_to_bool(*value, &b);
	*value = b ? "Up" : "Down";
	return 0;
}

static int get_br_port_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "ifname", value);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_br_port_last_change(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct bridging_port_args *)data)->bridge_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "uptime");
	if((*value)[0] == '\0')
		*value = "0";
	return 0;
}

static int get_br_port_management(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridging_port_args *)data)->bridge_port_sec), &dmmap_section);
	if (!dmmap_section)
		dmmap_section = ((struct bridging_port_args *)data)->bridge_port_sec;
	dmuci_get_value_by_section_string(dmmap_section, "mg_port", value);
	return 0;
}

static int set_br_port_management(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static struct uci_section *check_if_ifname_is_tagged(char *ifname)
{
	struct uci_section *s = NULL;
	uci_foreach_option_eq("network", "device", "name", ifname, s) {
		return s;
	}
	return NULL;
}

static int get_br_port_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name;
	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "name", &name);
	if (check_if_ifname_is_tagged(name) != NULL)
		*value = "CustomerVLANPort";
	else
		*value = "";
	return 0;
}

static int set_br_port_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, BridgeType, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_br_port_default_user_priority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *name, *type;

	*value = "0";
	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "name", &name);
	s = check_if_ifname_is_tagged(name);
	if (s != NULL) {
		dmuci_get_value_by_section_string(s, "type", &type);
		if (strcmp(type, "untagged") != 0)
			dmuci_get_value_by_section_string(s, "priority", value);
	}
	return 0;
}

static int set_br_port_default_user_priority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *name, *type;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "name", &name);
			s = check_if_ifname_is_tagged(name);
			if (s != NULL) {
				dmuci_get_value_by_section_string(s, "type", &type);
				if (strcmp(type, "untagged") != 0)
					dmuci_set_value_by_section(s, "priority", value);
			}
			return 0;
	}
	return 0;
}

static int get_br_port_priority_regeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0,1,2,3,4,5,6,7";
	return 0;
}

static int set_br_port_priority_regeneration(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, 8, 8, -1, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_br_port_port_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *name;

	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "name", &name);
	if (check_if_ifname_is_tagged(name) != NULL)
		*value = "Forwarding";
	else
		*value = "Disabled";
	return 0;
}

static int get_br_port_pvid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *name, *type;

	*value = "1";
	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "name", &name);
	s = check_if_ifname_is_tagged(name);
	if (s != NULL) {
		dmuci_get_value_by_section_string(s, "type", &type);
		if (strcmp(type, "untagged") != 0)
			dmuci_get_value_by_section_string(s, "vid", value);
	}
	return 0;
}

static int set_br_port_pvid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *name, *type, *ifname, *new_name;
	int is_enabled;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "name", &name);
			s = check_if_ifname_is_tagged(name);
			if (s != NULL) {
				dmuci_get_value_by_section_string(s, "type", &type);
				if (strcmp(type, "untagged") != 0) {
					dmuci_set_value_by_section(s, "vid", value);
					dmuci_get_value_by_section_string(s, "ifname", &ifname);
					dmasprintf(&new_name, "%s.%s", ifname, value);
					is_enabled = is_br_port_enabled((struct bridging_port_args *)data);
					if (is_enabled)
						update_br_port_ifname((struct bridging_port_args *)data, 0);
					dmuci_set_value_by_section(s, "name", new_name);
					if (is_enabled)
						update_br_port_ifname((struct bridging_port_args *)data, 1);
					dmfree(new_name);
				}
			}
			return 0;
	}
	return 0;
}

static int get_br_port_tpid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type;

	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "type", &type);
	if (strcmp(type, "8021q") == 0 || strcmp(type, "untagged") == 0)
		*value = "33024";
	else if (strcmp(type, "8021ad") == 0)
		*value = "34984";
	else
		*value = "37120";
	return 0;
}

static int set_br_port_tpid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "33024") == 0)
				dmuci_set_value_by_section(((struct bridging_port_args *)data)->bridge_port_sec, "type", "8021q");
			else if (strcmp(value, "34984") == 0)
				dmuci_set_value_by_section(((struct bridging_port_args *)data)->bridge_port_sec, "type", "8021ad");
			return 0;
	}
	return 0;
}

/**************************************************************************
* GET STAT
***************************************************************************/
static int br_get_sysfs(const struct bridging_port_args *br, const char *name, char **value)
{
	char *device;

	dmuci_get_value_by_section_string(br->bridge_port_sec, "ifname", &device);
	return get_net_device_sysfs(device, name, value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
static int get_br_port_stats_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
static int get_br_port_stats_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
static int get_br_port_stats_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
static int get_br_port_stats_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.ErrorsSent!UBUS:network.device/status/name,@Name/statistics.tx_errors*/
static int get_br_port_stats_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.ErrorsReceived!UBUS:network.device/status/name,@Name/statistics.rx_errors*/
static int get_br_port_stats_rx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_errors", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.DiscardPacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_dropped*/
static int get_br_port_stats_tx_discard_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.Bridging.Bridge.{i}.Port.{i}.Stats.DiscardPacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_dropped*/
static int get_br_port_stats_rx_discard_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/rx_dropped", value);
}

static int get_br_port_stats_rx_multicast_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return br_get_sysfs(data, "statistics/multicast", value);
}

static int is_bridge_vlan_enabled(struct bridging_vlan_args *curr_arg)
{
	struct uci_section *vlan_sec = curr_arg->bridge_vlan_sec, *br_sec = curr_arg->bridge_sec;
	char *ifname, *br_ifname, *ifname_dup;

	dmuci_get_value_by_section_string(br_sec, "ifname", &br_ifname);
	dmuci_get_value_by_section_string(vlan_sec, "name", &ifname);
	ifname_dup = dmstrdup(br_ifname);
	if (ifname != NULL && ifname[0] != '\0') {
		if (is_strword_in_optionvalue(ifname_dup, ifname))
			return 1;
	}
	return 0;
}

static int update_br_vlan_ifname(struct bridging_vlan_args *curr_arg, int status)
{
	char ifname_dup[128], *ptr, *baseifname, *ifname, *start, *end;
	struct uci_section *vlan_sec = curr_arg->bridge_vlan_sec, *br_sec = curr_arg->bridge_sec;
	int pos=0;
	dmuci_get_value_by_section_string(br_sec, "ifname", &ifname);
	dmuci_get_value_by_section_string(vlan_sec, "name", &baseifname);
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

static int get_br_vlan_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	int status = is_bridge_vlan_enabled((struct bridging_vlan_args *)data);
	if (status)
		*value = "true";
	return 0;
}

static int set_br_vlan_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	int is_enabled;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			is_enabled = is_bridge_vlan_enabled((struct bridging_vlan_args *)data);
			if (b && !is_enabled) {
				update_br_vlan_ifname((struct bridging_vlan_args *)data, 1);
			}
			if (!b && is_enabled) {
				update_br_vlan_ifname((struct bridging_vlan_args *)data, 0);
			}
			return 0;
	}
	return 0;
}

static int get_br_vlan_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name(((struct bridging_vlan_args *)data)->bridge_vlan_sec));
	return 0;
}

static int set_br_vlan_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			 dmuci_rename_section_by_section(((struct bridging_vlan_args *)data)->bridge_vlan_sec, value);
			return 0;
	}
	return 0;
}

static int get_br_vlan_vid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	/* Fetch the vlan id from the ifname option of "network", "interface"  section. */
	char *ifname;
	dmuci_get_value_by_section_string(((struct bridging_vlan_args *)data)->bridge_vlan_sec, "ifname", &ifname);
	char tag[20] = {0};
	char *tok =  strtok(ifname, " ");
	while (tok != NULL) {
		char intf[250] = {0};
		strncpy(intf, tok, sizeof(intf) - 1);
		char *end;
		strtok_r(intf, ".", &end);
		if (end != NULL) {
			strncpy(tag, end, sizeof(tag) - 1);
			*value = dmstrdup(tag);
			break;
		}

		tok = strtok(NULL, " ");
	}

	return 0;
}

static int set_br_vlan_vid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *name, *ifname;
	struct uci_section *sec = NULL, *prev_s = NULL;
	struct bridging_vlan_args *vlan_args = (struct bridging_vlan_args *)data;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"1","4094"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			/* Set the value of vid in Bridging.Bridge.x.VLAN object. */
			dmuci_get_value_by_section_string(vlan_args->bridge_sec, "ifname", &ifname);
			char intf_name[250] = {0};
			if (*ifname == '\0') {
				/* Get the name of all ports from port UCI file. */
				struct uci_section *port_s = NULL;
				uci_foreach_option_eq("ports", "ethport", "enabled", "1", port_s) {
					char *intf;
					dmuci_get_value_by_section_string(port_s, "ifname", &intf);
					if (*intf != '\0') {
						if (intf_name[0] != '\0') {
							strcat(intf_name, " ");
						}
						strcat(intf_name, intf);
					}
				}
			} else {
				strncpy(intf_name, ifname, sizeof(intf_name) - 1);
			}

			struct uci_section *s;
			char *val;
			char intf_tag[250] = {0};

			/* If vid is 1 then add config device section in /etc/config/network file also. */
			char vid[50] = {0};
			strncpy(vid, value, sizeof(vid) - 1);

			char *end;
			char *token = strtok_r(intf_name, " ", &end);
			while (token != NULL) {
				char intf[50] = {0};
				strncpy(intf, token, sizeof(intf) - 1);
				char *tag;

				strtok_r(intf, ".", &tag);

				/* Remove all the config device section before setting the vlan id. */
				if (tag != NULL ) {
					char vlan_id[20] = {0};
					strncpy(vlan_id, tag, sizeof(vlan_id) - 1);
					if (strncmp(vlan_id, "1", sizeof(vlan_id)) == 0) {
						uci_foreach_option_eq("network", "device", "name", token, sec) {
							prev_s = sec;
							break;
						}
						if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);

					}
				}
				dmasprintf(&name, "%s.%s", intf, vid);

				if (strncmp(vid, "1", sizeof(vid)) == 0 ) {
					/* Create config device section. */
					dmuci_add_section_and_rename("network", "device", &s, &val);
					dmuci_set_value_by_section(s, "type", "untagged");
					if (tag != NULL) {
						dmuci_set_value_by_section(s, "ifname", tag);
					} else {
						dmuci_set_value_by_section(s, "ifname", intf);
					}
					dmuci_set_value_by_section(s, "name", name);
				}

				if (intf_tag[0] != '\0') {
					strcat(intf_tag, " ");
				}
				strcat(intf_tag, name);

				/* Remove vlanport section from dmmap_network file. */
				struct uci_section *s = NULL, *dmmap_section = NULL;
				char *tmp;
				int ret = 0;
				uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "ifname", token, s) {
					dmuci_get_value_by_section_string(s, "section_name", &tmp);
					ret = 1;
					break;
				}

				if (ret == 1) {
					get_dmmap_section_of_config_section("dmmap_network", "vlanport", tmp, &dmmap_section);
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				}

				token = strtok_r(NULL, " ", &end);
			}

			dmuci_set_value_by_section(vlan_args->bridge_sec, "ifname", intf_tag);

			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "section_name", section_name(vlan_args->bridge_sec), sec) {
				dmuci_set_value_by_section(sec, "vlan_id", value);
			}
	}
	return 0;
}

static int get_br_vlan_priority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct bridging_vlan_args *)data)->bridge_vlan_sec, "priority", value);
	return 0;
}

static int set_br_vlan_priority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct bridging_vlan_args *)data)->bridge_vlan_sec, "priority", value);
			return 0;
	}
	return 0;
}
/*************************************************************
* GET SET ALIAS
**************************************************************/
static int get_br_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridging_args *)data)->bridge_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "bridge_alias", value);
	return 0;
}

static int set_br_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridging_args *)data)->bridge_sec), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(dmmap_section, "bridge_alias", value);
			return 0;
	}
	return 0;
}

static int get_br_port_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridging_port_args *)data)->bridge_port_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "bridge_port_alias", value);
	if ((*value)[0] == '\0') {
		char *type;
		dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "type", &type);
		if (*type == '\0') {
			dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "name", value);
		} else {
			struct uci_section *s = NULL;
			dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "ifname", value);
			uci_foreach_option_eq("ports", "ethport", "ifname", *value, s) {
				dmuci_get_value_by_section_string(s, "name", value);
				break;
			}
		}
	}
	return 0;
}

static int set_br_port_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridging_port_args *)data)->bridge_port_sec), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(dmmap_section, "bridge_port_alias", value);
			return 0;
	}
	return 0;
}

static int get_br_vlan_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	/* Interface section needs to be browsed to get the value for vlan alias. */
	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridging_vlan_args *)data)->bridge_vlan_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "bridge_vlan_alias", value);
	return 0;
}

static int set_br_vlan_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridging_vlan_args *)data)->bridge_vlan_sec), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(dmmap_section, "bridge_vlan_alias", value);
			return 0;
	}
	return 0;
}

/*************************************************************
* ADD DELETE OBJECT
**************************************************************/
static int add_bridge(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *last_inst, *v;
	char bridge_name[16], ib[8];
	char *p = bridge_name;
	struct uci_section* dmmap_bridge = NULL;

	last_inst = get_last_instance_lev2_bbfdm("network", "interface", "dmmap_network", "bridge_instance", "type", "bridge");
	snprintf(ib, sizeof(ib), "%d", last_inst ? atoi(last_inst)+1 : 1);
	dmstrappendstr(p, "bridge_0_");
	dmstrappendstr(p, ib);
	dmstrappendend(p);
	dmuci_set_value("network", bridge_name, "", "interface");
	dmuci_set_value("network", bridge_name, "type", "bridge");
	/* Bridge should be created without specifying the proto.*/

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_bridge, &v);
	dmuci_set_value_by_section(dmmap_bridge, "section_name", bridge_name);
	*instance = update_instance_bbfdm(dmmap_bridge, last_inst, "bridge_instance");

	update_section_list(DMMAP,"bridge_port", "bridge_key", 1, ib, "mg_port", "true", "bridge_port_instance", "1");
	return 0;
}

static int delete_bridge(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *prev_s = NULL, *bridge_s, *dmmap_section = NULL;
	char *bridgekey = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridging_args *)data)->bridge_sec), &dmmap_section);
			dmuci_set_value_by_section(((struct bridging_args *)data)->bridge_sec, "type", "");
			dmuci_set_value_by_section(dmmap_section, "bridge_instance", "");
			dmuci_set_value_by_section(dmmap_section, "ip_int_instance", "");
			dmuci_set_value_by_section(dmmap_section, "ipv4_instance", "");
			uci_path_foreach_option_eq(bbfdm, "dmmap", "bridge_port", "bridge_key", ((struct bridging_args *)data)->br_key, s) {
				if (prev_s)
					DMUCI_DELETE_BY_SECTION(bbfdm, prev_s, NULL, NULL);
				prev_s = s;
			}
			if (prev_s)
				DMUCI_DELETE_BY_SECTION(bbfdm, prev_s, NULL, NULL);
			reset_br_port( ((struct bridging_args *)data)->br_key);
			dmuci_set_value_by_section(((struct bridging_args *)data)->bridge_sec, "ifname", "");
			break;
		case DEL_ALL:
			uci_foreach_option_eq("network", "interface", "type", "bridge", bridge_s) {
				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(bridge_s), &dmmap_section);
				dmuci_set_value_by_section(bridge_s, "type", "");
				dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &bridgekey);
				dmuci_set_value_by_section(dmmap_section, "bridge_instance", "");
				dmuci_set_value_by_section(dmmap_section, "ip_int_instance", "");
				dmuci_set_value_by_section(dmmap_section, "ipv4_instance", "");
				uci_path_foreach_option_eq(bbfdm, "dmmap", "bridge_port", "bridge_key", bridgekey, s) {
					prev_s = s;
				}
				if (prev_s)
					DMUCI_DELETE_BY_SECTION(bbfdm, prev_s, NULL, NULL);
				reset_br_port(bridgekey);
				dmuci_set_value_by_section(bridge_s, "ifname", "");
			}
			break;
	}
	return 0;
}

static int get_vlanport_last_inst(char *br_key)
{
	char *tmp;
	int instance, max = 0;
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "bridge_key", br_key, s) {
		dmuci_get_value_by_section_string(s, "vport_inst", &tmp);
		if (tmp[0] == '\0')
			continue;
		instance = atoi(tmp);
		if (instance > max) max = instance;
	}
	return max;
}

static int add_br_vlanport(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *v, *name;

	/* To add Bridge.VLANPort object from the management methods. */
	struct bridging_args *br_args = (struct bridging_args *)data;
	char *br_ifname_list, *br_ifname_dup, *pch = NULL, *spch = NULL;

	/* Check if the section name has tagged ifname or not. */
	dmuci_get_value_by_section_string(br_args->bridge_sec, "ifname", &br_ifname_list);


	if(br_ifname_list[0] != '\0') {
		/* Check if the ifname is tagged or not , if not tagged replace it with a tag of 1. */
		br_ifname_dup = dmstrdup(br_ifname_list);
		for (pch = strtok_r(br_ifname_dup, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			int is_present = 0;
			if (strstr(pch, ".") == NULL) {
				continue;
			} else {
				/* Check if the vlanport section is not present for the interface. */
				struct uci_section *s = NULL;
				uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "ifname", pch, s) {
					is_present = 1;
					break;
				}

				if (is_present == 0) {
					/* Add vlanport section in dmmap_network. */
					struct uci_section *dmmap_port;
					dmuci_add_section_bbfdm("dmmap_network", "vlanport", &dmmap_port, &v);
					dmuci_set_value_by_section(dmmap_port, "bridge_key", br_args->br_key);

					/* Get the last vlan_instance and add one. */
					int m = get_vlanport_last_inst(br_args->br_key);
					char instance[10] = {0};
					snprintf(instance, sizeof(instance), "%d", m+1);
					dmuci_set_value_by_section(dmmap_port, "vport_inst", instance);
					dmasprintf(&name, "%s_%d", "vlanport", m);
					dmuci_set_value_by_section(dmmap_port, "section_name", name);
					dmuci_set_value_by_section(dmmap_port, "ifname", pch);
				}
			}
		}
	}

	/* Add vlanport section in dmmap_network. */
	struct uci_section *dmmap_port;
	dmuci_add_section_bbfdm("dmmap_network", "vlanport", &dmmap_port, &v);
	dmuci_set_value_by_section(dmmap_port, "bridge_key", br_args->br_key);

	/* Get the vlan port instance. */
	int m = get_vlanport_last_inst(br_args->br_key);
	char inst[10] = {0};
	snprintf(inst, sizeof(inst), "%d", m+1);
	dmuci_set_value_by_section(dmmap_port, "vport_inst", inst);
	dmasprintf(&name, "%s_%d", "vlanport", m);
	dmuci_set_value_by_section(dmmap_port, "section_name", name);
	dmasprintf(instance, "%d", m+1);

	return 0;
}

static int remove_ifname_from_uci(char *ifname, void *data, char *nontag_name)
{
	struct bridging_args *br_args = (struct bridging_args *)data;
	char *br_ifname_list;
	char new_ifname[250] = {0};
	char intf[50] = {0};

	dmuci_get_value_by_section_string(br_args->bridge_sec, "ifname", &br_ifname_list);

	strncpy(intf, ifname, sizeof(intf) - 1);

	char *tok =  strtok(br_ifname_list, " ");
	while (tok != NULL) {
		if (strncmp(intf, tok, sizeof(intf)) != 0) {
			if (new_ifname[0] != '\0') {
				strcat(new_ifname, " ");
			}
			strcat(new_ifname, tok);
		} else {
			if (new_ifname[0] != '\0') {
				strcat(new_ifname, " ");
			}
			strcat(new_ifname, nontag_name);
		}
		tok = strtok(NULL, " ");
	}

	dmuci_set_value_by_section(br_args->bridge_sec, "ifname", new_ifname);

	return 0;
}

static int delete_br_vlanport(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	/* To delete Bridge.VLANPort object from the management methods. */
	struct bridging_args *br_args = (struct bridging_args *)data;
	char *br_ifname_list = NULL, *br_ifname_dup = NULL, *pch = NULL, *spch =  NULL;
	struct uci_section *sec = NULL, *s = NULL, *vport_sec = NULL, *prev_s = NULL;
	char new_ifname[250] = {0};
	int inst_found  = 0;
	char *name;

	switch (del_action) {
		case DEL_INST:
			/* Get the Port associated with it. */
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "bridge_key", br_args->br_inst, s) {
				/* Fetch and compare the vlan port instance with the instance we got. */
				char *inst;
				dmuci_get_value_by_section_string(s, "vport_inst", &inst);
				char v_instance[10] = {0};
				strncpy(v_instance, instance, sizeof(v_instance) - 1);
				if (strncmp(v_instance, inst, sizeof(v_instance)) != 0)
					continue;

				inst_found = 1;
				/* Check if ifname is present or not. */
				char *ifname;
				dmuci_get_value_by_section_string(s, "ifname", &ifname);
				if (*ifname != '\0') {
					char intf[250] = {0};
					strncpy(intf, ifname, sizeof(intf) - 1);

					char *tag;
					strtok_r(intf, ".", &tag);
					if (tag != NULL) {
						/* Remove the tag in ifname from UCI file.*/
						remove_ifname_from_uci(ifname, data, intf);

						/* Check if the tag is 1 or not. */
						char vid[10] = {0};
						strncpy(vid, tag, sizeof(vid) - 1);

						if (strncmp(vid, "1", sizeof(vid)) == 0) {
							/* Remove the config device section. */
							uci_foreach_option_eq("network", "device", "name", ifname, sec) {
								prev_s = sec;
								break;
							}
							if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
						}
					}
				}
			}
			/* Remove the vlan port dmmap section. */
			if (inst_found == 1) {
				int id = atoi(instance);
				dmasprintf(&name, "%s_%d", "vlanport", (id - 1));
				get_dmmap_section_of_config_section("dmmap_network", "vlanport", name, &vport_sec);
				dmuci_delete_by_section(vport_sec, NULL, NULL);
			}
			int v_last = get_vlanport_last_inst(br_args->br_inst);
			int j = 0;
			int val = atoi(instance) + 1;
			for (j = val; j <= v_last; j++) {
				dmasprintf(&name, "%s_%d", "vlanport", (j - 1));
				get_dmmap_section_of_config_section("dmmap_network", "vlanport", name, &vport_sec);
				char inst_val[10] = {0};
				snprintf(inst_val, sizeof(inst_val), "%d", (j-1));
				dmuci_set_value_by_section(vport_sec, "vport_inst", inst_val);
				char *v_name;
				dmasprintf(&v_name, "%s_%d", "vlanport", (j - 2));
				dmuci_set_value_by_section(vport_sec, "section_name", v_name);
			}
			break;
		case DEL_ALL:
			/* Check if the section name has tagged ifname or not. */
			dmuci_get_value_by_section_string(br_args->bridge_sec, "ifname", &br_ifname_list);

			if(br_ifname_list[0] != '\0') {
				br_ifname_dup = dmstrdup(br_ifname_list);
			}

			if (*br_ifname_dup == '\0') {
				return -1;
			}

			/* Check if the ifname is tagged or not, if yes then remove the tag. */
			for (pch = strtok_r(br_ifname_dup, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
				char pch_tag[20] = {0};
				strncpy(pch_tag, pch, sizeof(pch_tag) - 1);

				if (strstr(pch_tag, ".") == NULL) {
					if( new_ifname[0] != '\0') {
						strcat(new_ifname, " ");
					}
					strcat(new_ifname, pch);
				} else {
					/* Remove the tag. */
					char name[50] = {0};
					strncpy(name, pch, sizeof(name) - 1);
					char *tag_id;
					char *tag = strtok_r(name, ".", &tag_id);
					if (tag != NULL) {
						if( new_ifname[0] != '\0') {
							strcat(new_ifname, " ");
						}
						strcat(new_ifname, tag);
					}
					if (tag_id != NULL) {
						/* Check if the tag_id is 1, then remove the device section. */
						char if_tag[20] = {0};
						strncpy(if_tag, tag_id, sizeof(if_tag) - 1);

						if(strncmp(if_tag, "1", sizeof(if_tag)) == 0) {
							uci_foreach_option_eq("network", "device", "name", pch, sec) {
								prev_s = sec;
								break;
							}
							if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
						}
					}
				}
			}
			dmuci_set_value_by_section(br_args->bridge_sec, "ifname", new_ifname);

			/* Remove all dmmap VLANPort section. */
			int m = get_vlanport_last_inst(br_args->br_key);
			struct uci_section *s;
			int i;
			for (i = 0; i < m; i++) {
				dmasprintf(&name, "%s_%d", "vlanport", i);
				get_dmmap_section_of_config_section("dmmap_network", "vlanport", name, &s);
				dmuci_delete_by_section(s, NULL, NULL);
			}
			break;
		}

	return 0;
}

static int add_br_vlan(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	/* To add Bridge.VLAN object from the management methods. */
	char *v, *name;
	struct uci_section *sec =  NULL, *dmmap_bridge_vlan =  NULL;

	check_create_dmmap_package("dmmap_network");

	/* Check if section_name exists with specified bridge_key. */
	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "section_name", section_name(((struct bridging_args *)data)->bridge_sec), sec) {
		/* If section exists, create new vlan instance. */
		dmuci_add_section_bbfdm("dmmap_network", "vlan", &dmmap_bridge_vlan, &v);
		dmasprintf(&name, "%s_%s", "vlan", ((struct bridging_args *)data)->br_inst );
		dmuci_set_value_by_section(dmmap_bridge_vlan, "section_name", name);
		dmuci_set_value_by_section(dmmap_bridge_vlan, "bridge_instance", ((struct bridging_args *)data)->br_inst);
		dmuci_set_value_by_section(dmmap_bridge_vlan, "bridge_key", ((struct bridging_args *)data)->br_key);
	}
	return 0;
}

static int delete_br_vlan(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	/* To delete Bridge.VLAN object from the management methods. */
	char *type;
	struct uci_section *prev_s = NULL, *vlan_s = NULL, *dmmap_section = NULL;
	int is_enabled;

	switch (del_action) {
	case DEL_INST:
		is_enabled = is_bridge_vlan_enabled((struct bridging_vlan_args *)data);
		if(is_enabled) {
			update_br_vlan_ifname((struct bridging_vlan_args *)data, 0);
		}
		get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct bridging_vlan_args *)data)->bridge_vlan_sec), &dmmap_section);
		if (dmmap_section) dmuci_delete_by_section(dmmap_section, "bridge_vlan_instance", NULL);
		break;
	case DEL_ALL:
		uci_foreach_sections("network", "interface", vlan_s) {
			dmuci_get_value_by_section_string(vlan_s, "type", &type);
			if (*type == '\0' || strcmp(type, "untagged") == 0)
				continue;

			if (prev_s != NULL){
				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(prev_s), &dmmap_section);
				if (dmmap_section) dmuci_delete_by_section(dmmap_section, "bridge_vlan_instance", NULL);
			}
			prev_s = vlan_s;
		}
		if (prev_s != NULL){
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(prev_s), &dmmap_section);
			if (dmmap_section) dmuci_delete_by_section(dmmap_section, "bridge_vlan_instance", NULL);
		}
		break;
	}

	/* Update the ifname section in network file. */
	char *br_ifname_list;
	char final_list[250] = {0};
	dmuci_get_value_by_section_string(((struct bridging_args *)data)->bridge_sec, "ifname", &br_ifname_list);
	char *end;
	char *tok =  strtok_r(br_ifname_list, " ", &end);
	while (tok != NULL) {
		char intf[20] = {0};
		strncpy(intf, tok, sizeof(intf) - 1);
		char *end2;
		char *tag = strtok_r(tok, ".", &end2);
		if (tag != NULL) {
			char vid[10] = {0};
			strncpy(vid, end2, sizeof(vid) - 1);
			if (strncmp(vid, "1", sizeof(vid)) == 0) {
				/* Remove the config device section. */
				struct uci_section *sec = NULL, *prev_s = NULL;
				uci_foreach_option_eq("network", "device", "name", intf, sec) {
					prev_s = sec;
					break;
				}
				if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
			}

			/* Remove the vlanport instance from the dmmap_network file. */
			struct uci_section *vport_s = NULL;
			char *sec_name;
			int ret = 0;
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "ifname", intf, vport_s) {
				dmuci_get_value_by_section_string(vport_s, "section_name", &sec_name);
				ret = 1;
				break;
			}

			if (ret == 1) {
				get_dmmap_section_of_config_section("dmmap_network", "vlanport", sec_name, &vport_s);
				dmuci_delete_by_section(vport_s, NULL, NULL);
			}

			if (final_list[0] != '\0') {
				strcat(final_list, " ");
			}
			strcat(final_list, tag);
		}
		tok = strtok_r(NULL, " ", &end);
	}
	dmuci_set_value_by_section(((struct bridging_args *)data)->bridge_sec, "ifname", final_list);

	/* Remove the vlan instance from the dmmap_network file. */
	char *name;
	dmasprintf(&name, "%s_%s", "vlan", ((struct bridging_vlan_args *)data)->br_inst);
	get_dmmap_section_of_config_section("dmmap_network", "vlan", name, &dmmap_section);
	dmuci_delete_by_section(dmmap_section, NULL, NULL);

	return 0;
}

static int add_br_port(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value;
	struct uci_section *br_port_s;

	int m = get_br_port_last_inst(((struct bridging_args *)data)->br_key);
	dmasprintf(instance, "%d", m+1);
	DMUCI_ADD_SECTION(bbfdm, "dmmap_bridge_port", "bridge_port", &br_port_s, &value);
	dmuci_set_value_by_section(br_port_s, "bridge_key", ((struct bridging_args *)data)->br_key);
	dmuci_set_value_by_section(br_port_s, "bridge_port_instance", *instance);
	dmuci_set_value_by_section(br_port_s, "mg_port", "false");
	return 0;
}

static int delete_br_port(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	char *ifname;
	char new_ifname[128];
	struct uci_section *s = NULL, *prev_s = NULL, *dmmap_section= NULL;

	switch (del_action) {
	case DEL_INST:
		get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridging_port_args *)data)->bridge_port_sec), &dmmap_section);
		if (!dmmap_section) {
			dmmap_section = ((struct bridging_port_args *)data)->bridge_port_sec;
			dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
		} else {
			dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_sec, "ifname", &ifname);
			if (ifname[0] != '\0') {
				remove_interface_from_ifname(((struct bridging_port_args *)data)->ifname, ifname, new_ifname);
				dmuci_set_value_by_section(((struct bridging_port_args *)data)->bridge_sec, "ifname", new_ifname);
			}
			get_dmmap_section_of_config_section("dmmap_bridge_port", "bridge_port", section_name(((struct bridging_port_args *)data)->bridge_port_sec), &dmmap_section);
			dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
		}
		break;
	case DEL_ALL:
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", ((struct bridging_args *)data)->br_key, s) {
			if (prev_s)
				DMUCI_DELETE_BY_SECTION(bbfdm, prev_s, NULL, NULL);
			prev_s = s;
		}
		if (prev_s)
			DMUCI_DELETE_BY_SECTION(bbfdm, prev_s, NULL, NULL);
		dmuci_set_value_by_section(((struct bridging_args *)data)->bridge_sec, "ifname", ""); // TO CHECK
		break;
	}
	return 0;
}

/*************************************************************
* LOWER LAYER
**************************************************************/
static int check_port_with_ifname (char *ifname, struct uci_section **ss, int *is_tag)
{
	struct uci_section *sss = NULL, *s = NULL;
	char *atm_device, *ptm_device;

	if (strncmp(ifname, "ptm", 3) == 0) {
		if (access("/etc/config/dsl", F_OK) != -1) {
			uci_foreach_sections("dsl", "ptm-device", sss) {
				dmuci_get_value_by_section_string(sss, "device", &ptm_device);
				dmasprintf(&ptm_device, "%s.1", ptm_device);
				if (strcmp(ifname, ptm_device) == 0) {
					uci_foreach_option_eq("network", "device", "name", ifname, s) {
						*ss = s;
						break;
					}
				}
			}
		}
	} else if (strncmp(ifname, "atm", 3) == 0) {
		if (access("/etc/config/dsl", F_OK) != -1) {
			uci_foreach_sections("dsl", "atm-device", sss) {
				dmuci_get_value_by_section_string(sss, "device", &atm_device);
				dmasprintf(&atm_device, "%s.1", atm_device);
				if (strcmp(ifname, atm_device) == 0) {
					uci_foreach_option_eq("network", "device", "name", ifname, s) {
						*ss = s;
						break;
					}
				}
			}
		}
	} else if (strncmp(ifname, wan_baseifname, strlen(ifname)) == 0) {
		/* For wan, no entry will be found in "network", "device".
		 * Entry for untagged interfaces would be there. */
		uci_foreach_option_eq("ports", "ethport", "ifname", ifname, s) {
			*ss = s;
			break;
		}
	} else if (strncmp(ifname, "wl", 2) == 0 || strncmp(ifname, "ra", 2) == 0 || strncmp(ifname, "apclii", 6) == 0) {
		uci_foreach_option_eq("wireless", "wifi-iface", "ifname", ifname, s) {
			*ss = s;
			break;
		}
	} else {
		/* Add support for untagged interfaces(vlan id =1) in lower layer. */
		char intf[50] = {0};
		strncpy(intf, ifname, sizeof(intf) - 1);
		char *p = strstr(intf, ".");
		if (p) {
			char *token , *end= NULL;
			token = strtok_r(intf, ".", &end);
			if (NULL != token) {
				char tag[50] = {0};
				strncpy(tag, end, sizeof(tag) - 1);
				if (strncmp(tag, "1", sizeof(tag)) == 0) {
					uci_foreach_option_eq("network", "device", "name", ifname, s) {
						*ss = s;
						break;
					}
				} else {
					/* Add support for tagged interfaces in lower layer. */
					uci_foreach_option_eq("ports", "ethport", "ifname", token, s) {
						*is_tag = 1;
						*ss = s;
						break;
					}
				}
			}
		} else {
			uci_foreach_option_eq("ports", "ethport", "ifname", ifname, s) {
				*ss = s;
				break;
			}
		}
	}
	return 0;
}

static int get_port_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mg_port, *pch, *spch, *ifname, *ifname_dup, *p, *linker = "";
	char buf[16], plinker[32], lbuf[512] = { 0, 0 };
	struct uci_section *s = NULL;

	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "mg_port", &mg_port);
	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_sec, "ifname", &ifname);
	if (ifname[0] != '\0' && strcmp(mg_port, "true") ==  0) {
		ifname_dup = dmstrdup(ifname);
		p = lbuf;
		for (pch = strtok_r(ifname_dup, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			/* Added support for tagged and untagged interfaces. */
			int is_tag = 0;
			check_port_with_ifname(pch, &s, &is_tag);
			if (s == NULL)
				continue;
			snprintf(plinker, sizeof(plinker), "%s+%s", section_name(s), pch);
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), plinker, value);
			if (*value == NULL)
				*value = "";
			dmstrappendstr(p, *value);
			dmstrappendchr(p, ',');
		}
		p = p -1;
		dmstrappendend(p);
		*value = dmstrdup(lbuf);
		return 0;
	} else {
		dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "ifname", &linker);
		if (strcmp(linker, wan_baseifname) == 0) {
			dmasprintf(&linker, "%s.1", linker);
		}
		if(((struct bridging_port_args *)data)->vlan) {
			strncpy(buf, linker, 5);
			buf[5] = '\0';
			strcat(buf, "1");
			linker = buf;
		}
	}
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

static void set_bridge_port_parameters(struct uci_section *dmmap_section, char* bridge_key)
{
	char *br_key;
	char *name;
	dmuci_get_value_by_section_string(dmmap_section, "bridge_key", &br_key);
	dmuci_get_value_by_section_string(dmmap_section, "section_name", &name);
	if (*br_key != '\0') {
		/* Check if the bridge_key of the dmmap_section same as the bridge_key. */
		if (strcmp(br_key, bridge_key) == 0) {
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "bridge_key", bridge_key);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "mg_port", "false");
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "penable", "1");
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "is_dmmap", "false");
		} else {
			/* Find out the dmmap_section with the specified bridge_key and add
			 * the values to it. */
			struct uci_section *br_s;
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", bridge_key, br_s) {
				/* Fetch the section name. */
				char *sec_name;
				dmuci_get_value_by_section_string(br_s, "section_name", &sec_name);
				if (strcmp(sec_name, name) == 0) {
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, br_s, "bridge_key", bridge_key);
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, br_s, "mg_port", "false");
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, br_s, "penable", "1");
					DMUCI_SET_VALUE_BY_SECTION(bbfdm, br_s, "is_dmmap", "false");
				}
			}
		}
	} else {
		/* If the bridge key is not found in the dmmap section, then set the
		 * attributes under the section. */
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "bridge_key", bridge_key);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "mg_port", "false");
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "penable", "1");
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "is_dmmap", "false");
	}
}

static int set_port_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	/* Set lower layer value from management methods. */
	char *linker_intf, *br_key;
	char *newvalue = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (value[strlen(value)-1] != '.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker_intf);
			} else {
				adm_entry_get_linker_value(ctx, value, &linker_intf);
			}

			/* If linker value is untagged wan, then change it to wan. */
			char *linker =  NULL;
			char if_name[20] = {0};
			char intf[20] = {0};
			strncpy(intf, linker_intf, sizeof(intf) - 1);

			/* Get the upstream interface. */
			char intf_tag[50] = {0};
			/* Get the upstream interface. */
			get_upstream_interface(intf_tag, sizeof(intf_tag));

			/* Create untagged upstream interface. */
			if (intf_tag[0] != '\0')
				strcat(intf_tag, ".1");

			if (strncmp(intf, intf_tag, sizeof(intf)) == 0) {
				char *tok = strtok(intf, ".");
				if (tok != NULL) {
					strncpy(if_name, tok, sizeof(if_name) - 1);
					linker = if_name;
				}
			} else {
				strncpy(if_name, linker_intf, sizeof(if_name) - 1);
				linker = if_name;
			}

			/* Check if the ifname is present in the network UCI file under the bridge section name
			 * obtained from the refparam. */
			if (linker && check_ifname_exist_in_br_ifname_list(linker, section_name(((struct bridging_port_args *)data)->bridge_sec))) {
				// Do nothing
			} else {
				/* Fetch the value of ifname from the UCI. */
				char *name;
				dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_sec, "ifname", &name);

				/* Fetch the bridge key associated with the ifname. */
				dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_port_sec, "bridge_key", &br_key);

				char intf_name[250] = {0};
				strncpy(intf_name, name, sizeof(intf_name) - 1);
				/* Append the interface name to it. */
				if (intf_name[0] != '\0') {
					strcat(intf_name, " ");
				}
				strcat(intf_name, linker);

				synchronize_multi_config_sections_with_dmmap_set("ports", "ethport", "dmmap_bridge_port", "bridge_port", "ifname", linker, instance, br_key);

				dmuci_set_value_by_section(((struct bridging_port_args *)data)->bridge_sec, "ifname", intf_name);
			}
			return 0;
		}
	return 0;
}

static int get_vlan_port_vlan_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = 1; // For now this will only work for Bridges with 1 VLAN only
	char linker[8];
	snprintf(linker, sizeof(linker),"vlan%d_%s", cnt, ((struct bridging_vlan_args *)data)->br_inst);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_vlan_port_vlan_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			return 0;
	}
	return 0;
}

static int get_vlan_port_port_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int cnt = 1;
	char *pch, *spch, *ifname;
	char plinker[32];
	struct uci_section *s = NULL;

	dmuci_get_value_by_section_string(((struct bridging_port_args *)data)->bridge_sec, "ifname", &ifname);
	if (ifname[0] != '\0') {
		for (pch = strtok_r(ifname, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			if (cnt == atoi(instance)) {
				/* Added support for tagged and untagged interfaces. */
				int is_tag = 0;
				check_port_with_ifname(pch, &s, &is_tag);
				if (s == NULL)
					continue;

				snprintf(plinker, sizeof(plinker), "%s+%s", section_name(s), pch);
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), plinker, value);
				if (*value == NULL)
					*value = "";
				break;
			} else {
				cnt++;
			}
		}
	} else {
		*value = "";
	}

	return 0;
}

static int set_vlan_port_port_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL, *newvalue;
	struct bridging_args *br_args = (struct bridging_args *)data;
	struct uci_section *s, *sec;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (value[strlen(value)-1] != '.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else {
				adm_entry_get_linker_value(ctx, value, &linker);
			}

			if (!linker)
				return -1;

			/* Get the interface name from linker. */
			char intf[50] = {0};
			char *p = strstr(linker, "+");
			if (p)
				strncpy(intf, p+1, sizeof(intf) - 1);
			else
				return -1;

			/* Using bridge key, check if vlan port instance exists in vlan port dmmap. */
			int ret = 0;
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "bridge_key", br_args->br_inst, s) {
				char *tmp;
				dmuci_get_value_by_section_string(s, "vport_inst", &tmp);

				char inst[10] = {0};
				strncpy(inst, instance, sizeof(inst) - 1);

				if (strncmp(inst, tmp, sizeof(inst)) == 0) {
					ret = 1;
					break;
				}
			}

			if (ret == 0)
				return -1;

			/* Get vlan_id from interface section using bridge_key. */
			char *vlan_id;
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "bridge_key", br_args->br_inst, sec) {
				dmuci_get_value_by_section_string(sec, "vlan_id", &vlan_id);
			}

			if (*vlan_id == '\0')
				return -1;

			/* Combine vid wd linker. */
			char new_if[64] = {0};
			snprintf(new_if, sizeof(new_if), "%s.%s", intf, vlan_id);

			/* Check if the new name is present in UCI. If yes do nothing, if no
			 * then update vlanport and UCI wd new ifname.*/
			char *br_ifname;
			dmuci_get_value_by_section_string(((struct bridging_args *)data)->bridge_sec, "ifname", &br_ifname);

			char new_ifname[250] = {0};
			char *tok, *end;
			tok = strtok_r(br_ifname, " ", &end);
			while (tok != NULL) {
				/* check if intf matches with tok. */
				if (strncmp(intf, tok, sizeof(intf)) == 0) {
					/* Check if tok and new_if are same or not. */
					if (strncmp(new_if, tok, sizeof(new_if)) == 0) {
						/* Do nothing. */
					} else {
						/* Check the vid of existing ifname, and remove
						 * the config device section if vid is one.
						 * Also update the ifname wd new name. */
						char if_tag[10] = {0};
						strncpy(if_tag, tok, sizeof(if_tag) - 1);

						char *tag;
						strtok_r(if_tag, ".", &tag);
						if (tag != NULL) {
							char vid[10] = {0};
							strncpy(vid, tag, sizeof(vid) - 1);

							if (strncmp(vid, "1", sizeof(vid)) == 0) {
								/* remove device section. */
								struct uci_section *sec = NULL, *prev_s = NULL;
								uci_foreach_option_eq("network", "device", "name", tok, sec) {
									prev_s = sec;
									break;
								}
								if (prev_s) dmuci_delete_by_section(prev_s, NULL, NULL);
							}
						}
						if (new_ifname[0] != '\0') {
							strcat(new_ifname, " ");
						}
						strcat(new_ifname, new_if);

						/* Add ifname to vlanport section in dmmap. */
						uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "vport_inst", instance, sec) {
							dmuci_set_value_by_section(sec, "ifname", new_if);
						}

						/* IF vlan id fro the new ifname is 1, then add device section.*/
						char vd[10] = {0};
						char *val;
						strncpy(vd, vlan_id, sizeof(vd) - 1);

						if (strncmp(vd, "1", sizeof(vd)) == 0) {
							dmuci_add_section_and_rename("network", "device", &sec, &val);
							dmuci_set_value_by_section(sec, "name", new_if);
							dmuci_set_value_by_section(sec, "type", "untagged");
							dmuci_set_value_by_section(sec, "ifname", intf);
						}
					}
				} else {
					if (new_ifname[0] != '\0') {
						strcat(new_ifname, " ");
					}
					strcat(new_ifname, tok);
				}
				tok = strtok_r(NULL, " ", &end);
			}

			dmuci_set_value_by_section(((struct bridging_args *)data)->bridge_sec, "ifname", new_ifname);
			break;
	}
	return 0;
}

static int get_br_vlan_untagged(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_br_vlan_untagged(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.Bridging.Bridge.{i}.!UCI:network/interface/dmmap_network*/
static int browseBridgeInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *br_inst = NULL, *br_inst_last = NULL, *ifname;
	struct bridging_args curr_bridging_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	dmuci_get_option_value_string("ports", "WAN", "ifname", &wan_baseifname);

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


static int browseBridgePortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance){
	struct uci_section *new_port = NULL, *ss_atm = NULL, *ss_ptm = NULL;
	char *port = NULL, *port_last = NULL, *ifname_dup = NULL, *pch = NULL, *spch = NULL, *is_dmmap, *deviceatm, *deviceptm, *atm_device, *ptm_device;
	bool find_max = true, found = false;
	struct bridging_port_args curr_bridging_port_args = {0};
	struct dmmap_dup *p = NULL;
	LIST_HEAD(dup_list);

	check_create_dmmap_package("dmmap_bridge_port");
	update_section_list_bbfdm("dmmap_bridge_port","bridge_port", "bridge_key", 1, ((struct bridging_args *)prev_data)->br_key, "mg_port", "true", "bridge_port_instance", "1");
	uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", ((struct bridging_args *)prev_data)->br_key, new_port) {
		dmuci_get_value_by_section_string(new_port, "is_dmmap", &is_dmmap);
		if (strcmp(is_dmmap, "false") != 0) {
			init_bridging_port_args(&curr_bridging_port_args, new_port, ((struct bridging_args *)prev_data)->bridge_sec, false, "");
			port = handle_update_instance(2, dmctx, &port_last, update_instance_alias_bbfdm, 5, new_port, "bridge_port_instance", "bridge_port_alias",  &find_max, ((struct bridging_args *)prev_data)->br_key);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_port_args, port) == DM_STOP)
				goto end;
		}
	}

	if (((struct bridging_args *)prev_data)->ifname[0] == '\0')
		return 0;

	ifname_dup = dmstrdup(((struct bridging_args *)prev_data)->ifname);
	for (pch = strtok_r(ifname_dup, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
		found = false;

		if (!found) {
			/*  Add support for untagged interfaces.*/
			char val[50] = {0};
			strncpy(val, pch, sizeof(val) - 1);
			char *p = strstr(val, ".");
			if (p) {
				char *tok, *tok_end;
				tok = strtok_r(val, ".", &tok_end);
				if (tok != NULL) {
					char tag[20] = {0};
					strncpy(tag, tok_end, sizeof(tag) - 1);
					if (strncmp(tag, "1", sizeof(tag)) == 0) {
						found = synchronize_multi_config_sections_with_dmmap_eq("network", "device", "dmmap_bridge_port", "bridge_port", "name", pch, pch, &dup_list);
					} else {
						/* Add support for tagged interfaces(eth0.100, eth1.200 etc).*/
						found = synchronize_multi_config_sections_with_dmmap_eq("ports", "ethport", "dmmap_bridge_port", "bridge_port", "ifname", tok, pch, &dup_list);
					}
				}
			} else {
				/* Add support for interfaces eth0, eth1, eth2.....etc.*/
				found = synchronize_multi_config_sections_with_dmmap_port("ports", "ethport", "dmmap_bridge_port", "bridge_port", "ifname", pch, pch, &dup_list, ((struct bridging_args *)prev_data)->br_key);
			}
		}

		if (!found)
			found = synchronize_multi_config_sections_with_dmmap_eq("wireless", "wifi-iface", "dmmap_bridge_port", "bridge_port", "ifname", pch, pch, &dup_list);

		if (access("/etc/config/dsl", F_OK) != -1) {
			uci_foreach_sections("dsl", "atm-device", ss_atm) {
				dmuci_get_value_by_section_string(ss_atm, "device", &deviceatm);
				dmasprintf(&atm_device, "%s.1", deviceatm);
				if (!found) {
					if (strncmp(pch, atm_device, strlen(atm_device)) == 0) {
						found = synchronize_multi_config_sections_with_dmmap_eq("network", "device", "dmmap_bridge_port", "bridge_port", "name", pch, pch, &dup_list);
					}
				}
			}

			uci_foreach_sections("dsl", "ptm-device", ss_ptm) {
				dmuci_get_value_by_section_string(ss_ptm, "device", &deviceptm);
				dmasprintf(&ptm_device, "%s.1", deviceptm);
				if (!found) {
					if (strncmp(pch, ptm_device, strlen(ptm_device)) == 0) {
						found = synchronize_multi_config_sections_with_dmmap_eq("network", "device", "dmmap_bridge_port", "bridge_port", "name", pch, pch, &dup_list);
					}
				}
			}
		}

		if (!found) {
			if (strncmp(pch, wan_baseifname, strlen(wan_baseifname))==0) {
				found = synchronize_multi_config_sections_with_dmmap_eq("network", "device", "dmmap_bridge_port", "bridge_port", "name", pch, pch, &dup_list);
			}
		}

		if (!found) {
			if (strncmp(pch, wan_baseifname, 4) == 0 || strncmp(pch, "ptm", 3) == 0 || strncmp(pch, "atm", 3) == 0) {
				found = synchronize_multi_config_sections_with_dmmap_eq_diff("network", "device", "dmmap_bridge_port", "bridge_port", "name", pch, "type", "untagged", pch, &dup_list);
			}
		}
	}

	list_for_each_entry(p, &dup_list, list) {
		set_bridge_port_parameters(p->dmmap_section, ((struct bridging_args *)prev_data)->br_key);
		init_bridging_port_args(&curr_bridging_port_args, p->config_section, ((struct bridging_args *)prev_data)->bridge_sec, false, (char*)p->additional_attribute);
		port = handle_update_instance(2, dmctx, &port_last, update_instance_alias_bbfdm, 5, p->dmmap_section, "bridge_port_instance", "bridge_port_alias", &find_max, ((struct bridging_args *)prev_data)->br_key);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_port_args, port) == DM_STOP)
			goto end;
	}
end:
	free_dmmap_config_dup_list(&dup_list);
	dmfree(ifname_dup);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.VLAN.!UCI:network/device/dmmap_network*/
static int browseBridgeVlanInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *vlan = NULL, *vlan_last = NULL;
	struct bridging_vlan_args curr_bridging_vlan_args = {0};
	struct bridging_args *br_args = (struct bridging_args *)prev_data;
	struct dmmap_dup *p = NULL;
	struct uci_section *sec = NULL, *section = NULL;
	int count = 0;
	char id;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_vlan("network", "interface", "dmmap_network", br_args->ifname, &dup_list, &count, &id);
	/* To add bridge object and lower layer through management method. */
	if (count != 0) {
		list_for_each_entry(p, &dup_list, list) {
			if (!p->config_section)
				goto end;

			dmuci_set_value_by_section(p->dmmap_section, "bridge_key", br_args->br_key);
			dmuci_set_value_by_section(p->dmmap_section, "vlan_id", &id);
			vlan =  handle_update_instance(2, dmctx, &vlan_last, update_instance_alias, 3, p->dmmap_section, "bridge_vlan_instance", "bridge_vlan_alias");
			init_bridging_vlan_args(&curr_bridging_vlan_args, p->config_section, br_args->bridge_sec, vlan_last, br_args->br_key);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_vlan_args, vlan) == DM_STOP)
				goto end;
		}
	} else {
		/* Check if config vlan section is present in the dmmap_network. */
		uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlan", "bridge_instance", br_args->br_inst, sec) {
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "bridge_instance", br_args->br_inst, section) {
				dmuci_set_value_by_section(section, "bridge_key", br_args->br_key);
				vlan =  handle_update_instance(2, dmctx, &vlan_last, update_instance_alias, 3, section, "bridge_vlan_instance", "bridge_vlan_alias");
				init_bridging_vlan_args(&curr_bridging_vlan_args, section, br_args->bridge_sec, vlan_last, br_args->br_key);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_vlan_args, vlan) == DM_STOP)
					goto end;
			}
		}
	}
end:
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.Bridging.Bridge.{i}.VLANPort.!UCI:network/device/dmmap_network*/
static int browseBridgeVlanPortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int cnt = 1;
	char *vlan;
	char *br_ifname_list, *br_ifname_dup, *pch = NULL, *spch = NULL;
	struct bridging_vlan_args curr_bridging_vlan_args = {0};
	struct bridging_args *br_args = (struct bridging_args *)prev_data;
	struct uci_section *sec = NULL;

	dmuci_get_value_by_section_string(br_args->bridge_sec, "ifname", &br_ifname_list);

	if(br_ifname_list[0] == '\0') {
		/* Check if dmmap vlanport section is present. If present create link for it
		 * with empty fileds. */
		uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "bridge_key", br_args->br_key, sec) {
			char *tmp;
			dmuci_get_value_by_section_string(sec, "ifname", &tmp);
			if (*tmp == '\0') {
				dmasprintf(&vlan, "%d", cnt);
				init_bridging_vlan_args(&curr_bridging_vlan_args, br_args->bridge_sec, br_args->bridge_sec, NULL, br_args->br_key);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_vlan_args, vlan) == DM_STOP)
					goto end;
				cnt++;
			}
		}
	} else {
		br_ifname_dup = dmstrdup(br_ifname_list);
		for (pch = strtok_r(br_ifname_dup, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
			int ret = 0;
			if (strstr(pch, ".") == NULL)
				continue;

			dmasprintf(&vlan, "%d", cnt);
			init_bridging_vlan_args(&curr_bridging_vlan_args, br_args->bridge_sec, br_args->bridge_sec, NULL, br_args->br_key);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_vlan_args, vlan) == DM_STOP)
					goto end;
			cnt++;

			/* Check if the vlanport section is not present for the interface. */
			struct uci_section *s = NULL;
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "ifname", pch, s) {
				ret = 1;
				break;
			}

			if (ret == 0) {
				/* Add vlanport section in dmmap_network. */
				struct uci_section *dmmap_port =  NULL;
				char *v, *name;
				dmuci_add_section_bbfdm("dmmap_network", "vlanport", &dmmap_port, &v);
				dmuci_set_value_by_section(dmmap_port, "bridge_key", br_args->br_key);
				/* Get the last vlan_instance and add one. */
				int m = get_vlanport_last_inst(br_args->br_key);
				char instance[10] = {0};
				snprintf(instance, sizeof(instance), "%d", m+1);
				dmuci_set_value_by_section(dmmap_port, "vport_inst", instance);
				dmasprintf(&name, "%s_%d", "vlanport", m);
				dmuci_set_value_by_section(dmmap_port, "section_name", name);
				dmuci_set_value_by_section(dmmap_port, "ifname", pch);
			}
		}

		/* Also check if any dmmap vlanport section is present without ifname.
		 * If present, then create the link. */
		uci_path_foreach_option_eq(bbfdm, "dmmap_network", "vlanport", "bridge_key", br_args->br_key, sec) {
			char *tmp;
			dmuci_get_value_by_section_string(sec, "ifname", &tmp);
			if (*tmp == '\0') {
				dmasprintf(&vlan, "%d", cnt);
				init_bridging_vlan_args(&curr_bridging_vlan_args, br_args->bridge_sec, br_args->bridge_sec, NULL, br_args->br_key);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_bridging_vlan_args, vlan) == DM_STOP)
					goto end;

				cnt++;
			}
		}
	}
end:
	return 0;
}

/*** Bridging. ***/
DMOBJ tBridgingObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Bridge", &DMWRITE, add_bridge, delete_bridge, NULL, browseBridgeInst, NULL, NULL, NULL, tBridgingBridgeObj, tBridgingBridgeParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"MaxBridgeEntries", &DMREAD, DMT_UNINT, get_Max_Bridge_Entries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxDBridgeEntries", &DMREAD, DMT_UNINT, get_Max_DBridge_Entries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxQBridgeEntries", &DMREAD, DMT_UNINT, get_Max_QBridge_Entries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxVLANEntries", &DMREAD, DMT_UNINT, get_Max_VLAN_Entries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxProviderBridgeEntries", &DMREAD, DMT_UNINT, get_Max_Provider_Bridge_Entries, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxFilterEntries", &DMREAD, DMT_UNINT, get_Max_Filter_Entries, NULL, NULL, NULL, BBFDM_BOTH},
{"BridgeNumberOfEntries", &DMREAD, DMT_UNINT, get_Bridge_Number_Of_Entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}. ***/
DMOBJ tBridgingBridgeObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Port", &DMWRITE, add_br_port, delete_br_port, NULL, browseBridgePortInst, NULL, NULL, NULL, tBridgingBridgePortObj, tBridgingBridgePortParams, get_linker_br_port, BBFDM_BOTH},
{"VLAN", &DMWRITE, add_br_vlan, delete_br_vlan, NULL, browseBridgeVlanInst, NULL, NULL, NULL, NULL, tBridgingBridgeVLANParams, get_linker_br_vlan, BBFDM_BOTH},
{"VLANPort", &DMWRITE, add_br_vlanport, delete_br_vlanport, NULL, browseBridgeVlanPortInst, NULL, NULL, NULL, NULL, tBridgingBridgeVLANPortParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBridgingBridgeParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_br_enable, set_br_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_br_status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_br_alias, set_br_alias, NULL, NULL, BBFDM_BOTH},
{"Standard", &DMWRITE, DMT_STRING, get_br_standard, set_br_standard, NULL, NULL, BBFDM_BOTH},
{"PortNumberOfEntries", &DMREAD, DMT_UNINT, get_br_port_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"VLANNumberOfEntries", &DMREAD, DMT_UNINT, get_br_vlan_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"VLANPortNumberOfEntries", &DMREAD, DMT_UNINT, get_br_vlan_port_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
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
{"Enable", &DMWRITE, DMT_BOOL, get_br_port_enable, set_br_port_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_br_port_status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_br_port_alias, set_br_port_alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_br_port_name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_br_port_last_change, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_port_lower_layer, set_port_lower_layer, NULL, NULL, BBFDM_BOTH},
{"ManagementPort", &DMWRITE, DMT_BOOL, get_br_port_management, set_br_port_management, NULL, NULL, BBFDM_BOTH},
{"Type", &DMWRITE, DMT_STRING, get_br_port_type, set_br_port_type, NULL, NULL, BBFDM_BOTH},
{"DefaultUserPriority", &DMWRITE, DMT_UNINT, get_br_port_default_user_priority, set_br_port_default_user_priority, NULL, NULL, BBFDM_BOTH},
{"PriorityRegeneration", &DMWRITE, DMT_STRING, get_br_port_priority_regeneration, set_br_port_priority_regeneration, NULL, NULL, BBFDM_BOTH},
{"PortState", &DMREAD, DMT_STRING, get_br_port_port_state, NULL, NULL, NULL, BBFDM_BOTH},
{"PVID", &DMWRITE, DMT_INT, get_br_port_pvid, set_br_port_pvid, NULL, NULL, BBFDM_BOTH},
{"TPID", &DMWRITE, DMT_UNINT, get_br_port_tpid, set_br_port_tpid, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.Port.{i}.Stats. ***/
DMLEAF tBridgingBridgePortStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_br_port_stats_tx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_br_port_stats_rx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_br_port_stats_tx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_br_port_stats_rx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_br_port_stats_tx_errors, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_br_port_stats_rx_errors, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_br_port_stats_tx_unicast_packets, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_br_port_stats_rx_unicast_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_br_port_stats_tx_discard_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_br_port_stats_rx_discard_packets, NULL, NULL, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_br_port_stats_tx_multicast_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_br_port_stats_rx_multicast_packets, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_br_port_stats_tx_broadcast_packets, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_br_port_stats_rx_broadcast_packets, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_br_port_stats_rx_unknown_proto_packets, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLAN.{i}. ***/
DMLEAF tBridgingBridgeVLANParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_br_vlan_enable, set_br_vlan_enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,get_br_vlan_alias, set_br_vlan_alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_br_vlan_name, set_br_vlan_name, NULL, NULL, BBFDM_BOTH},
{"VLANID", &DMWRITE, DMT_INT, get_br_vlan_vid, set_br_vlan_vid, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"VLANPriority", &DMWRITE, DMT_STRING, get_br_vlan_priority, set_br_vlan_priority, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** Bridging.Bridge.{i}.VLANPort.{i}. ***/
DMLEAF tBridgingBridgeVLANPortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_br_vlan_enable, set_br_vlan_enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING,  get_br_vlan_alias, set_br_vlan_alias, NULL, NULL, BBFDM_BOTH},
{"VLAN", &DMWRITE, DMT_STRING,  get_vlan_port_vlan_ref, set_vlan_port_vlan_ref, NULL, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_STRING, get_vlan_port_port_ref, set_vlan_port_port_ref, NULL, NULL, BBFDM_BOTH},
{"Untagged", &DMWRITE, DMT_BOOL, get_br_vlan_untagged, set_br_vlan_untagged, NULL, NULL, BBFDM_BOTH},
{0}
};
