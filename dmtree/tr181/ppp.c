/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "ppp.h"


/*************************************************************
* GET SET ALIAS
**************************************************************/
static int get_ppp_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_section);
	if (dmmap_section)
		dmuci_get_value_by_section_string(dmmap_section, "ppp_int_alias", value);
	return 0;
}

static int set_ppp_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(dmmap_section, "ppp_int_alias", value);
			return 0;
	}
	return 0;
}

/**************************************************************************
* GET & SET PARAMETERS
***************************************************************************/
/*#Device.PPP.Interface.{i}.Enable!UBUS:network.interface/status/interface,@Name/up*/
static int get_ppp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct uci_section *)data)), String}}, 1, &res);
	DM_ASSERT(res, *value = "false");
	*value = dmjson_get_value(res, 1, "up");
	return 0;
}

static int set_ppp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *ubus_object;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmastrcat(&ubus_object, "network.interface.", section_name(((struct uci_section *)data)));
			dmubus_call_set(ubus_object, b ? "up" : "down", UBUS_ARGS{}, 0);
			dmfree(ubus_object);
			break;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.Status!UBUS:network.interface/status/interface,@Name/up*/
static int get_PPPInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *status;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct uci_section *)data)), String}}, 1, &res);
	DM_ASSERT(res, *value = "Down");
	status = dmjson_get_value(res, 1, "up");
	if (strcmp(status, "true") == 0)
		*value= "Up";
	else
		*value= "Down";
	return 0;
}

/*#Device.PPP.Interface.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
static int get_PPPInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name((struct uci_section *)data), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}

static int get_PPPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	return 0;
}

static int set_PPPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *ubus_object;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				dmastrcat(&ubus_object, "network.interface.", section_name(((struct uci_section *)data)));
				dmubus_call_set(ubus_object, "down", UBUS_ARGS{}, 0);
				dmubus_call_set(ubus_object, "up", UBUS_ARGS{}, 0);
				dmfree(ubus_object);
			}
			break;
	}
	return 0;
}

static int get_ppp_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name(((struct uci_section *)data)));
	return 0;
}

/*#Device.PPP.Interface.{i}.ConnectionStatus!UBUS:network.interface/status/interface,@Name/up*/
static int get_ppp_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status = NULL,  *uptime = NULL, *pending = NULL;
	json_object *res = NULL, *jobj = NULL;
	bool bstatus = false, bpend = false;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct uci_section *)data)), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	jobj = dmjson_get_obj(res, 1, "up");
	if (jobj) {
		status = dmjson_get_value(res, 1, "up");
		string_to_bool(status, &bstatus);
		if (bstatus) {
			uptime = dmjson_get_value(res, 1, "uptime");
			pending = dmjson_get_value(res, 1, "pending");			
			string_to_bool(pending, &bpend);
		}
	}
	if (uptime && atoi(uptime) > 0)
		*value = "Connected";
	else if (pending && bpend)
		*value = "Pending Disconnect";
	else
		*value = "Disconnected";
	return 0;
}

/*#Device.PPP.Interface.{i}.Username!UCI:network/interface,@i-1/username*/
static int get_ppp_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct uci_section *)data), "username", value);
	return 0;
}

static int set_ppp_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct uci_section *)data), "username", value);
			return 0;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.Password!UCI:network/interface,@i-1/password*/
static int set_ppp_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct uci_section *)data), "password", value);
			return 0;
	}
	return 0;
}

static int ppp_read_sysfs(struct uci_section *sect, const char *name, char **value)
{
	char *proto;
	int rc = 0;

	dmuci_get_value_by_section_string(sect, "proto", &proto);

	if (!strcmp(proto, "pppoe")) {
		char *ifname;

		dmuci_get_value_by_section_string(sect, "ifname", &ifname);
		rc = get_net_device_sysfs(ifname, name, value);
	}
	return rc;
}

/*#Device.PPP.Interface.{i}.Stats.BytesReceived!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
static int get_ppp_eth_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_bytes", value);
}

/*#Device.PPP.Interface.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
static int get_ppp_eth_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/tx_bytes", value);
}

/*#Device.PPP.Interface.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
static int get_ppp_eth_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_packets", value);
}

/*#Device.PPP.Interface.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
static int get_ppp_eth_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/tx_packets", value);
}

/*#Device.PPP.Interface.{i}.Stats.ErrorsSent!UBUS:network.device/status/name,@Name/statistics.tx_errors*/
static int get_PPPInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/tx_errors", value);
}

/*#Device.PPP.Interface.{i}.Stats.ErrorsReceived!UBUS:network.device/status/name,@Name/statistics.rx_errors*/
static int get_PPPInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_errors", value);
}

static int get_PPPInterfaceStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_PPPInterfaceStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.PPP.Interface.{i}.Stats.DiscardPacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_dropped*/
static int get_PPPInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/tx_dropped", value);
}

/*#Device.PPP.Interface.{i}.Stats.DiscardPacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_dropped*/
static int get_PPPInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/rx_dropped", value);
}

static int get_PPPInterfaceStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_PPPInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ppp_read_sysfs(data, "statistics/multicast", value);
}

static int get_PPPInterfaceStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_PPPInterfaceStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_PPPInterfaceStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_ppp_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;
	dmuci_get_value_by_section_string(((struct uci_section *)data), "ifname", &linker);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cATM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cPTM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_ppp_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker, *newvalue = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, NULL, NULL, "1024", NULL, NULL, NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (value[strlen(value)-1]!='.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else
				adm_entry_get_linker_value(ctx, value, &linker);
			if(linker)
				dmuci_set_value_by_section(((struct uci_section *)data), "ifname", linker);
			else
				return FAULT_9005;
			return 0;
	}
	return 0;
}

static int get_PPP_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	char *proto;
	int nbre= 0;

	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (!strstr(proto, "ppp"))
			continue;
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

static int get_PPPInterfacePPPoE_SessionID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.PPP.Interface.{i}.PPPoE.ACName!UCI:network/interface,@i-1/ac*/
static int get_PPPInterfacePPPoE_ACName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto;
	dmuci_get_value_by_section_string(((struct uci_section *)data), "proto", &proto);
	if (strcmp(proto, "pppoe") == 0) {
		dmuci_get_value_by_section_string(((struct uci_section *)data), "ac", value);
		return 0;
	}
	return 0;
}

static int set_PPPInterfacePPPoE_ACName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct uci_section *)data), "proto", &proto);
			if (strcmp(proto, "pppoe") != 0)
				return FAULT_9001;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct uci_section *)data), "ac", value);
			break;
	}
	return 0;
}

/*#Device.PPP.Interface.{i}.PPPoE.ServiceName!UCI:network/interface,@i-1/service*/
static int get_PPPInterfacePPPoE_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *proto;
	dmuci_get_value_by_section_string(((struct uci_section *)data), "proto", &proto);
	if (strcmp(proto, "pppoe") == 0) {
		dmuci_get_value_by_section_string(((struct uci_section *)data), "service", value);
		return 0;
	}
	return 0;
}

static int set_PPPInterfacePPPoE_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct uci_section *)data), "proto", &proto);
			if (strcmp(proto, "pppoe") != 0)
				return FAULT_9001;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct uci_section *)data), "service", value);
			break;
	}
	return 0;
}

/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_ppp_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker) {

	if(((struct uci_section *)data)) {
		dmasprintf(linker, "%s", section_name(((struct uci_section *)data)));
		return 0;
	}
	*linker = "";
	return 0;
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_ppp_interface(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char name[16] = {0};
	char *inst, *v;
	struct uci_section *dmmap_ppp = NULL;

	check_create_dmmap_package("dmmap_network");
	inst = get_last_instance_lev2_bbfdm("network", "interface", "dmmap_network", "ppp_int_instance", "proto", "ppp");
	snprintf(name, sizeof(name), "ppp_%d", inst ? (atoi(inst)+1) : 1);
	dmuci_set_value("network", name, "", "interface");
	dmuci_set_value("network", name, "proto", "ppp");
	dmuci_set_value("network", name, "username", name);
	dmuci_set_value("network", name, "password", name);
	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_ppp, &v);
	dmuci_set_value_by_section(dmmap_ppp, "section_name", name);
	*instance = update_instance_bbfdm(dmmap_ppp, inst, "ppp_int_instance");
	return 0;
}

static int delete_ppp_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *ppp_s = NULL, *ss = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct uci_section *)data)), &dmmap_section);
			if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct uci_section *)data), NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq("network", "interface", "proto", "ppp", ppp_s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(ss), &dmmap_section);
					if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = ppp_s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(ss), &dmmap_section);
				if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.PPP.Interface.{i}.!UCI:network/interface/dmmap_network*/
static int browseInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ppp_int = NULL, *ppp_int_last = NULL, *proto;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "interface", "dmmap_network", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "proto", &proto);
		if (!strstr(proto, "ppp"))
			continue;
		ppp_int = handle_update_instance(1, dmctx, &ppp_int_last, update_instance_alias, 3, p->dmmap_section, "ppp_int_instance", "ppp_int_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, ppp_int) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/* *** Device.PPP. *** */
DMOBJ tPPPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Interface", &DMWRITE, add_ppp_interface, delete_ppp_interface, NULL, browseInterfaceInst, NULL, NULL, NULL, tPPPInterfaceObj, tPPPInterfaceParams, get_linker_ppp_interface, BBFDM_BOTH},
{0}
};

DMLEAF tPPPParams[] = {
/* PARAM, permission, type, getvlue, setvalue, forced_inform, notification*/
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_PPP_InterfaceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.PPP.Interface.{i}. *** */
DMOBJ tPPPInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"PPPoE", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfacePPPoEParams, NULL, BBFDM_BOTH},
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPInterfaceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tPPPInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_ppp_alias, set_ppp_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_ppp_enable, set_ppp_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_PPPInterface_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_PPPInterface_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"Reset", &DMWRITE, DMT_BOOL, get_PPPInterface_Reset, set_PPPInterface_Reset, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_ppp_name, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ppp_lower_layer, set_ppp_lower_layer, NULL, NULL, BBFDM_BOTH},
{"ConnectionStatus", &DMREAD, DMT_STRING, get_ppp_status, NULL, NULL, NULL, BBFDM_BOTH},
{"Username", &DMWRITE, DMT_STRING, get_ppp_username, set_ppp_username, NULL, NULL, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_empty, set_ppp_password, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.PPP.Interface.{i}.PPPoE. *** */
DMLEAF tPPPInterfacePPPoEParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"SessionID", &DMREAD, DMT_UNINT, get_PPPInterfacePPPoE_SessionID, NULL, NULL, NULL, BBFDM_BOTH},
{"ACName", &DMWRITE, DMT_STRING, get_PPPInterfacePPPoE_ACName, set_PPPInterfacePPPoE_ACName, NULL, NULL, BBFDM_BOTH},
{"ServiceName", &DMWRITE, DMT_STRING, get_PPPInterfacePPPoE_ServiceName, set_PPPInterfacePPPoE_ServiceName, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.PPP.Interface.{i}.Stats. *** */
DMLEAF tPPPInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesReceived", &DMREAD, DMT_UNLONG, get_ppp_eth_bytes_received, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNLONG, get_ppp_eth_bytes_sent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_ppp_eth_pack_received, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_ppp_eth_pack_sent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
//{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, get_PPPInterfaceStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
//{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_PPPInterfaceStats_UnknownProtoPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
