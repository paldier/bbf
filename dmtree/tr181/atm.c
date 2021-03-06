/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "atm.h"

struct atm_args
{
	struct uci_section *atm_sec;
	char *ifname;
};

/**************************************************************************
* LINKER
***************************************************************************/
static int get_atm_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct atm_args *)data)->ifname) {
		*linker = ((struct atm_args *)data)->ifname;
		return 0;
	}
	*linker = "" ;
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_atm_link(struct atm_args *args, struct uci_section *s, char *ifname)
{
	args->atm_sec = s;
	args->ifname = ifname;
	return 0;
}

/**************************************************************************
* SET & GET DSL LINK PARAMETERS
***************************************************************************/
/*#Device.ATM.Link.{i}.DestinationAddress!UCI:dsl/atm-device,@i-1/vpi&UCI:dsl/atm-device,@i-1/vci*/
static int get_atm_destination_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vpi, *vci;

	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "vpi", &vpi);
	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "vci", &vci);
	dmasprintf(value, "%s/%s", vpi, vci); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int set_atm_destination_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *vpi = NULL, *vci = NULL, *spch;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, DestinationAddress, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			vpi = strtok_r(value, "/", &spch);
			if (vpi)
				vci = strtok_r(NULL, "/", &spch);
			if (vpi && vci) {
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "vpi", vpi);
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "vci", vci);
			}
			return 0;
	}
	return 0;
}

/*#Device.ATM.Link.{i}.Name!UCI:dsl/atm-device,@i-1/name*/
static int get_atm_link_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "name", value);
	return 0;
}

/*#Device.ATM.Link.{i}.Encapsulation!UCI:dsl/atm-device,@i-1/encapsulation*/
static int get_atm_encapsulation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *encapsulation;

	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "encapsulation", &encapsulation);
	if (strcmp(encapsulation, "vcmux") == 0)
		*value = "VCMUX";
	else if (strcmp(encapsulation, "llc") == 0)
		*value = "LLC";
	else
		*value = "";
	return 0;
}

static int set_atm_encapsulation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, Encapsulation, 2, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "VCMUX") == 0)
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "encapsulation", "vcmux");
			else if (strcmp(value, "LLC") == 0)
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "encapsulation", "llc");
			return 0;
	}
	return 0;
}

/*#Device.ATM.Link.{i}.LinkType!UCI:dsl/atm-device,@i-1/link_type*/
static int get_atm_link_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *link_type;

	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "link_type", &link_type);
	if (strcmp(link_type, "eoa") == 0)
		*value = "EoA";
	else if (strcmp(link_type, "ipoa") == 0)
		*value = "IPoA";
	else if (strcmp(link_type, "pppoa") == 0)
		*value = "PPPoA";
	else if (strcmp(link_type, "cip") == 0)
		*value = "CIP";
	else
		*value = "Unconfigured";
	return 0;
}

static int set_atm_link_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, LinkType, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "EoA") == 0)
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "link_type", "eoa");
			else if (strcmp(value, "IPoA") == 0)
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "link_type", "ipoa");
			else if (strcmp(value, "PPPoA") == 0)
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "link_type", "pppoa");
			else if (strcmp(value, "CIP") == 0)
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "link_type", "cip");
			else
				dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "link_type", "");
			return 0;
	}
	return 0;
}

static int get_atm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char linker[32];
	snprintf(linker, sizeof(linker), "channel_%d", atoi(instance)-1);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cDSL%cChannel%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static inline int ubus_atm_stats(char **value, char *stat_mod, void *data)
{
	json_object *res = NULL;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct atm_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "statistics", stat_mod);
	if ((*value)[0] == '\0')
		*value = "0";
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.BytesReceived!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
static int get_atm_stats_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_atm_stats(value, "rx_bytes", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
static int get_atm_stats_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_atm_stats(value, "tx_bytes", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
static int get_atm_stats_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_atm_stats(value, "rx_packets", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
static int get_atm_stats_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_atm_stats(value, "tx_packets", data);
	return 0;
}

static int get_atm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_atm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			//TODO
			return 0;
	}
	return 0;
}

static int get_atm_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

/*************************************************************
* ADD OBJ
*************************************************************/
static int add_atm_link(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *instance = NULL, *atm_device = NULL, *v = NULL, *instance_update = NULL;
	struct uci_section *dmmap_atm = NULL;

	check_create_dmmap_package("dmmap_dsl");
	instance = get_last_instance_bbfdm("dmmap_dsl", "atm-device", "atmlinkinstance");
	dmasprintf(&atm_device, "atm%d", instance ? atoi(instance) : 0);
	dmasprintf(&instance_update, "%d", instance ? atoi(instance)+ 1 : 1);
	dmuci_set_value("dsl", atm_device, "", "atm-device");
	dmuci_set_value("dsl", atm_device, "name", "ATM");
	dmuci_set_value("dsl", atm_device, "vpi", "8");
	dmuci_set_value("dsl", atm_device, "vci", "35");
	dmuci_set_value("dsl", atm_device, "device", atm_device);
	dmuci_set_value("dsl", atm_device, "link_type", "eoa");
	dmuci_set_value("dsl", atm_device, "encapsulation", "llc");
	dmuci_set_value("dsl", atm_device, "qos_class", "ubr");
	dmuci_add_section_bbfdm("dmmap_dsl", "atm-device", &dmmap_atm, &v);
	dmuci_set_value_by_section(dmmap_atm, "section_name", atm_device);
	*instancepara = update_instance_bbfdm(dmmap_atm, instance, "atmlinkinstance");
	return 0;
}

static int delete_atm_link(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *ns = NULL, *nss = NULL, *dmmap_section= NULL;
	char *ifname;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_dsl", "atm-device", section_name(((struct atm_args *)data)->atm_sec), &dmmap_section);
			if(dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct atm_args *)data)->atm_sec, NULL, NULL);
			uci_foreach_option_cont("network", "interface", "ifname", ((struct atm_args *)data)->ifname, s) {
				if (ss && ifname!=NULL)
					wan_remove_dev_interface(ss, ((struct atm_args *)data)->ifname);
				ss = s;
			}
			if (ss != NULL && ifname!=NULL)
				wan_remove_dev_interface(ss, ((struct atm_args *)data)->ifname);
			break;
		case DEL_ALL:
			uci_foreach_sections("dsl", "atm-device", s) {
				if (ss){
					get_dmmap_section_of_config_section("dmmap_dsl", "atm-device", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_get_value_by_section_string(ss, "device", &ifname);
					dmuci_delete_by_section(ss, NULL, NULL);
					uci_foreach_option_cont("network", "interface", "ifname", ifname, ns) {
						if (nss && ifname!=NULL)
							wan_remove_dev_interface(nss, ifname);
						nss = ns;
					}
					if (nss != NULL && ifname!=NULL)
						wan_remove_dev_interface(nss, ifname);
				}
				ss = s;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_dsl", "atm-device", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_get_value_by_section_string(ss, "device", &ifname);
				dmuci_delete_by_section(ss, NULL, NULL);
				uci_foreach_option_cont("network", "interface", "ifname", ifname, ns) {
					if (nss && ifname!=NULL)
						wan_remove_dev_interface(nss, ifname);
					nss = ns;
				}
				if (nss != NULL && ifname!=NULL)
					wan_remove_dev_interface(nss, ifname);
			}
			break;
	}
	return 0;
}

/*************************************************************
* SET AND GET ALIAS
*************************************************************/
/*#Device.ATM.Link.{i}.Alias!UCI:dmmap_dsl/atm-device,@i-1/atmlinkalias*/
static int get_atm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_dsl", "atm-device", section_name(((struct atm_args *)data)->atm_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "atmlinkalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_atm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dsl", "atm-device", section_name(((struct atm_args *)data)->atm_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "atmlinkalias", value);
			return 0;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
/*#Device.ATM.Link.{i}.!UCI:dsl/atm-device/dmmap_dsl*/
static int browseAtmLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *channel_last = NULL, *ifname;
	struct atm_args curr_atm_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dsl", "atm-device", "dmmap_dsl", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "device", &ifname);
		init_atm_link(&curr_atm_args, p->config_section, ifname);
		wnum = handle_update_instance(1, dmctx, &channel_last, update_instance_alias, 3, p->dmmap_section, "atmlinkinstance", "atmlinkalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_atm_args, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*** ATM. ***/
DMOBJ tATMObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Link", &DMWRITE, add_atm_link, delete_atm_link, NULL, browseAtmLinkInst, NULL, NULL, NULL, tATMLinkObj, tATMLinkParams, get_atm_linker, BBFDM_BOTH},
{0}
};

/*** ATM.Link. ***/
DMOBJ tATMLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tATMLinkStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tATMLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_atm_alias, set_atm_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_atm_enable, set_atm_enable, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_atm_link_name, NULL, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_atm_status, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMREAD, DMT_STRING, get_atm_lower_layer, NULL, NULL, NULL, BBFDM_BOTH},
{"LinkType", &DMWRITE, DMT_STRING, get_atm_link_type, set_atm_link_type, NULL, NULL, BBFDM_BOTH},
{"DestinationAddress", &DMWRITE, DMT_STRING, get_atm_destination_address, set_atm_destination_address, NULL, NULL, BBFDM_BOTH},
{"Encapsulation", &DMWRITE, DMT_STRING, get_atm_encapsulation, set_atm_encapsulation, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** ATM.Link.Stats. ***/
DMLEAF tATMLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_atm_stats_bytes_sent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_atm_stats_bytes_received, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_atm_stats_pack_sent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_atm_stats_pack_received, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
