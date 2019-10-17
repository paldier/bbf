/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2019 iopsys Software Solutions AB
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#include <ctype.h>
#include <uci.h>
#include "dmbbf.h"
#include "dmuci.h"
#include "dmubus.h"
#include "dmcommon.h"
#include "atm.h"
#include "dmjson.h"
#include "dmentry.h"

/*** ATM. ***/
DMOBJ tATMObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Link", &DMWRITE, add_atm_link, delete_atm_link, NULL, browseAtmLinkInst, NULL, NULL, NULL, tATMLinkObj, tATMLinkParams, get_atm_linker, BBFDM_BOTH},
{0}
};

/*** ATM.Link. ***/
DMOBJ tATMLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tATMLinkStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tATMLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING,  get_atm_alias, set_atm_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMREAD, DMT_BOOL, get_atm_enable, NULL, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_atm_link_name, NULL, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_atm_enable, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMREAD, DMT_STRING, get_atm_lower_layer, NULL, NULL, NULL, BBFDM_BOTH},
{"LinkType", &DMWRITE, DMT_STRING, get_atm_link_type, set_atm_link_type, NULL, NULL, BBFDM_BOTH},
{"DestinationAddress", &DMWRITE, DMT_STRING, get_atm_destination_address, set_atm_destination_address, NULL, NULL, BBFDM_BOTH},
{"Encapsulation", &DMWRITE, DMT_STRING, get_atm_encapsulation, set_atm_encapsulation, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** ATM.Link.Stats. ***/
DMLEAF tATMLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNINT, get_atm_stats_bytes_sent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_atm_stats_bytes_received, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_atm_stats_pack_sent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_atm_stats_pack_received, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/**************************************************************************
* LINKER
***************************************************************************/
int get_atm_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker) {
	if (data && ((struct atm_args *)data)->ifname) {
		*linker =  ((struct atm_args *)data)->ifname;
		return 0;
	}
	*linker = "" ;
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
inline int init_atm_link(struct atm_args *args, struct uci_section *s, char *ifname)
{
	args->atm_sec = s;
	args->ifname = ifname;
	return 0;
}

/**************************************************************************
* SET & GET DSL LINK PARAMETERS
***************************************************************************/
/*#Device.ATM.Link.{i}.DestinationAddress!UCI:dsl/atm-device,@i-1/vpi*/
int get_atm_destination_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *vpi, *vci;

	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "vpi", &vpi);
	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "vci", &vci);
	dmasprintf(value, "PVC: %s/%s", vpi, vci); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

int set_atm_destination_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *vpi = NULL, *vci = NULL, *spch, *val;
	struct uci_section *s;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
				if (strstr(value, "PVC: "))
					value += 5;
				else
					return 0;
				val = dmstrdup(value);
				vpi = strtok_r(val, "/", &spch);
				if (vpi) {
					vci = strtok_r(NULL, "/", &spch);
				}
				if (vpi && vci) {
					dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "vpi", vpi);
					dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "vci", vci);
				}
				dmfree(val);
				break;
			return 0;
	}
	return 0;
}

/*#Device.ATM.Link.{i}.Name!UCI:dsl/atm-device,@i-1/name*/
int get_atm_link_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "name", value);
	return 0;
}

/*#Device.ATM.Link.{i}.Encapsulation!UCI:dsl/atm-device,@i-1/encapsulation*/
int get_atm_encapsulation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *encapsulation;

	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "encapsulation", &encapsulation);
	if (strcasecmp(encapsulation, "vcmux") == 0) {
		*value = "VCMUX";
	}
	else if (strcasecmp(encapsulation, "llc") == 0) {
		*value = "LLC";
	} else {
		*value = "";
	}
	return 0;
}

int set_atm_encapsulation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encapsulation;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (strcmp(value, "VCMUX") == 0)
				encapsulation = "vcmux";
			else if (strcmp(value, "LLC") == 0)
				encapsulation = "llc";
			else
				return 0;

			dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "encapsulation", encapsulation);
			return 0;
	}
	return 0;
}

/*#Device.ATM.Link.{i}.LinkType!UCI:dsl/atm-device,@i-1/link_type*/
int get_atm_link_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	dmuci_get_value_by_section_string(((struct atm_args *)data)->atm_sec, "link_type", value);
	return 0;
}

int set_atm_link_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct atm_args *)data)->atm_sec, "link_type", value);
			return 0;
	}
	return 0;
}

int get_atm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char linker[16];
	sprintf(linker, "channel_%d", atoi(instance)-1);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cDSL%cChannel%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static inline int ubus_atm_stats(json_object *res, char **value, char *stat_mod, void *data)
{
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct atm_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", stat_mod);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.BytesReceived!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
int get_atm_stats_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	ubus_atm_stats(res, value, "rx_bytes", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
int get_atm_stats_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	ubus_atm_stats(res, value, "tx_bytes", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
int get_atm_stats_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	ubus_atm_stats(res, value, "rx_packets", data);
	return 0;
}

/*#Device.ATM.Link.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
int get_atm_stats_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	ubus_atm_stats(res, value, "tx_packets", data);
	return 0;
}

int get_atm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*************************************************************
 * ADD OBJ
/*************************************************************/
int add_atm_link(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
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

int delete_atm_link(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
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
/*************************************************************/
int get_atm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_dsl", "atm-device", section_name(((struct atm_args *)data)->atm_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "atmlinkalias", value);
	return 0;
}

int set_atm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;

	switch (action) {
		case VALUECHECK:
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
/*************************************************************/
/*#Device.ATM.Link.{i}.!UCI:dsl/atm-device/dmmap_dsl*/
int browseAtmLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
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
