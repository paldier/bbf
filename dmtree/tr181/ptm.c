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
#include "ptm.h"

struct ptm_args
{
	struct uci_section *ptm_sec;
	char *ifname;
};


/**************************************************************************
* LINKER
***************************************************************************/
static int get_ptm_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct ptm_args *)data)->ifname)
		*linker = ((struct ptm_args *)data)->ifname;
	else
		*linker = "" ;
	return 0;
}

/**************************************************************************
* INIT
***************************************************************************/
static inline int init_ptm_link(struct ptm_args *args, struct uci_section *s, char *ifname)
{
	args->ptm_sec = s;
	args->ifname = ifname;
	return 0;
}

/**************************************************************************
* SET & GET DSL LINK PARAMETERS
***************************************************************************/
/*#Device.PTM.Link.{i}.Name!UCI:dsl/ptm-device,@i-1/name*/
static int get_ptm_link_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ptm_args *)data)->ptm_sec, "name", value);
	return 0;
}

static int get_ptm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char linker[32];
	snprintf(linker, sizeof(linker), "channel_%d", atoi(instance)-1);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cDSL%cChannel%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static inline int ubus_ptm_stats(char **value, char *stat_mod, void *data)
{
	json_object *res = NULL;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct ptm_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "statistics", stat_mod);
	if ((*value)[0] == '\0')
		*value = "0";
	return 0;
}

/*#Device.PTM.Link.{i}.Stats.BytesReceived!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
static int get_ptm_stats_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_ptm_stats(value, "rx_bytes", data);
	return 0;
}

/*#Device.PTM.Link.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
static int get_ptm_stats_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_ptm_stats(value, "tx_bytes", data);
	return 0;
}

/*#Device.PTM.Link.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
static int get_ptm_stats_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_ptm_stats(value, "rx_packets", data);
	return 0;
}

/*#Device.PTM.Link.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
static int get_ptm_stats_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	ubus_ptm_stats(value, "tx_packets", data);
	return 0;
}

static int get_ptm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_ptm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_ptm_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Up";
	return 0;
}

/*************************************************************
* ADD OBJ
*************************************************************/
static int add_ptm_link(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *instance = NULL, *ptm_device = NULL, *v = NULL, *instance_update = NULL;
	struct uci_section *dmmap_ptm = NULL;

	check_create_dmmap_package("dmmap_dsl");
	instance = get_last_instance_bbfdm("dmmap_dsl", "ptm-device", "ptmlinkinstance");
	dmasprintf(&ptm_device, "ptm%d", instance ? atoi(instance) : 0);
	dmasprintf(&instance_update, "%d", instance ? atoi(instance)+ 1 : 1);
	dmuci_set_value("dsl", ptm_device, "", "ptm-device");
	dmuci_set_value("dsl", ptm_device, "name", "PTM");
	dmuci_set_value("dsl", ptm_device, "device", ptm_device);
	dmuci_set_value("dsl", ptm_device, "priority", "1");
	dmuci_set_value("dsl", ptm_device, "portid", "1");
	dmuci_add_section_bbfdm("dmmap_dsl", "ptm-device", &dmmap_ptm, &v);
	dmuci_set_value_by_section(dmmap_ptm, "section_name", ptm_device);
	*instancepara = update_instance_bbfdm(dmmap_ptm, instance, "ptmlinkinstance");
	return 0;
}

static int delete_ptm_link(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	char *ifname;
	struct uci_section *s = NULL, *ss = NULL, *ns = NULL, *nss = NULL, *dmmap_section= NULL;

	switch (del_action) {
	case DEL_INST:
		get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
		if (dmmap_section != NULL)
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
		dmuci_delete_by_section(((struct ptm_args *)data)->ptm_sec, NULL, NULL);
		uci_foreach_option_cont("network", "interface", "ifname", ((struct ptm_args *)data)->ifname, s) {
			if (ss && ifname!=NULL)
				wan_remove_dev_interface(ss, ((struct ptm_args *)data)->ifname);
			ss = s;
		}
		if (ss != NULL && ifname!=NULL)
			wan_remove_dev_interface(ss, ((struct ptm_args *)data)->ifname);
		break;
	case DEL_ALL:
		uci_foreach_sections("dsl", "ptm-device", s) {
			if (ss){
				get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_get_value_by_section_string(ss, "device", &ifname);
				dmuci_delete_by_section(ss, NULL, NULL);
				uci_foreach_option_cont("network", "interface", "ifname", ifname, ns) {
					if (nss)
						wan_remove_dev_interface(nss, ifname);
					nss = ns;
				}
				if (nss != NULL && ifname!=NULL)
					wan_remove_dev_interface(nss, ifname);
			}
			ss = s;
		}
		if (ss != NULL) {
			get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(ss), &dmmap_section);
			if (dmmap_section != NULL)
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
/*#Device.PTM.Link.{i}.Alias!UCI:dmmap_dsl/ptm-device,@i-1/ptmlinkalias*/
static int get_ptm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ptmlinkalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ptm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dsl", "ptm-device", section_name(((struct ptm_args *)data)->ptm_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "ptmlinkalias", value);
			return 0;
	}
	return 0;
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
/*#Device.PTM.Link.{i}.!UCI:dsl/ptm-device/dmmap_dsl*/
static int browsePtmLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *channel_last = NULL, *ifname;
	struct ptm_args curr_ptm_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dsl", "ptm-device", "dmmap_dsl", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "device", &ifname);
		init_ptm_link(&curr_ptm_args, p->config_section, ifname);
		wnum = handle_update_instance(1, dmctx, &channel_last, update_instance_alias, 3, p->dmmap_section, "ptmlinkinstance", "ptmlinkalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ptm_args, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/* *** Device.PTM. *** */
DMOBJ tPTMObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Link", &DMWRITE, add_ptm_link, delete_ptm_link, NULL, browsePtmLinkInst, NULL, NULL, NULL, tPTMLinkObj, tPTMLinkParams, get_ptm_linker, BBFDM_BOTH},
{0}
};

/* *** Device.PTM.Link.{i}. *** */
DMOBJ tPTMLinkObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPTMLinkStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tPTMLinkParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_ptm_alias, set_ptm_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_ptm_enable, set_ptm_enable, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_ptm_link_name, NULL, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_ptm_status, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMREAD, DMT_STRING, get_ptm_lower_layer, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.PTM.Link.{i}.Stats. *** */
DMLEAF tPTMLinkStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, get_ptm_stats_bytes_sent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, get_ptm_stats_bytes_received, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, get_ptm_stats_pack_sent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, get_ptm_stats_pack_received, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
