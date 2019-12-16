/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include <ctype.h>
#include <uci.h>
#include "dmbbf.h"
#include "dmcommon.h"
#include "dmuci.h"
#include "dmubus.h"
#include "dmjson.h"
#include "dmentry.h"
#include "gre.h"

/* *** Device.GRE. *** */
DMOBJ tGREObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nexjsontobj, nextobj, leaf, linker, bbfdm_type*/
{"Tunnel", &DMWRITE, addObjGRETunnel, delObjGRETunnel, NULL, browseGRETunnelInst, NULL, NULL, NULL, tGRETunnelObj, tGRETunnelParams, NULL, BBFDM_BOTH},
{"Filter", &DMWRITE, addObjGREFilter, delObjGREFilter, NULL, browseGREFilterInst, NULL, NULL, NULL, NULL, tGREFilterParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tGREParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"TunnelNumberOfEntries", &DMREAD, DMT_UNINT, get_GRE_TunnelNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_GRE_FilterNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Tunnel.{i}. *** */
DMOBJ tGRETunnelObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nexjsontobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGRETunnelStatsParams, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, addObjGRETunnelInterface, delObjGRETunnelInterface, NULL, browseGRETunnelInterfaceInst, NULL, NULL, NULL, tGRETunnelInterfaceObj, tGRETunnelInterfaceParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tGRETunnelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_GRETunnel_Enable, set_GRETunnel_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_GRETunnel_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_GRETunnel_Alias, set_GRETunnel_Alias, NULL, NULL, BBFDM_BOTH},
{"RemoteEndpoints", &DMWRITE, DMT_STRING, get_GRETunnel_RemoteEndpoints, set_GRETunnel_RemoteEndpoints, NULL, NULL, BBFDM_BOTH},
{"KeepAlivePolicy", &DMWRITE, DMT_STRING, get_GRETunnel_KeepAlivePolicy, set_GRETunnel_KeepAlivePolicy, NULL, NULL, BBFDM_BOTH},
{"KeepAliveTimeout", &DMWRITE, DMT_UNINT, get_GRETunnel_KeepAliveTimeout, set_GRETunnel_KeepAliveTimeout, NULL, NULL, BBFDM_BOTH},
{"KeepAliveThreshold", &DMWRITE, DMT_UNINT, get_GRETunnel_KeepAliveThreshold, set_GRETunnel_KeepAliveThreshold, NULL, NULL, BBFDM_BOTH},
{"DeliveryHeaderProtocol", &DMWRITE, DMT_STRING, get_GRETunnel_DeliveryHeaderProtocol, set_GRETunnel_DeliveryHeaderProtocol, NULL, NULL, BBFDM_BOTH},
{"DefaultDSCPMark", &DMWRITE, DMT_UNINT, get_GRETunnel_DefaultDSCPMark, set_GRETunnel_DefaultDSCPMark, NULL, NULL, BBFDM_BOTH},
{"ConnectedRemoteEndpoint", &DMREAD, DMT_STRING, get_GRETunnel_ConnectedRemoteEndpoint, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_GRETunnel_InterfaceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Tunnel.{i}.Stats. *** */
DMLEAF tGRETunnelStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"KeepAliveSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_KeepAliveSent, NULL, NULL, NULL, BBFDM_BOTH},
{"KeepAliveReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_KeepAliveReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_GRETunnelStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_GRETunnelStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Tunnel.{i}.Interface.{i}. *** */
DMOBJ tGRETunnelInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nexjsontobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tGRETunnelInterfaceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tGRETunnelInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_Enable, set_GRETunnelInterface_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_GRETunnelInterface_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_GRETunnelInterface_Alias, set_GRETunnelInterface_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_GRETunnelInterface_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_GRETunnelInterface_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_GRETunnelInterface_LowerLayers, set_GRETunnelInterface_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"ProtocolIdOverride", &DMWRITE, DMT_UNINT, get_GRETunnelInterface_ProtocolIdOverride, set_GRETunnelInterface_ProtocolIdOverride, NULL, NULL, BBFDM_BOTH},
{"UseChecksum", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_UseChecksum, set_GRETunnelInterface_UseChecksum, NULL, NULL, BBFDM_BOTH},
{"KeyIdentifierGenerationPolicy", &DMWRITE, DMT_STRING, get_GRETunnelInterface_KeyIdentifierGenerationPolicy, set_GRETunnelInterface_KeyIdentifierGenerationPolicy, NULL, NULL, BBFDM_BOTH},
{"KeyIdentifier", &DMWRITE, DMT_UNINT, get_GRETunnelInterface_KeyIdentifier, set_GRETunnelInterface_KeyIdentifier, NULL, NULL, BBFDM_BOTH},
{"UseSequenceNumber", &DMWRITE, DMT_BOOL, get_GRETunnelInterface_UseSequenceNumber, set_GRETunnelInterface_UseSequenceNumber, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Tunnel.{i}.Interface.{i}.Stats. *** */
DMLEAF tGRETunnelInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardChecksumReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_DiscardChecksumReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardSequenceNumberReceived", &DMREAD, DMT_UNINT, get_GRETunnelInterfaceStats_DiscardSequenceNumberReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.GRE.Filter.{i}. *** */
DMLEAF tGREFilterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_GREFilter_Enable, set_GREFilter_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_GREFilter_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Order", &DMWRITE, DMT_UNINT, get_GREFilter_Order, set_GREFilter_Order, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_GREFilter_Alias, set_GREFilter_Alias, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_GREFilter_Interface, set_GREFilter_Interface, NULL, NULL, BBFDM_BOTH},
{"AllInterfaces", &DMWRITE, DMT_BOOL, get_GREFilter_AllInterfaces, set_GREFilter_AllInterfaces, NULL, NULL, BBFDM_BOTH},
{"VLANIDCheck", &DMWRITE, DMT_INT, get_GREFilter_VLANIDCheck, set_GREFilter_VLANIDCheck, NULL, NULL, BBFDM_BOTH},
{"VLANIDExclude", &DMWRITE, DMT_BOOL, get_GREFilter_VLANIDExclude, set_GREFilter_VLANIDExclude, NULL, NULL, BBFDM_BOTH},
{"DSCPMarkPolicy", &DMWRITE, DMT_INT, get_GREFilter_DSCPMarkPolicy, set_GREFilter_DSCPMarkPolicy, NULL, NULL, BBFDM_BOTH},
{0}
};

/*************************************************************
 * ENTRY METHOD
/*************************************************************/
int browseGRETunnelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *gretun_inst= NULL, *gretun_inst_last= NULL;
	struct dmmap_dup *p= NULL;

	LIST_HEAD(dup_list);
	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_network", "proto", "gre", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		gretun_inst = handle_update_instance(1, dmctx, &gretun_inst_last, update_instance_alias, 3, p->dmmap_section, "gretunnel_instance", "gretunnel_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, gretun_inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int browseGREFilterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

struct uci_section *has_tunnel_interface_route(char *interface)
{
	struct uci_section *s;

	uci_foreach_option_eq("network", "route", "interface", interface, s) {
		return s;
	}
	return NULL;
}

int browseGRETunnelInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *greiface_inst= NULL, *greiface_inst_last= NULL, *ifname= NULL;
	struct dmmap_dup *p, *dm= (struct dmmap_dup *)prev_data;
	struct uci_section *s;

	LIST_HEAD(dup_list);
	dmasprintf(&ifname, "@%s", section_name(dm->config_section));
	synchronize_specific_config_sections_with_dmmap_eq("network", "interface", "dmmap_network", "ifname", ifname, &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if ((s = has_tunnel_interface_route(section_name(p->config_section))) == NULL)
			continue;
		greiface_inst = handle_update_instance(1, dmctx, &greiface_inst_last, update_instance_alias, 3, p->dmmap_section, "greiface_instance", "greiface_alias");
		p->additional_attribute= dm->config_section;
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, greiface_inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
 * ADD & DEL OBJ
/*************************************************************/
int addObjGRETunnel(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *value, *v;
	char *instance;
	struct uci_section *gre_sec = NULL, *dmmap_sec= NULL;

	check_create_dmmap_package("dmmap_network");
	instance = get_last_instance_lev2_bbfdm("network", "interface", "dmmap_network", "gretunnel_instance", "proto", "gre");

	dmuci_add_section("network", "interface", &gre_sec, &value);
	dmuci_set_value_by_section(gre_sec, "proto", "gre");

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_sec, &v);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(gre_sec));
	*instancepara = update_instance_bbfdm(dmmap_sec, instance, "gretunnel_instance");
	return 0;
}

int delObjGRETunnel(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL;
	struct uci_section *ss = NULL;
	struct uci_section *dmmap_section;
	int found = 0;
	struct dmmap_dup *p= (struct dmmap_dup *)data;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(p->config_section), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "gretunnel_instance", "");
			dmuci_set_value_by_section(dmmap_section, "gretunnel_alias", "");
			dmuci_delete_by_section(p->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq("network", "interface", "proto", "gre", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL){
						dmuci_set_value_by_section(dmmap_section, "gretunnel_instance", "");
						dmuci_set_value_by_section(dmmap_section, "gretunnel_alias", "");
					}
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL){
				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL){
					dmuci_set_value_by_section(dmmap_section, "gretunnel_instance", "");
					dmuci_set_value_by_section(dmmap_section, "gretunnel_alias", "");
				}
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

int addObjGREFilter(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dmmap_dup *dm = (struct dmmap_dup *)data;
	return 0;
}

int delObjGREFilter(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

int addObjGRETunnelInterface(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *value, *v;
	char *instance, *ifname;
	struct uci_section *greiface_sec = NULL, *dmmap_sec= NULL, *route_sec= NULL;
	struct dmmap_dup *dm= (struct dmmap_dup *)data;

	check_create_dmmap_package("dmmap_network");
	instance= get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_network", "interface", "greiface_instance", "gre_tunnel_sect", section_name(dm->config_section));

	dmuci_add_section("network", "interface", &greiface_sec, &value);
	dmasprintf(&ifname, "@%s", section_name(dm->config_section));
	dmuci_set_value_by_section(greiface_sec, "ifname", ifname);

	dmuci_add_section("network", "route", &route_sec, &value);
	dmuci_set_value_by_section(route_sec, "interface", section_name(greiface_sec));

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_sec, &v);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(greiface_sec));
	dmuci_set_value_by_section(dmmap_sec, "gre_tunnel_sect", section_name(dm->config_section));
	*instancepara = update_instance_bbfdm(dmmap_sec, instance, "greiface_instance");
	return 0;
}

int delObjGRETunnelInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *s1= NULL;
	struct uci_section *ss = NULL;
	struct uci_section *dmmap_section;
	int found = 0;
	struct dmmap_dup *p= (struct dmmap_dup *)data;
	char *iface= NULL, *atiface= NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(p->config_section), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "greiface_instance", "");
			dmuci_set_value_by_section(dmmap_section, "greiface_alias", "");
			if ((s = has_tunnel_interface_route(section_name(p->config_section))) != NULL)
				dmuci_delete_by_section(s, NULL, NULL);
			dmuci_delete_by_section(p->config_section, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("network", "interface", s) {
				dmuci_get_value_by_section_string(s, "ifname", &iface);
				dmasprintf(&atiface, "@%s", section_name(p->config_section));

				if(!iface || strcmp(iface, atiface) != 0)
					continue;
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL){
						dmuci_set_value_by_section(dmmap_section, "greiface_instance", "");
						dmuci_set_value_by_section(dmmap_section, "greiface_alias", "");
					}
					if ((s1 = has_tunnel_interface_route(section_name(ss))) != NULL)
						dmuci_delete_by_section(s1, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL){
				get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL){
					dmuci_set_value_by_section(dmmap_section, "greiface_instance", "");
					dmuci_set_value_by_section(dmmap_section, "greiface_alias", "");
				}
				if ((s1 = has_tunnel_interface_route(section_name(ss))) != NULL)
					dmuci_delete_by_section(s1, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
 * GET & SET PARAM
/*************************************************************/
static char *get_gre_tunnel_interface_statistics(char *interface, char *key)
{
	json_object *res, *diag;
	char *device, *value = "0";

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	device = dmjson_get_value(res, 1, "device");
	if(device[0] != '\0') {
		dmubus_call("network.device", "status", UBUS_ARGS{{"name", device, String}}, 1, &diag);
		value = dmjson_get_value(diag, 2, "statistics", key);
	}
	return value;
}

int get_GRE_TunnelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s= NULL;
	int i= 0;
	uci_foreach_option_eq("network", "interface", "proto", "gre", s) {
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

int get_GRE_FilterNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GRETunnel_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnel_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnel_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GRETunnel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;
	struct dmmap_dup *dm= (struct dmmap_dup *)data;
	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(dm->config_section), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "gretunnel_alias", value);
	return 0;
}

int set_GRETunnel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;
	struct dmmap_dup *dm= (struct dmmap_dup *)data;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(dm->config_section), &dmmap_section);
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(dmmap_section, "gretunnel_alias", value);
			break;
	}
	return 0;
}

int get_GRETunnel_RemoteEndpoints(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnel_RemoteEndpoints(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnel_KeepAlivePolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnel_KeepAlivePolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnel_KeepAliveTimeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnel_KeepAliveTimeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnel_KeepAliveThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *dm= (struct dmmap_dup *)data;

	dmuci_get_value_by_section_string(dm->config_section, "keepalive", value);
	return 0;
}

int set_GRETunnel_KeepAliveThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *dm= (struct dmmap_dup *)data;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(dm->config_section, "keepalive", value);
			break;
	}
	return 0;
}

int get_GRETunnel_DeliveryHeaderProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnel_DeliveryHeaderProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnel_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnel_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnel_ConnectedRemoteEndpoint(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *dm= (struct dmmap_dup *)data;

	dmuci_get_value_by_section_string(dm->config_section, "peeraddr", value);
	return 0;
}

int get_GRETunnel_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *dm= (struct dmmap_dup *)data;
	struct uci_section *s;
	char *ifname;
	int i= 0;

	dmasprintf(&ifname, "@%s", section_name(dm->config_section));
	uci_foreach_option_eq("network", "interface", "ifname", ifname, s) {
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

int get_GRETunnelStats_KeepAliveSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GRETunnelStats_KeepAliveReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GRETunnelStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_bytes");
	return 0;
}

int get_GRETunnelStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_bytes");
	return 0;
}

int get_GRETunnelStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_packets");
	return 0;
}

int get_GRETunnelStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_packets");
	return 0;
}

int get_GRETunnelStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_errors");
	return 0;
}

int get_GRETunnelStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_errors");
	return 0;
}

int get_GRETunnelInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnelInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnelInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GRETunnelInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section= NULL;
	struct dmmap_dup *dm= (struct dmmap_dup *)data;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(dm->config_section), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "greiface_alias", value);
	return 0;
}

int set_GRETunnelInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;
	struct dmmap_dup *dm= (struct dmmap_dup *)data;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(dm->config_section), &dmmap_section);
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(dmmap_section, "greiface_alias", value);
			break;
	}
	return 0;
}

int get_GRETunnelInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name(((struct dmmap_dup *)data)->config_section));
	return 0;
}

int get_GRETunnelInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GRETunnelInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnelInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnelInterface_ProtocolIdOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnelInterface_ProtocolIdOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnelInterface_UseChecksum(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnelInterface_UseChecksum(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnelInterface_KeyIdentifierGenerationPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnelInterface_KeyIdentifierGenerationPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnelInterface_KeyIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnelInterface_KeyIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnelInterface_UseSequenceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GRETunnelInterface_UseSequenceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GRETunnelInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_bytes");
	return 0;
}

int get_GRETunnelInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_bytes");
	return 0;
}

int get_GRETunnelInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_packets");
	return 0;
}

int get_GRETunnelInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_packets");
	return 0;
}

int get_GRETunnelInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "tx_errors");
	return 0;
}

int get_GRETunnelInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= get_gre_tunnel_interface_statistics(section_name(((struct dmmap_dup *)data)->config_section), "rx_errors");
	return 0;
}

int get_GRETunnelInterfaceStats_DiscardChecksumReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GRETunnelInterfaceStats_DiscardSequenceNumberReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GREFilter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GREFilter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GREFilter_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_GREFilter_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GREFilter_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GREFilter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GREFilter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GREFilter_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GREFilter_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GREFilter_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GREFilter_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GREFilter_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GREFilter_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GREFilter_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GREFilter_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_GREFilter_DSCPMarkPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_GREFilter_DSCPMarkPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

