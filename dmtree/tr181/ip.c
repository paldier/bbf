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

#include <uci.h>
#include <stdio.h>
#include <ctype.h>
#include "dmuci.h"
#include "dmubus.h"
#include "dmbbf.h"
#include "dmcommon.h"
#include "ip.h"
#include "dmjson.h"
#include "dmentry.h"
#ifdef BBF_TR143
#include "diagnostics.h"
#endif

struct dm_forced_inform_s IPv4INFRM = {0, get_ipv4_finform};
struct dm_forced_inform_s IPv6INFRM = {0, get_ipv6_finform};

/* *** Device.IP. *** */
DMOBJ tIPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Interface", &DMWRITE, add_ip_interface, delete_ip_interface, NULL, browseIPIfaceInst, NULL, NULL, NULL, tIPInterfaceObj, tIPInterfaceParams, get_linker_ip_interface, BBFDM_BOTH},
#ifdef BBF_TR143
{"Diagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsObj, tIPDiagnosticsParams, NULL, BBFDM_BOTH},
#endif
{0}
};

DMLEAF tIPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IPv4Capable", &DMREAD, DMT_BOOL, get_IP_IPv4Capable, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4Enable", &DMWRITE, DMT_BOOL, get_IP_IPv4Enable, set_IP_IPv4Enable, NULL, NULL, BBFDM_BOTH},
{"IPv4Status", &DMREAD, DMT_STRING, get_IP_IPv4Status, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6Capable", &DMREAD, DMT_BOOL, get_IP_IPv6Capable, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6Enable", &DMWRITE, DMT_BOOL, get_IP_IPv6Enable, set_IP_IPv6Enable, NULL, NULL, BBFDM_BOTH},
{"IPv6Status", &DMREAD, DMT_STRING, get_IP_IPv6Status, NULL, NULL, NULL, BBFDM_BOTH},
{"ULAPrefix", &DMWRITE, DMT_STRING, get_IP_ULAPrefix, set_IP_ULAPrefix, NULL, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_IP_InterfaceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface. *** */
DMOBJ tIPInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"IPv4Address", &DMWRITE, add_ipv4, delete_ipv4, NULL, browseIfaceIPv4Inst, NULL, NULL, NULL, NULL, tIPInterfaceIPv4AddressParams, NULL, BBFDM_BOTH},
{"IPv6Address", &DMWRITE, add_ipv6, delete_ipv6, NULL, browseIfaceIPv6Inst, NULL, NULL, NULL, NULL, tIPInterfaceIPv6AddressParams, NULL, BBFDM_BOTH},
{"IPv6Prefix", &DMWRITE, add_ipv6_prefix, delete_ipv6_prefix, NULL, browseIfaceIPv6PrefixInst, NULL, NULL, NULL, NULL, tIPInterfaceIPv6PrefixParams, get_linker_ipv6_prefix, BBFDM_BOTH},
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPInterfaceStatsParams, NULL, BBFDM_BOTH},
{"TWAMPReflector", &DMWRITE, addObjIPInterfaceTWAMPReflector, delObjIPInterfaceTWAMPReflector, NULL, browseIPInterfaceTWAMPReflectorInst, NULL, NULL, NULL, NULL, tIPInterfaceTWAMPReflectorParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tIPInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterface_Enable, set_IPInterface_Enable, NULL, NULL, BBFDM_BOTH},
{"IPv4Enable", &DMWRITE, DMT_BOOL, get_IPInterface_IPv4Enable, set_IPInterface_IPv4Enable, NULL, NULL, BBFDM_BOTH},
{"IPv6Enable", &DMWRITE, DMT_BOOL, get_IPInterface_IPv6Enable, set_IPInterface_IPv6Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterface_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterface_Alias, set_IPInterface_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_IPInterface_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_IPInterface_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_IPInterface_LowerLayers, set_IPInterface_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"Router", &DMWRITE, DMT_STRING, get_IPInterface_Router, set_IPInterface_Router, NULL, NULL, BBFDM_BOTH},
{"Reset", &DMWRITE, DMT_BOOL, get_IPInterface_Reset, set_IPInterface_Reset, NULL, NULL, BBFDM_BOTH},
{"MaxMTUSize", &DMWRITE, DMT_UNINT, get_IPInterface_MaxMTUSize, set_IPInterface_MaxMTUSize, NULL, NULL, BBFDM_BOTH},
{"Type", &DMREAD, DMT_STRING, get_IPInterface_Type, NULL, NULL, NULL, BBFDM_BOTH},
{"Loopback", &DMWRITE, DMT_BOOL, get_IPInterface_Loopback, set_IPInterface_Loopback, NULL, NULL, BBFDM_BOTH},
{"IPv4AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_IPInterface_IPv4AddressNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_IPInterface_IPv6AddressNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6PrefixNumberOfEntries", &DMREAD, DMT_UNINT, get_IPInterface_IPv6PrefixNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"TWAMPReflectorNumberOfEntries", &DMREAD, DMT_UNINT, get_IPInterface_TWAMPReflectorNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.IPv4Address.{i}. *** */
DMLEAF tIPInterfaceIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterface_Enable, set_IPInterface_Enable, &IPv4INFRM, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterface_Status, NULL, &IPv4INFRM, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_ipv4_alias, set_ipv4_alias, &IPv4INFRM, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"FirewallEnabled", &DMWRITE, DMT_BOOL, get_firewall_enabled, set_firewall_enabled, &IPv4INFRM, NULL, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_ipv4_address, set_ipv4_address, &IPv4INFRM, NULL, BBFDM_BOTH},
{"SubnetMask", &DMWRITE, DMT_STRING, get_ipv4_netmask, set_ipv4_netmask, &IPv4INFRM, NULL, BBFDM_BOTH},
{"AddressingType", &DMWRITE, DMT_STRING, get_ipv4_addressing_type, set_ipv4_addressing_type, &IPv4INFRM, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.IPv6Address.{i}. *** */
DMLEAF tIPInterfaceIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv6Address_Enable, set_IPInterfaceIPv6Address_Enable, &IPv6INFRM, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Address_Status, NULL, &IPv6INFRM, NULL, BBFDM_BOTH},
{"IPAddressStatus", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Address_IPAddressStatus, NULL, &IPv6INFRM, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Address_Alias, set_IPInterfaceIPv6Address_Alias, &IPv6INFRM, NULL, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Address_IPAddress, set_IPInterfaceIPv6Address_IPAddress, &IPv6INFRM, NULL, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Address_Origin, NULL, &IPv6INFRM, NULL, BBFDM_BOTH},
{"Prefix", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Address_Prefix, set_IPInterfaceIPv6Address_Prefix, &IPv6INFRM, NULL, BBFDM_BOTH},
{"PreferredLifetime", &DMWRITE, DMT_TIME, get_IPInterfaceIPv6Address_PreferredLifetime, set_IPInterfaceIPv6Address_PreferredLifetime, &IPv6INFRM, NULL, BBFDM_BOTH},
{"ValidLifetime", &DMWRITE, DMT_TIME, get_IPInterfaceIPv6Address_ValidLifetime, set_IPInterfaceIPv6Address_ValidLifetime, &IPv6INFRM, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.IPv6Prefix.{i}. *** */
DMLEAF tIPInterfaceIPv6PrefixParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterfaceIPv6Prefix_Enable, set_IPInterfaceIPv6Prefix_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Prefix_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"PrefixStatus", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Prefix_PrefixStatus, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_Alias, set_IPInterfaceIPv6Prefix_Alias, NULL, NULL, BBFDM_BOTH},
{"Prefix", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_Prefix, set_IPInterfaceIPv6Prefix_Prefix, NULL, NULL, BBFDM_BOTH},
{"Origin", &DMREAD, DMT_STRING, get_IPInterfaceIPv6Prefix_Origin, NULL, NULL, NULL, BBFDM_BOTH},
{"StaticType", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_StaticType, set_IPInterfaceIPv6Prefix_StaticType, NULL, NULL, BBFDM_BOTH},
{"ParentPrefix", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_ParentPrefix, set_IPInterfaceIPv6Prefix_ParentPrefix, NULL, NULL, BBFDM_BOTH},
{"ChildPrefixBits", &DMWRITE, DMT_STRING, get_IPInterfaceIPv6Prefix_ChildPrefixBits, set_IPInterfaceIPv6Prefix_ChildPrefixBits, NULL, NULL, BBFDM_BOTH},
{"PreferredLifetime", &DMWRITE, DMT_TIME, get_IPInterfaceIPv6Prefix_PreferredLifetime, set_IPInterfaceIPv6Prefix_PreferredLifetime, NULL, NULL, BBFDM_BOTH},
{"ValidLifetime", &DMWRITE, DMT_TIME, get_IPInterfaceIPv6Prefix_ValidLifetime, set_IPInterfaceIPv6Prefix_ValidLifetime, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.Stats. *** */
DMLEAF tIPInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNINT, get_ip_interface_statistics_tx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_ip_interface_statistics_rx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_ip_interface_statistics_tx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_ip_interface_statistics_rx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_ip_interface_statistics_tx_errors, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_ip_interface_statistics_rx_errors, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_ip_interface_statistics_tx_discardpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_ip_interface_statistics_rx_discardpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNINT, get_ip_interface_statistics_tx_unicastpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNINT, get_ip_interface_statistics_rx_unicastpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNINT, get_ip_interface_statistics_tx_multicastpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNINT, get_ip_interface_statistics_rx_multicastpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNINT, get_ip_interface_statistics_tx_broadcastpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNINT, get_ip_interface_statistics_rx_broadcastpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_ip_interface_statistics_rx_unknownprotopackets, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Interface.{i}.TWAMPReflector.{i}. *** */
DMLEAF tIPInterfaceTWAMPReflectorParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPInterfaceTWAMPReflector_Enable, set_IPInterfaceTWAMPReflector_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_IPInterfaceTWAMPReflector_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_IPInterfaceTWAMPReflector_Alias, set_IPInterfaceTWAMPReflector_Alias, NULL, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_IPInterfaceTWAMPReflector_Port, set_IPInterfaceTWAMPReflector_Port, NULL, NULL, BBFDM_BOTH},
{"MaximumTTL", &DMWRITE, DMT_UNINT, get_IPInterfaceTWAMPReflector_MaximumTTL, set_IPInterfaceTWAMPReflector_MaximumTTL, NULL, NULL, BBFDM_BOTH},
{"IPAllowedList", &DMWRITE, DMT_STRING, get_IPInterfaceTWAMPReflector_IPAllowedList, set_IPInterfaceTWAMPReflector_IPAllowedList, NULL, NULL, BBFDM_BOTH},
{"PortAllowedList", &DMWRITE, DMT_STRING, get_IPInterfaceTWAMPReflector_PortAllowedList, set_IPInterfaceTWAMPReflector_PortAllowedList, NULL, NULL, BBFDM_BOTH},
{0}
};

unsigned char get_ipv4_finform(char *refparam, struct dmctx *dmctx, void *data, char *instance)
{
	return 1;
}

unsigned char get_ipv6_finform(char *refparam, struct dmctx *dmctx, void *data, char *instance)
{
	return 1;
}

/*************************************************************
 * INIT
/*************************************************************/
inline int init_ip_args(struct ip_args *args, struct uci_section *s, char *ip_4address)
{
	args->ip_sec = s;
	args->ip_4address = ip_4address;
	return 0;
}

inline int init_ipv6_args(struct ipv6_args *args, struct uci_section *s, char *ip_6address, char *ip_6mask, char *ip_6preferred, char *ip_6valid)
{
	args->ip_sec = s;
	args->ip_6address = ip_6address;
	args->ip_6mask = ip_6mask;
	args->ip_6preferred = ip_6preferred;
	args->ip_6valid = ip_6valid;
	return 0;
}

inline int init_ipv6prefix_args(struct ipv6prefix_args *args, struct uci_section *s, char *ip_6prefixaddress, char *ip_6prefixmask, char *ip_6prefixpreferred, char *ip_6prefixvalid)
{
	args->ip_sec = s;
	args->ip_6prefixaddress = ip_6prefixaddress;
	args->ip_6prefixmask = ip_6prefixmask;
	args->ip_6prefixpreferred = ip_6prefixpreferred;
	args->ip_6prefixvalid = ip_6prefixvalid;
	return 0;
}

/*************************************************************
 * COMMON Functions
/*************************************************************/
static char *ubus_call_get_value_with_two_objects(char *interface, char *obj1, char *obj2, char *key)
{
	json_object *res, *jobj1, *jobj2;
	char *value = "";

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	if (res)
	{
		jobj1 = dmjson_select_obj_in_array_idx(res, 0, 1, obj1);
		if(jobj1)
			jobj2 = dmjson_get_obj(jobj1, 1, obj2);
		if(jobj2)
			value = dmjson_get_value(jobj2, 1, key);
	}
	return value;
}

static char *ubus_call_get_value(char *interface, char *obj, char *key)
{
	json_object *res, *jobj;
	char *value = "";

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	if (res)
	{
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, obj);
		value = dmjson_get_value(jobj, 1, key);
	}
	return value;
}

static char *get_child_prefix_linker(char *interface)
{
	char *address = NULL, *mask = NULL, *value;
	json_object *res, *jobj, *jobj1, *jobj2;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
	if(res) {
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-prefix");
		if(jobj) {
			jobj1 = dmjson_get_obj(jobj, 1, "assigned");
			if(jobj1) {
				jobj2 = dmjson_get_obj(jobj1, 1, "lan");
				if(jobj2) {
					address = dmjson_get_value(jobj2, 1, "address");
					mask = dmjson_get_value(jobj2, 1, "mask");
					dmasprintf(&value, "%s/%s", address,mask);
					return value;
				}
			}
		}
	}
	return "";
}

/*************************************************************
 * GET & SET PARAM
/*************************************************************/
/*
 * *** Device.IP. ***
 */
int get_IP_IPv4Capable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int get_IP_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int set_IP_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IP_IPv4Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

int get_IP_IPv6Capable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int get_IP_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int set_IP_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IP_IPv6Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

int get_IP_ULAPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("network", "globals", "ula_prefix", value);
	return 0;
}

int set_IP_ULAPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value("network", "globals", "ula_prefix", value);
			break;
	}
	return 0;
}

int get_IP_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("network", "interface", s) {
		if (strcmp(section_name(s), "loopback") == 0)
			continue;
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*
 * *** Device.IP.Interface. ***
 */
/*#Device.IP.Interface.{i}.Enable!UCI:network/interface,@i-1/disabled*/
int get_IPInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct ip_args *)data)->ip_sec, "disabled", &v);
	*value = (*v != '1') ? "1" : "0";
	return 0;
}

int set_IPInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "disabled", (b) ? "0" : "1");
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.Status!UCI:network/interface,@i-1/disabled*/
int get_IPInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *lan_name = section_name(((struct ip_args *)data)->ip_sec), *val= NULL;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", lan_name, String}}, 1, &res);
	val = dmjson_get_value(res, 1, "up");
	*value = !strcmp(val, "true") ? "Up" : "Down";
	return 0;
}

int get_IPInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name(((struct ip_args *)data)->ip_sec));
	return 0;
}

int get_IPInterface_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int set_IPInterface_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Enable!UCI:network/interface,@i-1/ipv6*/
int get_IPInterface_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;
	dmuci_get_value_by_section_string(((struct ip_args *)data)->ip_sec, "ipv6", &v);
	*value = (*v != '0') ? "1" : "0";
	return 0;
}

int set_IPInterface_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ipv6", (b) ? "" : "0");
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.LastChange!UBUS:network.interface/status/interface,@Name/uptime*/
int get_IPInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct ip_args *)data)->ip_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "uptime");
	return 0;
}

int get_IPInterface_Router(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Device.Routing.Router.1.";
	return 0;
}

int set_IPInterface_Router(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

int set_IPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if(b) {
				set_interface_enable_ubus(section_name(((struct ip_args *)data)->ip_sec), refparam, ctx, action, "0");
				set_interface_enable_ubus(section_name(((struct ip_args *)data)->ip_sec), refparam, ctx, action, "1");
			}
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.MaxMTUSize!UBUS:network.interface/status/interface,@Name/mtu*/
int get_IPInterface_MaxMTUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res, *diag;
	char *device= NULL;

	dmuci_get_value_by_section_string(((struct ip_args *)data)->ip_sec, "mtu", value);
	if(*value[0] == '\0') {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct ip_args *)data)->ip_sec), String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		device = dmjson_get_value(res, 1, "device");
		if(device) {
			dmubus_call("network.device", "status", UBUS_ARGS{{"name", device, String}}, 1, &diag);
			DM_ASSERT(diag, *value = "");
			*value = dmjson_get_value(diag, 1, "mtu");
		}
		return 0;
	}
	return 0;
}

int set_IPInterface_MaxMTUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "mtu", value);
			break;
	}
	return 0;
}

int get_IPInterface_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (strcmp(section_name(((struct ip_args *)data)->ip_sec), "loopback") == 0)
		*value = "Loopback";
	else
		*value = "Normal";
	return 0;
}

int get_IPInterface_Loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (strcmp(section_name(((struct ip_args *)data)->ip_sec), "loopback") == 0)
		*value = "1";
	else
		*value = "0";
	return 0;
}

int set_IPInterface_Loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IPInterface_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	char *inst;

	*value = "0";
	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "interface", "section_name", section_name(((struct ip_args *)data)->ip_sec), s) {
		dmuci_get_value_by_section_string(s, "ipv4_instance", &inst);
		if(inst[0] != '\0')
			*value = "1";
	}
	return 0;
}

int get_IPInterface_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int cnt = 0;

	*value = "0";
	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6", "section_name", section_name(((struct ip_args *)data)->ip_sec), s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

int get_IPInterface_IPv6PrefixNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int cnt = 0;

	*value = "0";
	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6prefix", "section_name", section_name(((struct ip_args *)data)->ip_sec), s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

int get_IPInterface_TWAMPReflectorNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;
	uci_foreach_option_eq("cwmp_twamp", "twamp_refector", "interface", section_name(((struct ip_args *)data)->ip_sec), s) {
			cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*
 * *** Device.IP.Interface.{i}.IPv4Address.{i}. ***
 */
int get_firewall_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_interface_firewall_enabled(section_name(((struct ip_args *)data)->ip_sec), refparam, ctx, value);
	return 0;
}

int set_firewall_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	set_interface_firewall_enabled(section_name(((struct ip_args *)data)->ip_sec), refparam, ctx, action, value);
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.IPAddress!UCI:network/interface,@i-1/ipaddr*/
int get_ipv4_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct ip_args *)data)->ip_4address;
	return 0;
}

int set_ipv4_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct ip_args *)data)->ip_sec, "proto", &proto);
			if(strcmp(proto, "static") == 0)
				dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ipaddr", value);
			return 0;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.SubnetMask!UCI:network/interface,@i-1/netmask*/
int get_ipv4_netmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res, *jobj;
	char *mask;

	dmuci_get_value_by_section_string(((struct ip_args *)data)->ip_sec, "netmask", &mask);
	if (mask[0] == '\0') {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct ip_args *)data)->ip_sec), String}}, 1, &res);
		if (res) {
			jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
			mask = dmjson_get_value(jobj, 1, "mask");
			if (mask[0] == '\0')
				return 0;
			mask = cidr2netmask(atoi(mask));
		}
	}
	*value = mask;
	return 0;
}

int set_ipv4_netmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct ip_args *)data)->ip_sec, "proto", &proto);
			if(strcmp(proto, "static") == 0)
				dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "netmask", value);
			return 0;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv4Address.{i}.AddressingType!UCI:network/interface,@i-1/proto*/
int get_ipv4_addressing_type (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct ip_args *)data)->ip_sec, "proto", value);
	if (strcmp(*value, "static") == 0)
		*value = "Static";
	else if (strcmp(*value, "dhcp") == 0)
		*value = "DHCP";
	else
		*value = "";
	return 0;
}

int set_ipv4_addressing_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if(strcasecmp(value, "static") == 0) {
				dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "proto", "static");
				dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ipaddr", "0.0.0.0");
			}
			if(strcasecmp(value, "dhcp") == 0) {
				dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "proto", "dhcp");
				dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ipaddr", "");
			}
			return 0;
	}
	return 0;
}

int get_IPInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;
	char linker[64] = "", *proto, *device, *mac;

	dmuci_get_value_by_section_string(((struct ip_args *)data)->ip_sec, "proto", &proto);
	if (strstr(proto, "ppp")) {
		sprintf(linker, "%s", section_name(((struct ip_args *)data)->ip_sec));
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cPPP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
		goto end;
	}

	device = get_device(section_name(((struct ip_args *)data)->ip_sec));
	if (device[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cVLANTermination%c", dmroot, dm_delim, dm_delim, dm_delim), device, value);
		if (*value != NULL)
			return 0;
	}

	mac = get_macaddr(section_name(((struct ip_args *)data)->ip_sec));
	if (mac[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), mac, value);
		goto end;
	}

end :
	if (*value == NULL)
		*value = "";
	return 0;
}

int set_IPInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL, *newvalue = NULL;
	struct uci_section *s;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (value[strlen(value)-1]!='.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else
				adm_entry_get_linker_value(ctx, value, &linker);

			if (linker)
				dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ifname", linker);
			else
				return FAULT_9005;

			return 0;
	}
	return 0;
}

/*
 * *** Device.IP.Interface.{i}.IPv6Address.{i}. ***
 */
/*#Device.IP.Interface.{i}.IPv6Address.{i}.IPAddress!UCI:network/interface,@i-1/ip6addr*/
int get_IPInterfaceIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct ipv6_args *)data)->ip_6address;
	if(((struct ipv6_args *)data)->ip_6mask[0] != '\0')
		dmasprintf(value, "%s/%s", ((struct ipv6_args *)data)->ip_6address, ((struct ipv6_args *)data)->ip_6mask);
	return 0;
}

int set_IPInterfaceIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct ipv6_args *)data)->ip_sec, "proto", &proto);
			if(strcmp(proto, "static") == 0)
				dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ip6addr", value);
			return 0;
	}
	return 0;
}

int get_IPInterfaceIPv6Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int set_IPInterfaceIPv6Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IPInterfaceIPv6Address_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

int get_IPInterfaceIPv6Address_IPAddressStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct ipv6_args *)data)->ip_6valid[0] != '\0')
		*value = "Preferred";
	else
		*value = "Unknown";
	return 0;
}

int get_IPInterfaceIPv6Address_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ubus_call_get_value_with_two_objects(section_name(((struct ipv6_args *)data)->ip_sec), "ipv6-prefix-assignment", "local-address", "address");
	if(*value[0] != '\0')
		*value = "AutoConfigured";
	else {
		dmuci_get_value_by_section_string(((struct ipv6_args *)data)->ip_sec, "proto", value);
		if (strcmp(*value, "static") == 0)
			*value = "Static";
		else if (strcmp(*value, "dhcpv6") == 0)
			*value = "DHCPv6";
		else
			*value = "WellKnown";
	}
	return 0;
}

int get_IPInterfaceIPv6Address_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;
	char *inst;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ipv6_args *)data)->ip_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ip_int_instance", &inst);

	*value = "";
	if(((struct ipv6prefix_args *)data)->ip_6prefixaddress[0] != '\0')
		dmasprintf(value, "Device.IP.Interface.%s.IPv6Prefix.1.", inst);
	return 0;
}

int set_IPInterfaceIPv6Address_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.PreferredLifetime!UCI:network/interface,@i-1/adv_preferred_lifetime*/
int get_IPInterfaceIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char local_time[32] = {0};
	char *preferred = ((struct ipv6_args *)data)->ip_6preferred;
	*value = "0001-01-01T00:00:00Z";
	if (get_shift_time_time(atoi(preferred), local_time, sizeof(local_time)) == -1)
		return 0;
	*value = dmstrdup(local_time);
	return 0;
}

int set_IPInterfaceIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[32] = "", *proto;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct ipv6_args *)data)->ip_sec, "proto", &proto);
			if(strcasecmp(proto, "static") == 0) {
				get_shift_time_shift(value, buf);
				if (!(*buf))
					return 0;
				dmuci_set_value_by_section(((struct ipv6_args *)data)->ip_sec, "adv_preferred_lifetime", buf);
			}
			return 0;
	}
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Address.{i}.ValidLifetime!UCI:network/interface,@i-1/adv_valid_lifetime*/
int get_IPInterfaceIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char local_time[32] = {0};
	char *preferred = ((struct ipv6_args *)data)->ip_6valid;
	*value = "0001-01-01T00:00:00Z";
	if (get_shift_time_time(atoi(preferred), local_time, sizeof(local_time)) == -1)
		return 0;
	*value = dmstrdup(local_time);
	return 0;
}

int set_IPInterfaceIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[32] = "", *proto;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct ipv6_args *)data)->ip_sec, "proto", &proto);
			if(strcasecmp(proto, "static") == 0) {
				get_shift_time_shift(value, buf);
				if (!(*buf))
					return 0;
				dmuci_set_value_by_section(((struct ipv6_args *)data)->ip_sec, "adv_valid_lifetime", buf);
			}
			return 0;
	}
	return 0;
}

/*
 * *** Device.IP.Interface.{i}.IPv6Prefix.{i}. ***
 */
int get_IPInterfaceIPv6Prefix_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int set_IPInterfaceIPv6Prefix_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IPInterfaceIPv6Prefix_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Enabled";
	return 0;
}

int get_IPInterfaceIPv6Prefix_PrefixStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct ipv6prefix_args *)data)->ip_6prefixvalid[0] != '\0')
		*value = "Preferred";
	else
		*value = "Unknown";
	return 0;
}

/*#Device.IP.Interface.{i}.IPv6Prefix.{i}.Prefix!UCI:network/interface,@i-1/ip6prefix*/
int get_IPInterfaceIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ((struct ipv6prefix_args *)data)->ip_6prefixaddress;
	if(((struct ipv6prefix_args *)data)->ip_6prefixmask[0] != '\0')
		dmasprintf(value, "%s/%s", ((struct ipv6prefix_args *)data)->ip_6prefixaddress, ((struct ipv6prefix_args *)data)->ip_6prefixmask);
	return 0;
}

int set_IPInterfaceIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *proto;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct ipv6prefix_args *)data)->ip_sec, "proto", &proto);
			if(strcmp(proto, "static") == 0)
				dmuci_set_value_by_section(((struct ipv6prefix_args *)data)->ip_sec, "ip6prefix", value);
			return 0;
	}
	return 0;
}

int get_IPInterfaceIPv6Prefix_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ubus_call_get_value(section_name(((struct ipv6prefix_args *)data)->ip_sec), "ipv6-prefix-assignment", "address");
	if(*value[0] != '\0')
		*value = "AutoConfigured";
	else {
		dmuci_get_value_by_section_string(((struct ipv6prefix_args *)data)->ip_sec, "proto", value);
		if (strcmp(*value, "static") == 0)
			*value = "Static";
		else if (strcmp(*value, "dhcpv6") == 0)
			*value = "DHCPv6";
		else
			*value = "WellKnown";
	}
	return 0;
}

int get_IPInterfaceIPv6Prefix_StaticType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Static";
	return 0;
}

int set_IPInterfaceIPv6Prefix_StaticType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IPInterfaceIPv6Prefix_ParentPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;
	dmasprintf(&linker, "%s/%s", ((struct ipv6prefix_args *)data)->ip_6prefixaddress, ((struct ipv6prefix_args *)data)->ip_6prefixmask);
	if(linker[0] != '\0')
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%Interface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int set_IPInterfaceIPv6Prefix_ParentPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IPInterfaceIPv6Prefix_ChildPrefixBits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_child_prefix_linker(section_name(((struct ipv6prefix_args *)data)->ip_sec));
	return 0;
}

int set_IPInterfaceIPv6Prefix_ChildPrefixBits(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IPInterfaceIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char local_time[32] = {0};
	char *preferred = ((struct ipv6prefix_args *)data)->ip_6prefixpreferred;
	*value = "0001-01-01T00:00:00Z";
	if (get_shift_time_time(atoi(preferred), local_time, sizeof(local_time)) == -1)
		return 0;
	*value = dmstrdup(local_time);
	return 0;
}

int set_IPInterfaceIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int get_IPInterfaceIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char local_time[32] = {0};
	char *preferred = ((struct ipv6prefix_args *)data)->ip_6prefixvalid;
	*value = "0001-01-01T00:00:00Z";
	if (get_shift_time_time(atoi(preferred), local_time, sizeof(local_time)) == -1)
		return 0;
	*value = dmstrdup(local_time);
	return 0;
}

int set_IPInterfaceIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*
 * *** Device.IP.Interface.{i}.Stats. ***
 */
static char *get_ip_interface_statistics(char *interface, char *key)
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

int get_ip_interface_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "tx_bytes");
	return 0;
}

int get_ip_interface_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "rx_bytes");
	return 0;
}

int get_ip_interface_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "tx_packets");
	return 0;
}

int get_ip_interface_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "rx_packets");
	return 0;
}

int get_ip_interface_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "tx_errors");
	return 0;
}

int get_ip_interface_statistics_rx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "rx_errors");
	return 0;
}

int get_ip_interface_statistics_tx_discardpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "tx_dropped");
	return 0;
}

int get_ip_interface_statistics_rx_discardpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "rx_dropped");
	return 0;
}

int get_ip_interface_statistics_tx_unicastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	char *device = get_device(section_name(((struct ip_args *)data)->ip_sec));
	if(device[0] != '\0')
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(device, "TX", "unicast"));
	return 0;
}

int get_ip_interface_statistics_rx_unicastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	char *device = get_device(section_name(((struct ip_args *)data)->ip_sec));
	if(device[0] != '\0')
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(device, "RX", "unicast"));
	return 0;
}

int get_ip_interface_statistics_tx_multicastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	char *device = get_device(section_name(((struct ip_args *)data)->ip_sec));
	if(device[0] != '\0')
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(device, "TX", "multicast"));
	return 0;
}

int get_ip_interface_statistics_rx_multicastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	char *device = get_device(section_name(((struct ip_args *)data)->ip_sec));
	if(device[0] != '\0')
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(device, "RX", "multicast"));
	return 0;
}

int get_ip_interface_statistics_tx_broadcastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	char *device = get_device(section_name(((struct ip_args *)data)->ip_sec));
	if(device[0] != '\0')
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(device, "TX", "broadcast"));
	return 0;
}

int get_ip_interface_statistics_rx_broadcastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	char *device = get_device(section_name(((struct ip_args *)data)->ip_sec));
	if(device[0] != '\0')
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(device, "RX", "broadcast"));
	return 0;
}

int get_ip_interface_statistics_rx_unknownprotopackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_ip_interface_statistics(section_name(((struct ip_args *)data)->ip_sec), "rx_over_errors");
	return 0;
}

/*
 * *** Device.IP.Interface.{i}.TWAMPReflector.{i}. ***
 */
int get_IPInterfaceTWAMPReflector_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	return 0;
}

int set_IPInterfaceTWAMPReflector_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct uci_section *s;
	char *type, *interface, *device, *id, *ipv4addr = "";
	json_object *res, *jobj;

	switch (action)	{
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if(b) {
				dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &interface);
				dmuci_get_value_by_section_string((struct uci_section *)data, "id", &id);
				dmuci_set_value_by_section((struct uci_section *)data, "enable", "1");
				dmuci_set_value("cwmp_twamp", "twamp", "id", id);
				uci_foreach_sections("network", "interface", s) {
					if(strcmp(section_name(s), interface) != 0)
						continue;
					dmuci_get_value_by_section_string(s, "ipaddr", &ipv4addr);
					break;
				}
				if (ipv4addr[0] == '\0') {
					dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
					if (res)
					{
						jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
						ipv4addr = dmjson_get_value(jobj, 1, "address");
						if (ipv4addr[0] == '\0')
							dmuci_set_value_by_section((struct uci_section *)data, "ip_version", "6");
						else
							dmuci_set_value_by_section((struct uci_section *)data, "ip_version", "4");
					}
				}
				else
					dmuci_set_value_by_section((struct uci_section *)data, "ip_version", "4");
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", interface, String}}, 1, &res);
				if (res)
				{
					device = dmjson_get_value(res, 1, "device");
					dmuci_set_value_by_section((struct uci_section *)data, "device", device);
				}
			} else {
				dmuci_set_value_by_section((struct uci_section *)data, "enable", "0");
			}
			break;
	}
	return 0;
}

int get_IPInterfaceTWAMPReflector_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *enable;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", &enable);
	if(strcmp(enable, "1")==0)
		*value = "Active";
	else
		*value = "Disabled";
	return 0;
}

int get_IPInterfaceTWAMPReflector_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "twamp_alias", value);
	return 0;
}

int set_IPInterfaceTWAMPReflector_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "twamp_alias", value);
			break;
	}
	return 0;
}

int get_IPInterfaceTWAMPReflector_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "port", value);
	return 0;
}

int set_IPInterfaceTWAMPReflector_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "port", value);
			break;
	}
	return 0;
}

int get_IPInterfaceTWAMPReflector_MaximumTTL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "max_ttl", value);
	return 0;
}

int set_IPInterfaceTWAMPReflector_MaximumTTL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "max_ttl", value);
			break;
	}
	return 0;
}

int get_IPInterfaceTWAMPReflector_IPAllowedList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ip_list", value);
	return 0;
}

int set_IPInterfaceTWAMPReflector_IPAllowedList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "ip_list", value);
			break;
	}
	return 0;
}

int get_IPInterfaceTWAMPReflector_PortAllowedList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "port_list", value);
	return 0;
}

int set_IPInterfaceTWAMPReflector_PortAllowedList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "port_list", value);
			break;
	}
	return 0;
}

/*************************************************************
 * GET & SET ALIAS
/*************************************************************/
int get_IPInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ip_args *)data)->ip_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ip_int_alias", value);
	return 0;
}

int set_IPInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section =NULL;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ip_args *)data)->ip_sec), &dmmap_section);
			if(dmmap_section != NULL)
				dmuci_set_value_by_section(dmmap_section, "ip_int_alias", value);
			return 0;
	}
	return 0;
}

int get_ipv4_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ip_args *)data)->ip_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ipv4_alias", value);
	return 0;
}

int set_ipv4_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section =NULL;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ip_args *)data)->ip_sec), &dmmap_section);
			if(dmmap_section != NULL)
				dmuci_set_value_by_section(dmmap_section, "ipv4_alias", value);
			return 0;
	}
	return 0;
}

int get_IPInterfaceIPv6Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;
	char *name;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6", "ipv6_instance", instance, dmmap_section) {
		dmuci_get_value_by_section_string(dmmap_section, "section_name", &name);
		if(strcmp(name, section_name(((struct ipv6_args *)data)->ip_sec)) == 0)
			dmuci_get_value_by_section_string(dmmap_section, "ipv6_alias", value);
	}
	return 0;
}

int set_IPInterfaceIPv6Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;
	char *name;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6", "ipv6_instance", instance, dmmap_section) {
				dmuci_get_value_by_section_string(dmmap_section, "section_name", &name);
				if(strcmp(name, section_name(((struct ipv6_args *)data)->ip_sec)) == 0)
					break;
			}
			dmuci_set_value_by_section(dmmap_section, "ipv6_alias", value);
			return 0;
	}
	return 0;
}

int get_IPInterfaceIPv6Prefix_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;
	char *name;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6prefix", "ipv6prefix_instance", instance, dmmap_section) {
		dmuci_get_value_by_section_string(dmmap_section, "section_name", &name);
		if(strcmp(name, section_name(((struct ipv6prefix_args *)data)->ip_sec)) == 0)
			dmuci_get_value_by_section_string(dmmap_section, "ipv6prefix_alias", value);
	}
	return 0;
}

int set_IPInterfaceIPv6Prefix_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;
	char *name;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6prefix", "ipv6prefix_instance", instance, dmmap_section) {
				dmuci_get_value_by_section_string(dmmap_section, "section_name", &name);
				if(strcmp(name, section_name(((struct ipv6prefix_args *)data)->ip_sec)) == 0)
					break;
			}
			dmuci_set_value_by_section(dmmap_section, "ipv6prefix_alias", value);
			return 0;
	}
	return 0;
}

/*************************************************************
 * ADD & DEL OBJ
/*************************************************************/
char *get_last_instance_cond(char* dmmap_package, char *package, char *section, char *opt_inst, char *opt_cond, char *cond_val, char *opt_filter, char *filter_val, char *refused_interface)
{
	struct uci_section *s, *dmmap_section;
	char *inst = NULL, *val, *val_f;
	char *type, *ipv4addr = "", *ipv6addr = "", *proto;
	json_object *res, *jobj;

	uci_foreach_sections(package, section, s) {
		if (opt_cond) dmuci_get_value_by_section_string(s, opt_cond, &val);
		if (opt_filter) dmuci_get_value_by_section_string(s, opt_filter, &val_f);
		if(opt_cond && opt_filter && (strcmp(val, cond_val) == 0 || strcmp(val_f, filter_val) == 0))
			continue;
		if (strcmp(section_name(s), refused_interface)==0)
			continue;

		dmuci_get_value_by_section_string(s, "ipaddr", &ipv4addr);
		if (ipv4addr[0] == '\0') {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
			if (res)
			{
				jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
				ipv4addr = dmjson_get_value(jobj, 1, "address");
			}
		}
		dmuci_get_value_by_section_string(s, "ip6addr", &ipv6addr);
		if (ipv6addr[0] == '\0') {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
			if (res)
			{
				jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
				ipv6addr = dmjson_get_value(jobj, 1, "address");
			}
		}
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (ipv4addr[0] == '\0' && ipv6addr[0] == '\0' && strcmp(proto, "dhcp") != 0 && strcmp(proto, "dhcpv6") != 0 && strcmp(val, "bridge") != 0) {
			continue;
		}
		get_dmmap_section_of_config_section(dmmap_package, section, section_name(s), &dmmap_section);
		inst = update_instance_bbfdm(dmmap_section, inst, opt_inst);
	}
	return inst;
}

int add_ip_interface(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *last_inst, *v;
	char ip_name[32], ib[8];
	char *p = ip_name;
	struct uci_section *dmmap_ip_interface, *dmmap_section;

	last_inst = get_last_instance_cond("dmmap_network", "network", "interface", "ip_int_instance", "type", "alias", "proto", "", "loopback");
	sprintf(ib, "%d", last_inst ? atoi(last_inst)+1 : 1);
	dmstrappendstr(p, "ip_interface_");
	dmstrappendstr(p, ib);
	dmstrappendend(p);
	dmuci_set_value("network", ip_name, "", "interface");
	dmuci_set_value("network", ip_name, "proto", "dhcp");

	dmuci_add_section_bbfdm("dmmap_network", "interface", &dmmap_ip_interface, &v);
	dmuci_set_value_by_section(dmmap_ip_interface, "section_name", ip_name);
	*instance = update_instance_bbfdm(dmmap_ip_interface, last_inst, "ip_int_instance");
	return 0;
}

int delete_ip_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section = NULL;

	switch (del_action) {
	case DEL_INST:
		dmuci_delete_by_section(((struct ip_args *)data)->ip_sec, NULL, NULL);
		get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ip_args *)data)->ip_sec), &dmmap_section);
		if(dmmap_section != NULL)
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
		break;
	case DEL_ALL:
		return FAULT_9005;
	}
	return 0;
}

int add_ipv4(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *instance;
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ip_args *)data)->ip_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ipv4_instance", &instance);
	*instancepara = update_instance_bbfdm(dmmap_section, instance, "ipv4_instance");
	if(instance[0] == '\0') {
		dmuci_set_value_by_section(dmmap_section, "ipv4_instance", *instancepara);
		dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ipaddr", "0.0.0.0");
		dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "proto", "static");
	}
	return 0;
}

int delete_ipv4(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section;

	switch (del_action) {
	case DEL_INST:
		dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ipaddr", "");
		dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "proto", "");
		get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ip_args *)data)->ip_sec), &dmmap_section);
		if(dmmap_section != NULL)
			dmuci_set_value_by_section(dmmap_section, "ipv4_instance", "");
		break;
	case DEL_ALL:
		return FAULT_9005;
	}
	return 0;
}

int add_ipv6(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *s, *ss;
	char *ip, *name, *inst, *curr_inst;

	uci_foreach_sections("network", "interface", s) {
		if(strcmp(section_name(s), section_name(((struct ipv6_args *)data)->ip_sec)) != 0)
			continue;
		dmuci_get_value_by_section_string(s, "ip6addr", &ip);
		break;
	}
	if(ip[0] == '\0') {
		uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6", "section_name", section_name(((struct ipv6_args *)data)->ip_sec), s) {
			dmuci_get_value_by_section_string(s, "ipv6_instance", &inst);
		}
		dmasprintf(&curr_inst, "%d", atoi(inst)+1);
		dmuci_set_value_by_section(((struct ipv6_args *)data)->ip_sec, "ip6addr", "::");
		dmuci_set_value_by_section(((struct ipv6_args *)data)->ip_sec, "proto", "static");
		DMUCI_ADD_SECTION(bbfdm, "dmmap_network", "ipv6", &ss, &name);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, ss, "section_name", section_name(((struct ipv6_args *)data)->ip_sec));
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, ss, "ipv6_instance", curr_inst);
	}
	return 0;
}

int delete_ipv6(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_network", "ipv6", section_name(((struct ipv6_args *)data)->ip_sec), &dmmap_section);
	switch (del_action) {
	case DEL_INST:
		dmuci_set_value_by_section(((struct ipv6_args *)data)->ip_sec, "ip6addr", "");
		dmuci_set_value_by_section(dmmap_section, "ipv6_instance", "");
		dmuci_set_value_by_section(((struct ipv6_args *)data)->ip_sec, "proto", "");
		break;
	case DEL_ALL:
		return FAULT_9005;
	}
	return 0;
}

int add_ipv6_prefix(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *s, *ss;
	char *ip, *name, *inst, *curr_inst;

	uci_foreach_sections("network", "interface", s) {
		if(strcmp(section_name(s), section_name(((struct ipv6prefix_args *)data)->ip_sec)) != 0)
			continue;
		dmuci_get_value_by_section_string(s, "ip6prefix", &ip);
		break;
	}
	if(ip[0] == '\0') {
		uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6prefix", "section_name", section_name(((struct ipv6prefix_args *)data)->ip_sec), s) {
			dmuci_get_value_by_section_string(s, "ipv6prefix_instance", &inst);
		}
		dmasprintf(&curr_inst, "%d", atoi(inst)+1);
		dmuci_set_value_by_section(((struct ip_args *)data)->ip_sec, "ip6prefix", "::");
		dmuci_set_value_by_section(((struct ipv6prefix_args *)data)->ip_sec, "proto", "static");
		DMUCI_ADD_SECTION(bbfdm, "dmmap_network", "ipv6prefix", &ss, &name);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, ss, "section_name", section_name(((struct ipv6prefix_args *)data)->ip_sec));
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, ss, "ipv6prefix_instance", curr_inst);
	}
	return 0;
}

int delete_ipv6_prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_network", "ipv6prefix", section_name(((struct ipv6prefix_args *)data)->ip_sec), &dmmap_section);
	switch (del_action) {
	case DEL_INST:
		dmuci_set_value_by_section(((struct ipv6prefix_args *)data)->ip_sec, "ip6prefix", "");
		dmuci_set_value_by_section(dmmap_section, "ipv6prefix_instance", "");
		dmuci_set_value_by_section(((struct ipv6prefix_args *)data)->ip_sec, "proto", "");
		break;
	case DEL_ALL:
		return FAULT_9005;
	}
	return 0;
}

static char *get_last_instance_with_option(char *package, char *section, char *option, char *val, char *opt_inst)
{
	struct uci_section *s;
	char *inst = NULL;

	uci_foreach_option_eq(package, section, option, val, s) {
		inst = update_instance(s, inst, opt_inst);
	}
	return inst;
}

static char *get_last_id(char *package, char *section)
{
	struct uci_section *s;
	char *id;
	int cnt = 0;

	uci_foreach_sections(package, section, s) {
		cnt++;
	}
	dmasprintf(&id, "%d", cnt+1);
	return id;
}

int addObjIPInterfaceTWAMPReflector(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *connection;
	char *value1, *last_inst, *id;

	last_inst = get_last_instance_with_option("cwmp_twamp", "twamp_refector", "interface", section_name(((struct ip_args *)data)->ip_sec), "twamp_inst");
	id = get_last_id("cwmp_twamp", "twamp_refector");
	dmuci_add_section("cwmp_twamp", "twamp_refector", &connection, &value1);
	dmasprintf(instance, "%d", last_inst?atoi(last_inst)+1:1);
	dmuci_set_value_by_section(connection, "twamp_inst", *instance);
	dmuci_set_value_by_section(connection, "id", id);
	dmuci_set_value_by_section(connection, "enable", "0");
	dmuci_set_value_by_section(connection, "interface", section_name(((struct ip_args *)data)->ip_sec));
	dmuci_set_value_by_section(connection, "port", "862");
	dmuci_set_value_by_section(connection, "max_ttl", "1");
	return 0;
}

int delObjIPInterfaceTWAMPReflector(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s, *ss = NULL;
	char *interface;
	struct uci_section *section = (struct uci_section *)data;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(section, NULL, NULL);
			return 0;
		case DEL_ALL:
			uci_foreach_sections("cwmp_twamp", "twamp_refector", s) {
				dmuci_get_value_by_section_string(s, "interface", &interface);
				if(strcmp(interface, section_name(((struct ip_args *)data)->ip_sec)) != 0)
					continue;
				if (found != 0) {
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

/**************************************************************************
* LINKER
***************************************************************************/
int get_linker_ip_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker) {
	if(data && ((struct ip_args *)data)->ip_sec) {
		dmasprintf(linker,"%s", section_name(((struct ip_args *)data)->ip_sec));
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}

int get_linker_ipv6_prefix(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker) {
	if(((struct ipv6prefix_args *)data)->ip_sec) {
		dmasprintf(linker,"%s", get_child_prefix_linker(section_name(((struct ipv6prefix_args *)data)->ip_sec)));
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}

/*************************************************************
 * ENTRY METHOD
/*************************************************************/
/*#Device.IP.Interface.{i}.!UCI:network/interface/dmmap_network*/
int browseIPIfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ip_int = NULL, *ip_int_last = NULL;
	char *type, *ipv4addr = "";
	struct ip_args curr_ip_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("network", "interface", "dmmap_network", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "type", &type);
		if (strcmp(type, "alias") == 0 || strcmp(section_name(p->config_section), "loopback")==0)
			continue;

		/* IPv4 address */
		dmuci_get_value_by_section_string(p->config_section, "ipaddr", &ipv4addr);
		if (ipv4addr[0] == '\0')
			ipv4addr = ubus_call_get_value(section_name(p->config_section), "ipv4-address", "address");

		init_ip_args(&curr_ip_args, p->config_section, ipv4addr);
		ip_int = handle_update_instance(1, dmctx, &ip_int_last, update_instance_alias, 3, p->dmmap_section, "ip_int_instance", "ip_int_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ip_args, ip_int) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int browseIfaceIPv4Inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ipv4_inst = NULL, *ipv4_inst_last = NULL;
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_network", "interface", section_name(((struct ip_args *)prev_data)->ip_sec), &dmmap_section);
	if(((struct ip_args *)prev_data)->ip_4address[0] != '\0') {
		ipv4_inst = handle_update_instance(2, dmctx, &ipv4_inst_last, update_instance_alias, 3, dmmap_section, "ipv4_instance", "ipv4_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, ipv4_inst) == DM_STOP)
			goto end;
	}
end:
	return 0;
}

static struct uci_section *update_dmmap_network_ipv6(char *curr_inst, char *section_name)
{
	struct uci_section *s = NULL;
	char *inst, *name;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6", "section_name", section_name, s) {
		dmuci_get_value_by_section_string(s, "ipv6_instance", &inst);
		if(strcmp(curr_inst, inst) == 0)
			return s;
	}
	if (!s) {
		DMUCI_ADD_SECTION(bbfdm, "dmmap_network", "ipv6", &s, &name);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "section_name", section_name);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "ipv6_instance", curr_inst);
	}
	return s;
}

int browseIfaceIPv6Inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s;
	char *ipv6_int = NULL, *ipv6_int_last = NULL, *ipv6addr = "", *ipv6mask = "", *ipv6_preferred = "", *ipv6_valid = "", buf[4]="";
	struct ipv6_args curr_ipv6_args = {0};
	json_object *res, *jobj, *jobj1;
	int entries = 0;

	if(prev_data && ((struct ip_args *)prev_data)->ip_sec) {
		dmuci_get_value_by_section_string(((struct ip_args *)prev_data)->ip_sec, "ip6addr", &ipv6addr);
		dmuci_get_value_by_section_string(((struct ip_args *)prev_data)->ip_sec, "adv_preferred_lifetime", &ipv6_preferred);
		dmuci_get_value_by_section_string(((struct ip_args *)prev_data)->ip_sec, "adv_valid_lifetime", &ipv6_valid);
		if (ipv6addr[0] == '\0') {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct ip_args *)prev_data)->ip_sec), String}}, 1, &res);
			while (res) {
				jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-prefix-assignment");
				if(jobj) {
					jobj1 = dmjson_get_obj(jobj, 1, "local-address");
					if(jobj1) {
						ipv6addr = dmjson_get_value(jobj1, 1, "address");
						ipv6mask = dmjson_get_value(jobj1, 1, "mask");
						goto browse;
					}
				}
				jobj = dmjson_select_obj_in_array_idx(res, entries, 1, "ipv6-address");
				if(jobj) {
					ipv6addr = dmjson_get_value(jobj, 1, "address");
					ipv6mask = dmjson_get_value(jobj, 1, "mask");
					if (ipv6_preferred[0] == '\0')
						ipv6_preferred = dmjson_get_value(jobj, 1, "preferred");
					if (ipv6_valid[0] == '\0')
						ipv6_valid = dmjson_get_value(jobj, 1, "valid");
					entries++;
					sprintf(buf, "%d", entries);
					s = update_dmmap_network_ipv6(buf, section_name(((struct ip_args *)prev_data)->ip_sec));
					init_ipv6_args(&curr_ipv6_args, ((struct ip_args *)prev_data)->ip_sec, ipv6addr, ipv6mask, ipv6_preferred, ipv6_valid);
					ipv6_int = handle_update_instance(1, dmctx, &ipv6_int_last, update_instance_alias, 3, s, "ipv6_instance", "ipv6_alias");
					if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ipv6_args, ipv6_int) == DM_STOP)
						goto end;
				} else
					goto end;
			}
		}
browse:
		s = update_dmmap_network_ipv6("1", section_name(((struct ip_args *)prev_data)->ip_sec));
		init_ipv6_args(&curr_ipv6_args, ((struct ip_args *)prev_data)->ip_sec, ipv6addr, ipv6mask, ipv6_preferred, ipv6_valid);
		ipv6_int = handle_update_instance(1, dmctx, &ipv6_int_last, update_instance_alias, 3, s, "ipv6_instance", "ipv6_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ipv6_args, ipv6_int) == DM_STOP)
			goto end;
	}
end:
	return 0;
}


static struct uci_section *update_dmmap_network_ipv6prefix(char *curr_inst, char *section_name)
{
	struct uci_section *s = NULL;
	char *inst, *name;

	uci_path_foreach_option_eq(bbfdm, "dmmap_network", "ipv6prefix", "section_name", section_name, s) {
		dmuci_get_value_by_section_string(s, "ipv6prefix_instance", &inst);
		if(strcmp(curr_inst, inst) == 0)
			return s;
	}
	if (!s) {
		DMUCI_ADD_SECTION(bbfdm, "dmmap_network", "ipv6prefix", &s, &name);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "section_name", section_name);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "ipv6prefix_instance", curr_inst);
	}
	return s;
}

int browseIfaceIPv6PrefixInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s;
	char *ipv6prefix_int = NULL, *ipv6prefix_int_last = NULL, *ipv6prefixaddr = "", *ipv6prefixmask = "", *ipv6prefix_preferred = "", *ipv6prefix_valid = "", buf[4] = "";
	struct ipv6prefix_args curr_ipv6prefix_args = {0};
	json_object *res, *jobj;
	int entries = 0;

	if(prev_data && ((struct ip_args *)prev_data)->ip_sec) {
		dmuci_get_value_by_section_string(((struct ip_args *)prev_data)->ip_sec, "ip6prefix", &ipv6prefixaddr);
		if (ipv6prefixaddr[0] == '\0') {
			dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct ip_args *)prev_data)->ip_sec), String}}, 1, &res);
			while (res) {
				jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-prefix-assignment");
				if(jobj) {
					ipv6prefixaddr = dmjson_get_value(jobj, 1, "address");
					ipv6prefixmask = dmjson_get_value(jobj, 1, "mask");
					ipv6prefix_preferred = dmjson_get_value(jobj, 1, "preferred");
					ipv6prefix_valid = dmjson_get_value(jobj, 1, "valid");
					goto browse;
				}
				jobj = dmjson_select_obj_in_array_idx(res, entries, 1, "ipv6-prefix");
				if(jobj) {
					ipv6prefixaddr = dmjson_get_value(jobj, 1, "address");
					ipv6prefixmask = dmjson_get_value(jobj, 1, "mask");
					ipv6prefix_preferred = dmjson_get_value(jobj, 1, "preferred");
					ipv6prefix_valid = dmjson_get_value(jobj, 1, "valid");
					entries++;
					sprintf(buf, "%d", entries);
					s = update_dmmap_network_ipv6prefix(buf, section_name(((struct ip_args *)prev_data)->ip_sec));
					init_ipv6prefix_args(&curr_ipv6prefix_args, ((struct ip_args *)prev_data)->ip_sec, ipv6prefixaddr, ipv6prefixmask, ipv6prefix_preferred, ipv6prefix_valid);
					ipv6prefix_int = handle_update_instance(1, dmctx, &ipv6prefix_int_last, update_instance_alias, 3, s, "ipv6prefix_instance", "ipv6prefix_alias");
					if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ipv6prefix_args, ipv6prefix_int) == DM_STOP)
						goto end;
				} else
					goto end;
			}
		}
browse:
		s = update_dmmap_network_ipv6prefix("1", section_name(((struct ip_args *)prev_data)->ip_sec));
		init_ipv6prefix_args(&curr_ipv6prefix_args, ((struct ip_args *)prev_data)->ip_sec, ipv6prefixaddr, ipv6prefixmask, ipv6prefix_preferred, ipv6prefix_valid);
		ipv6prefix_int = handle_update_instance(1, dmctx, &ipv6prefix_int_last, update_instance_alias, 3, s, "ipv6prefix_instance", "ipv6prefix_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_ipv6prefix_args, ipv6prefix_int) == DM_STOP)
			goto end;
	}
end:
	return 0;
}

int browseIPInterfaceTWAMPReflectorInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *twamp_inst = NULL, *twamp_inst_last = NULL;

	uci_foreach_option_eq("cwmp_twamp", "twamp_refector", "interface", section_name(((struct ip_args *)prev_data)->ip_sec), s)
	{
		twamp_inst = handle_update_instance(2, dmctx, &twamp_inst_last, update_instance_alias, 3, (void *)s, "twamp_inst", "twamp_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, twamp_inst) == DM_STOP)
			break;
	}
	return 0;
}
