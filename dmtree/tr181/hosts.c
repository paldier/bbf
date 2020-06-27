/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "hosts.h"
#include "os.h"

/* *** Device.Hosts. *** */
DMOBJ tHostsObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Host", &DMREAD, NULL, NULL, NULL, os__browseHostsHostInst, NULL, NULL, NULL, tHostsHostObj, tHostsHostParams, get_linker_host, BBFDM_BOTH},
{0}
};

DMLEAF tHostsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"HostNumberOfEntries", &DMREAD, DMT_UNINT, os__get_Hosts_HostNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Hosts.Host.{i}. *** */
DMOBJ tHostsHostObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"IPv4Address", &DMREAD, NULL, NULL, NULL, os__browseHostsHostIPv4AddressInst, NULL, NULL, NULL, NULL, tHostsHostIPv4AddressParams, NULL, BBFDM_BOTH},
{"IPv6Address", &DMREAD, NULL, NULL, NULL, os__browseHostsHostIPv6AddressInst, NULL, NULL, NULL, NULL, tHostsHostIPv6AddressParams, NULL, BBFDM_BOTH},
{"WANStats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tHostsHostWANStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tHostsHostParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, os__get_HostsHost_Alias, os__set_HostsHost_Alias, NULL, NULL, BBFDM_BOTH},
{"PhysAddress", &DMREAD, DMT_STRING, os__get_HostsHost_PhysAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"IPAddress", &DMREAD, DMT_STRING, os__get_HostsHost_IPAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"AddressSource", &DMREAD, DMT_STRING, os__get_HostsHost_AddressSource, NULL, NULL, NULL, BBFDM_BOTH},
{"DHCPClient", &DMREAD, DMT_STRING, os__get_HostsHost_DHCPClient, NULL, NULL, NULL, BBFDM_BOTH},
{"LeaseTimeRemaining", &DMREAD, DMT_INT, os__get_HostsHost_LeaseTimeRemaining, NULL, NULL, NULL, BBFDM_BOTH},
{"AssociatedDevice", &DMREAD, DMT_STRING, os__get_HostsHost_AssociatedDevice, NULL, NULL, NULL, BBFDM_BOTH},
{"Layer1Interface", &DMREAD, DMT_STRING, os__get_HostsHost_Layer1Interface, NULL, NULL, NULL, BBFDM_BOTH},
{"Layer3Interface", &DMREAD, DMT_STRING, os__get_HostsHost_Layer3Interface, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceType", &DMREAD, DMT_STRING, os__get_HostsHost_InterfaceType, NULL, NULL, NULL, BBFDM_BOTH},
{"VendorClassID", &DMREAD, DMT_STRING, os__get_HostsHost_VendorClassID, NULL, NULL, NULL, BBFDM_BOTH},
{"ClientID", &DMREAD, DMT_HEXBIN, os__get_HostsHost_ClientID, NULL, NULL, NULL, BBFDM_BOTH},
{"UserClassID", &DMREAD, DMT_HEXBIN, os__get_HostsHost_UserClassID, NULL, NULL, NULL, BBFDM_BOTH},
{"HostName", &DMREAD, DMT_STRING, os__get_HostsHost_HostName, NULL, NULL, NULL, BBFDM_BOTH},
{"Active", &DMREAD, DMT_BOOL, os__get_HostsHost_Active, NULL, NULL, NULL, BBFDM_BOTH},
{"ActiveLastChange", &DMREAD, DMT_TIME, os__get_HostsHost_ActiveLastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4AddressNumberOfEntries", &DMREAD, DMT_UNINT, os__get_HostsHost_IPv4AddressNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, os__get_HostsHost_IPv6AddressNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Hosts.Host.{i}.IPv4Address.{i}. *** */
DMLEAF tHostsHostIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IPAddress", &DMREAD, DMT_STRING, os__get_HostsHostIPv4Address_IPAddress, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Hosts.Host.{i}.IPv6Address.{i}. *** */
DMLEAF tHostsHostIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IPAddress", &DMREAD, DMT_STRING, os__get_HostsHostIPv6Address_IPAddress, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Hosts.Host.{i}.WANStats. *** */
DMLEAF tHostsHostWANStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNINT, os__get_HostsHostWANStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, os__get_HostsHostWANStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, os__get_HostsHostWANStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, os__get_HostsHostWANStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
