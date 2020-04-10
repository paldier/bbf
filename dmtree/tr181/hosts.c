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

#include "hosts.h"
#include "os.h"


/* *** Device.Hosts. *** */
DMOBJ tHostsObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Host", &DMREAD, NULL, NULL, NULL, os__browsehostInst, NULL, NULL, NULL, NULL, tHostsHostParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tHostsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"HostNumberOfEntries", &DMREAD, DMT_UNINT, os__get_host_nbr_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Hosts.Host.{i}. *** */
DMLEAF tHostsHostParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"AssociatedDevice", &DMREAD, DMT_STRING, os__get_host_associateddevice, NULL, NULL, NULL, BBFDM_BOTH},
{"Layer3Interface", &DMREAD, DMT_STRING, os__get_host_layer3interface, NULL, NULL, NULL, BBFDM_BOTH},
{"IPAddress", &DMREAD, DMT_STRING, os__get_host_ipaddress, NULL, NULL, NULL, BBFDM_BOTH},
{"HostName", &DMREAD, DMT_STRING, os__get_host_hostname, NULL, NULL, NULL, BBFDM_BOTH},
{"Active", &DMREAD, DMT_BOOL, os__get_host_active, NULL, NULL, NULL, BBFDM_BOTH},
{"PhysAddress", &DMREAD, DMT_STRING, os__get_host_phy_address, NULL, NULL, NULL, BBFDM_BOTH},
{"AddressSource", &DMREAD, DMT_STRING, os__get_host_address_source, NULL, NULL, NULL, BBFDM_BOTH},
{"LeaseTimeRemaining", &DMREAD, DMT_INT, os__get_host_leasetime_remaining, NULL, NULL, NULL, BBFDM_BOTH},
{"DHCPClient", &DMREAD, DMT_STRING, os__get_host_dhcp_client, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
