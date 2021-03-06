/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "device.h"
#include "deviceinfo.h"
#include "managementserver.h"
#include "times.h"
#include "upnp.h"
#include "x_iopsys_eu_igmp.h"
#include "x_iopsys_eu_mld.h"
#include "x_iopsys_eu_syslog.h"
#include "xmpp.h"
#include "x_iopsys_eu_owsd.h"
#include "x_iopsys_eu_dropbear.h"
#include "x_iopsys_eu_buttons.h"
#include "ip.h"
#include "ethernet.h"
#include "bridging.h"
#include "wifi.h"
#include "atm.h"
#include "ptm.h"
#include "dhcpv4.h"
#include "hosts.h"
#include "nat.h"
#include "ppp.h"
#include "routing.h"
#include "userinterface.h"
#include "firewall.h"
#include "dns.h"
#include "users.h"
#include "dsl.h"
#include "dhcpv6.h"
#include "interfacestack.h"
#include "qos.h"
#include "usb.h"
#include "datamodelversion.h"
#include "gre.h"
#include "dynamicdns.h"
#include "lanconfigsecurity.h"
#include "security.h"
#ifdef BBF_TR104
#include "voice_services.h"
#endif
#ifdef BBF_TR157
#include "bulkdata.h"
#include "softwaremodules.h"
#endif

/* *** BBFDM *** */
DMOBJ tEntry181Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, NULL, NULL, tRoot_181_Obj, tRoot_181_Params, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tRoot_181_Params[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceStackNumberOfEntries", &DMREAD, DMT_UNINT, get_Device_InterfaceStackNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"RootDataModelVersion", &DMREAD, DMT_STRING, get_Device_RootDataModelVersion, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tRoot_181_Obj[] = {
/* OBJ, permission, addobj, delobj, checkdep, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, NULL, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH},
{"ManagementServer", &DMREAD, NULL, NULL, "file:/etc/config/cwmp", NULL, &DMFINFRM, NULL, NULL, NULL, tManagementServerParams, NULL, BBFDM_BOTH},
{"Time", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, NULL, NULL, tTimeParams, NULL, BBFDM_BOTH},
{"UPnP", &DMREAD, NULL, NULL, "file:/etc/config/upnpd", NULL, NULL, NULL, NULL, tUPnPObj, NULL, NULL, BBFDM_BOTH},
#ifdef BBF_TR104
{"Services", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tServicesObj, NULL, NULL, BBFDM_BOTH},
#endif
{CUSTOM_PREFIX"Syslog", &DMREAD, NULL, NULL, "file:/etc/config/system", NULL, NULL, NULL, NULL, NULL, tSe_SyslogParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"OWSD", &DMREAD, NULL, NULL, "file:/etc/config/owsd", NULL, NULL, NULL, NULL, X_IOPSYS_EU_OWSDObj, X_IOPSYS_EU_OWSDParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"IGMP", &DMREAD, NULL, NULL, "file:/etc/config/mcast", NULL, NULL, NULL, NULL, X_IOPSYS_EU_IGMPObj, X_IOPSYS_EU_IGMPParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"MLD", &DMREAD, NULL, NULL, "file:/etc/config/mcast", NULL, NULL, NULL, NULL, X_IOPSYS_EU_MLDObj, X_IOPSYS_EU_MLDParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Dropbear", &DMWRITE, add_dropbear_instance, delete_dropbear_instance, "file:/etc/config/dropbear", browseXIopsysEuDropbear, NULL, NULL, NULL, NULL, X_IOPSYS_EU_DropbearParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Buttons", &DMREAD, NULL, NULL, "file:/etc/config/buttons", browseXIopsysEuButton, NULL, NULL, NULL, NULL, X_IOPSYS_EU_ButtonParams, NULL, BBFDM_BOTH},
{"Bridging",&DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, NULL, tBridgingObj, tBridgingParams, NULL, BBFDM_BOTH},
{"WiFi",&DMREAD, NULL, NULL, "file:/etc/config/wireless", NULL, NULL, NULL, NULL, tWiFiObj, tWiFiParams, NULL, BBFDM_BOTH},
{"IP",&DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, NULL, tIPObj, tIPParams, NULL, BBFDM_BOTH},
{"Ethernet", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, NULL, tEthernetObj, tEthernetParams, NULL, BBFDM_BOTH},
{"DSL",&DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, NULL, tDSLObj, tDSLParams, NULL, BBFDM_BOTH},
{"ATM",&DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, NULL, tATMObj, NULL, NULL, BBFDM_BOTH},
{"PTM", &DMREAD, NULL, NULL, "file:/etc/config/dsl", NULL, NULL, NULL, NULL, tPTMObj, NULL, NULL, BBFDM_BOTH},
{"DHCPv4", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcp.sh", NULL, NULL, NULL, NULL, tDHCPv4Obj, tDHCPv4Params, NULL, BBFDM_BOTH},
{"DHCPv6", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/dhcpv6.sh", NULL, NULL, NULL, NULL, tDHCPv6Obj, tDHCPv6Params, NULL, BBFDM_BOTH},
#ifdef GENERIC_OPENWRT
{"Hosts", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tHostsObj, tHostsParams, NULL, BBFDM_BOTH},
#else
{"Hosts", &DMREAD, NULL, NULL, "ubus:router.network->hosts", NULL, NULL, NULL, NULL, tHostsObj, tHostsParams, NULL, BBFDM_BOTH},
#endif
{"NAT", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, NULL, tNATObj, tNATParams, NULL, BBFDM_BOTH},
{"PPP", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/ppp.sh", NULL, NULL, NULL, NULL, tPPPObj, tPPPParams, NULL, BBFDM_BOTH},
{"Routing", &DMREAD, NULL, NULL, "file:/etc/config/network", NULL, NULL, NULL, NULL, tRoutingObj, tRoutingParams, NULL, BBFDM_BOTH},
{"UserInterface", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUserInterfaceObj, NULL, NULL, BBFDM_BOTH},
{"Firewall", &DMREAD, NULL, NULL, "file:/etc/config/firewall", NULL, NULL, NULL, NULL, tFirewallObj, tFirewallParams, NULL, BBFDM_BOTH},
{"DNS", &DMREAD, NULL, NULL, "file:/etc/config/dhcp", NULL, NULL, NULL, NULL, tDNSObj, tDNSParams, NULL, BBFDM_BOTH},
{"Users", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, NULL, tUsersObj, tUsersParams, NULL, BBFDM_BOTH},
{"InterfaceStack", &DMREAD, NULL, NULL, "file:/etc/config/network", browseInterfaceStackInst, NULL, NULL, NULL, NULL, tInterfaceStackParams, NULL, BBFDM_BOTH},
{"USB", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUSBObj, tUSBParams, NULL, BBFDM_BOTH},
{"GRE", &DMREAD, NULL, NULL, "file:/lib/netifd/proto/gre.sh", NULL, NULL, NULL,  NULL, tGREObj, tGREParams, NULL, BBFDM_BOTH},
{"DynamicDNS", &DMREAD, NULL, NULL, "file:/etc/config/ddns", NULL, NULL, NULL, NULL, tDynamicDNSObj, tDynamicDNSParams, NULL, BBFDM_BOTH},
{"QoS", &DMREAD, NULL, NULL, "file:/etc/config/qos", NULL, NULL, NULL, NULL, tQoSObj, tQoSParams, NULL, BBFDM_BOTH},
{"XMPP", &DMREAD, NULL, NULL, "file:/etc/config/cwmp_xmpp", NULL, NULL, NULL, NULL, tXMPPObj, tXMPPParams, NULL, BBFDM_BOTH},
{"LANConfigSecurity", &DMREAD, NULL, NULL, "file:/etc/config/users", NULL, NULL, NULL, NULL, NULL, tLANConfigSecurityParams, NULL, BBFDM_BOTH},
#ifdef BBF_TR157
{"BulkData", &DMREAD, NULL, NULL, "file:/etc/config/cwmp_bulkdata", NULL, NULL, NULL, NULL, tBulkDataObj, tBulkDataParams, NULL, BBFDM_BOTH},
{"SoftwareModules", &DMREAD, NULL, NULL, "ubus:swmodules", NULL, NULL, NULL, NULL, tSoftwareModulesObj, tSoftwareModulesParams, NULL, BBFDM_BOTH},
#endif
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL,  NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_BOTH},
{0}
};
