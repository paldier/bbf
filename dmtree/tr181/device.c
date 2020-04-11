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
#include "x_iopsys_eu_power_mgmt.h"
#include "x_iopsys_eu_syslog.h"
#include "xmpp.h"
#include "x_iopsys_eu_owsd.h"
#include "x_iopsys_eu_dropbear.h"
#include "x_iopsys_eu_buttons.h"
#include "x_iopsys_eu_wifilife.h"
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
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE, NULL, tRoot_181_Obj, tRoot_181_Params, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tRoot_181_Params[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceStackNumberOfEntries", &DMREAD, DMT_UNINT, get_Device_InterfaceStackNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"RootDataModelVersion", &DMREAD, DMT_UNINT, get_Device_RootDataModelVersion, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tRoot_181_Obj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE, NULL, tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH},
{"ManagementServer", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE, NULL, NULL, tManagementServerParams, NULL, BBFDM_BOTH},
{"Time", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, NULL, tTimeParams, NULL, BBFDM_BOTH},
{"UPnP", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, tUPnPObj, NULL, NULL, BBFDM_BOTH},
#ifdef BBF_TR104
{"Services", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, tServicesObj, NULL, NULL, BBFDM_BOTH},
#endif
{CUSTOM_PREFIX"IGMP", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, NULL, tSe_IgmpParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"PowerManagement", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, NULL, tSe_PowerManagementParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Syslog", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, NULL, tSe_SyslogParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"OWSD", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, X_IOPSYS_EU_OWSDObj, X_IOPSYS_EU_OWSDParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Dropbear", &DMWRITE, add_dropbear_instance, delete_dropbear_instance, NULL, browseXIopsysEuDropbear, NULL, &DMNONE, NULL, NULL, X_IOPSYS_EU_DropbearParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Buttons", &DMREAD, NULL, NULL, NULL, browseXIopsysEuButton, NULL, &DMNONE, NULL, NULL, X_IOPSYS_EU_ButtonParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"WiFiLife", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, X_IOPSYS_EU_WiFiLifeObj, X_IOPSYS_EU_WiFiLifeParams, NULL, BBFDM_BOTH},
{"Bridging",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingObj, tBridgingParams, NULL, BBFDM_BOTH},
{"WiFi",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiObj, tWiFiParams, NULL, BBFDM_BOTH},
{"IP",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPObj, tIPParams, NULL, BBFDM_BOTH},
{"Ethernet", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetObj, tEthernetParams, NULL, BBFDM_BOTH},
{"DSL",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDSLObj, tDSLParams, NULL, BBFDM_BOTH},
{"ATM",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tATMObj, NULL, NULL, BBFDM_BOTH},
{"PTM", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPTMObj, NULL, NULL, BBFDM_BOTH},
{"DHCPv4", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDHCPv4Obj, tDHCPv4Params, NULL, BBFDM_BOTH},
{"DHCPv6", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDHCPv6Obj, tDHCPv6Params, NULL, BBFDM_BOTH},
{"Hosts", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tHostsObj, tHostsParams, NULL, BBFDM_BOTH},
{"NAT", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tNATObj, tNATParams, NULL, BBFDM_BOTH},
{"PPP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tPPPObj, tPPPParams, NULL, BBFDM_BOTH},
{"Routing", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tRoutingObj, tRoutingParams, NULL, BBFDM_BOTH},
{"UserInterface", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUserInterfaceObj, NULL, NULL, BBFDM_BOTH},
{"Firewall", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tFirewallObj, tFirewallParams, NULL, BBFDM_BOTH},
{"DNS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDNSObj, tDNSParams, NULL, BBFDM_BOTH},
{"Users", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUsersObj, tUsersParams, NULL, BBFDM_BOTH},
{"InterfaceStack", &DMREAD, NULL, NULL, NULL, browseInterfaceStackInst, NULL, NULL, NULL, NULL, tInterfaceStackParams, NULL, BBFDM_BOTH},
{"USB", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUSBObj, tUSBParams, NULL, BBFDM_BOTH},
{"GRE", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL,  NULL, tGREObj, tGREParams, NULL, BBFDM_BOTH},
{"DynamicDNS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDynamicDNSObj, tDynamicDNSParams, NULL, BBFDM_BOTH},
{"QoS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tQoSObj, tQoSParams, NULL, BBFDM_BOTH},
{"XMPP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tXMPPObj, tXMPPParams, NULL, BBFDM_BOTH},
#ifdef BBF_TR157
{"BulkData", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBulkDataObj, tBulkDataParams, NULL, BBFDM_BOTH},
{"SoftwareModules", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE, NULL, tSoftwareModulesObj, tSoftwareModulesParams, NULL, BBFDM_BOTH},
#endif
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL,  NULL, tSecurityObj, tSecurityParams, NULL, BBFDM_BOTH},
{0}
};
