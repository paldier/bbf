/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2019 iopsys Software Solutions AB
 *	  Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#include "dmuci.h"
#include "dmbbf.h"
#include "upnp_device.h"
#include "deviceinfo.h"
#include "managementserver.h"
#include "times.h"
#include "upnp.h"
#if BBF_TR104
#include "voice_services.h"
#endif
#include "x_iopsys_eu_ice.h"
#include "x_iopsys_eu_igmp.h"
#include "x_iopsys_eu_ipacccfg.h"
#include "x_iopsys_eu_logincfg.h"
#include "x_iopsys_eu_power_mgmt.h"
#include "x_iopsys_eu_syslog.h"
#include "softwaremodules.h"
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
#include "landevice.h"
#include "wandevice.h"
#include "ippingdiagnostics.h"
#include "lan_interfaces.h"
#include "layer_3_forwarding.h"
#include "x_iopsys_eu_wifi.h"
#include "layer_2_bridging.h"
#include "downloaddiagnostic.h"
#include "uploaddiagnostic.h"
#include "deviceconfig.h"
#include "firewall.h"
#include "dns.h"
#include "users.h"
#include "dsl.h"
#include "dhcpv6.h"
#include "interfacestack.h"
#include "qos.h"

#ifdef BBF_TR064
#include "upnp_deviceinfo.h"
#include "upnp_configuration.h"
#include "upnp_monitoring.h"
#endif

/*** UPNP ***/
#ifdef BBF_TR064
DMOBJ tEntry181ObjUPNP[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextobj, leaf, linker, bbfdm_type*/
{(char *)&dmroot, &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE, tRoot181ObjUPNP, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tRoot181ObjUPNP[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextobj, leaf, linker, bbfdm_type*/
{"BBF", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE, tRoot181ObjUPNPBBF, NULL, NULL, BBFDM_BOTH},
{"UPnP", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE, tRoot181ObjUPNPDMROOT, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tRoot181ObjUPNPDMROOT[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextobj, leaf, linker, bbfdm_type*/
{"DM", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE, tRoot181ObjUPNPDM, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tRoot181ObjUPNPDM[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextobj, leaf, linker, bbfdm_type*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE,upnpDeviceInfoObj, upnpDeviceInfoParams, NULL, BBFDM_BOTH},
{"Configuration", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE,upnpConfigurationObj, NULL, NULL, BBFDM_BOTH},
{"Monitoring", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE,upnpMonitoringObj, upnpMonitoringParams, NULL, BBFDM_BOTH},
{0}
};

DMOBJ tRoot181ObjUPNPBBF[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextobj, leaf, linker, bbfdm_type*/
{"DeviceInfo", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE,tDeviceInfoObj, tDeviceInfoParams, NULL, BBFDM_BOTH},
{"ManagementServer", &DMREAD, NULL, NULL, NULL, NULL, &DMFINFRM, &DMNONE,NULL, tManagementServerParams, NULL, BBFDM_BOTH},
{"Time", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,NULL, tTimeParams, NULL, BBFDM_BOTH},
{"UPnP", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,tUPnPObj, NULL, NULL, BBFDM_BOTH},
#if BBF_TR104
{"VoiceService", &DMREAD, NULL, NULL, NULL, browseVoiceServiceInst, NULL, NULL, tVoiceServiceObj, tVoiceServiceParam, NULL, BBFDM_BOTH},
#endif
{CUSTOM_PREFIX"ICE", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,NULL, tSe_IceParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"IGMP", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,NULL, tSe_IgmpParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"IpAccCfg", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,tSe_IpAccObj, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"LoginCfg", &DMREAD, NULL, NULL, NULL, NULL,NULL, &DMNONE,NULL, tSe_LoginCfgParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"PowerManagement", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,NULL, tSe_PowerManagementParam, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"SyslogCfg", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,NULL, tSe_SyslogCfgParam, NULL, BBFDM_BOTH},
{"SoftwareModules", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,tSoftwareModulesObj, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Owsd", &DMREAD, NULL, NULL, NULL, NULL, NULL, &DMNONE,XIopsysEuOwsdObj, XIopsysEuOwsdParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Dropbear", &DMWRITE, add_dropbear_instance, delete_dropbear_instance, NULL, browseXIopsysEuDropbear, NULL, &DMNONE, NULL, X_IOPSYS_EU_DropbearParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Buttons", &DMREAD, NULL, NULL, NULL, browseXIopsysEuButton, NULL, &DMNONE, NULL, X_IOPSYS_EU_ButtonParams, NULL, BBFDM_BOTH},
{"Bridging",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tBridgingObj, NULL, NULL, BBFDM_BOTH},
{"WiFi",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tWifiObj, NULL, NULL, BBFDM_BOTH},
{"IP",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tIPObj, NULL, NULL, BBFDM_BOTH},
{"Ethernet", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tEthernetObj, NULL, NULL, BBFDM_BOTH},
{"DSL",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDslObj, NULL, NULL, BBFDM_BOTH},
{"ATM",&DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tAtmObj, NULL, NULL, BBFDM_BOTH},
{"PTM", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tPtmObj, NULL, NULL, BBFDM_BOTH},
{"DHCPv4", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tDhcpv4Obj, NULL, NULL, BBFDM_BOTH},
{"Hosts", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, thostsObj, thostsParam, NULL, BBFDM_BOTH},
{"NAT", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tnatObj, NULL, NULL, BBFDM_BOTH},
{"PPP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tpppObj, NULL, NULL, BBFDM_BOTH},
{"Routing", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, tRoutingObj, tRoutingParam, NULL, BBFDM_BOTH},
{"XMPP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL,tXMPPObj, tXMPPParams, NULL, BBFDM_BOTH},
{0}
};

UPNP_SUPPORTED_DM tUPNPSupportedDM[];
UPNP_SUPPORTED_DM tUPNPSupportedDM_181[] = {
{"/UPnP/DM/DeviceInfo/", "urn:UPnP:Parent Device:1:ConfigurationManagement:2", DMROOT_URL_181, "UPnP DeviceInfo from "DMROOT_DESC_181, ""},
{"/UPnP/DM/Configuration/", "urn:UPnP:Parent Device:1:ConfigurationManagement:2", DMROOT_URL_181, "Configuration from "DMROOT_DESC_181, ""},
{"/UPnP/DM/Monitoring/", "urn:UPnP:Parent Device:1:ConfigurationManagement:2", DMROOT_URL_181, "Monitoring from "DMROOT_DESC_181, ""},
{"/BBF/DeviceInfo/", DMROOT_URI_181, DMROOT_URL_181, "DeviceInfo from "DMROOT_DESC_181, ""},
{"/BBF/ManagementServer/", DMROOT_URI_181, DMROOT_URL_181, "ManagementServer from "DMROOT_DESC_181, ""},
{"/BBF/Time/", DMROOT_URI_181, DMROOT_URL_181, "Time from "DMROOT_DESC_181, ""},
{"/BBF/UPnP/", DMROOT_URI_181, DMROOT_URL_181, "UPnP from "DMROOT_DESC_181, ""},
{"/BBF/VoiceService/", "urn:broadband-forum-org:wt-104-2-0-0", "https://www.broadband-forum.org/cwmp/tr-104-2-0-0.html", "TR-104 Voice:2 Service Object definition", ""},
{"/BBF/"CUSTOM_PREFIX"ICE/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for ICE", ""},
{"/BBF/"CUSTOM_PREFIX"IGMP/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for ICE", ""},
{"/BBF/"CUSTOM_PREFIX"IpAccCfg/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for IGMP", ""},
{"/BBF/"CUSTOM_PREFIX"LoginCfg/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for LoginCfg", ""},
{"/BBF/"CUSTOM_PREFIX"PowerManagement/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for PowerManagement", ""},
{"/BBF/"CUSTOM_PREFIX"SyslogCfg/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for SyslogCfg", ""},
{"/BBF/SoftwareModules/", DMROOT_URI_181, DMROOT_URL_181, "SoftwareModules from "DMROOT_DESC_181, ""},
{"/BBF/"CUSTOM_PREFIX"Owsd/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for Owsd", ""},
{"/BBF/"CUSTOM_PREFIX"Dropbear/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for Dropbear", ""},
{"/BBF/"CUSTOM_PREFIX"Buttons/", "urn:iopsys-eu:na", "https://www.iopsys.eu/", "iopsys extension for Buttons", ""},
{"/BBF/Bridging/", DMROOT_URI_181, DMROOT_URL_181, "Bridging from "DMROOT_DESC_181, ""},
{"/BBF/WiFi/", DMROOT_URI_181, DMROOT_URL_181, "WiFi from "DMROOT_DESC_181, ""},
{"/BBF/IP/", DMROOT_URI_181, DMROOT_URL_181, "IP from "DMROOT_DESC_181, ""},
{"/BBF/Ethernet/", DMROOT_URI_181, DMROOT_URL_181, "Ethernet from "DMROOT_DESC_181, ""},
{"/BBF/DSL/", DMROOT_URI_181, DMROOT_URL_181, "DSL from "DMROOT_DESC_181, ""},
{"/BBF/ATM/", DMROOT_URI_181, DMROOT_URL_181, "ATM from "DMROOT_DESC_181, ""},
{"/BBF/PTM/", DMROOT_URI_181, DMROOT_URL_181, "PTM from "DMROOT_DESC_181, ""},
{"/BBF/DHCPv4/", DMROOT_URI_181, DMROOT_URL_181, "DHCPv4 from "DMROOT_DESC_181, ""},
{"/BBF/Hosts/", DMROOT_URI_181, DMROOT_URL_181, "Hosts from "DMROOT_DESC_181, ""},
{"/BBF/NAT/", DMROOT_URI_181, DMROOT_URL_181, "NAT from "DMROOT_DESC_181, ""},
{"/BBF/PPP/", DMROOT_URI_181, DMROOT_URL_181, "PPP from "DMROOT_DESC_181, ""},
{"/BBF/Routing/", DMROOT_URI_181, DMROOT_URL_181, "Routing from "DMROOT_DESC_181, ""},
{"/BBF/XMPP/", DMROOT_URI_181, DMROOT_URL_181, "XMPP from "DMROOT_DESC_181, ""},
{0}
};

size_t tr181_size = sizeof(tUPNPSupportedDM_181);
#endif
