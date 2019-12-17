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
#include "wifi.h"
#include "dmjson.h"
#include "dmentry.h"
#include "wepkey.h"
#define DELIMITOR ","

/* *** Device.WiFi. *** */
DMOBJ tWiFiObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Radio", &DMREAD, NULL, NULL, NULL, browseWifiRadioInst, NULL, NULL, NULL, tWiFiRadioObj, tWiFiRadioParams, get_linker_Wifi_Radio, BBFDM_BOTH},
{"SSID", &DMWRITE, add_wifi_ssid, delete_wifi_ssid, NULL, browseWifiSsidInst, NULL, NULL, NULL, tWiFiSSIDObj, tWiFiSSIDParams, get_linker_Wifi_Ssid, BBFDM_BOTH},
{"AccessPoint", &DMREAD, NULL, NULL, NULL, browseWifiAccessPointInst, NULL, NULL, NULL, tWiFiAccessPointObj, tWiFiAccessPointParams, NULL, BBFDM_BOTH},
{"NeighboringWiFiDiagnostic", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiNeighboringWiFiDiagnosticObj, tWiFiNeighboringWiFiDiagnosticParams, NULL, BBFDM_BOTH},
{"EndPoint", &DMWRITE, addObjWiFiEndPoint, delObjWiFiEndPoint, NULL, browseWiFiEndPointInst, NULL, NULL, NULL, tWiFiEndPointObj, tWiFiEndPointParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"RadioNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_RadioNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"SSIDNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_SSIDNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"AccessPointNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_AccessPointNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"EndPointNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFi_EndPointNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Bandsteering_Enable", &DMWRITE, DMT_BOOL, get_wifi_bandsteering_enable, set_wifi_bandsteering_enable, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.Radio.{i}. *** */
DMOBJ tWiFiRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiRadioStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiRadioParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_radio_alias, set_radio_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_radio_enable, set_radio_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_radio_status, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_WiFiRadio_LowerLayers, set_WiFiRadio_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_WiFiRadio_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxBitRate", &DMREAD, DMT_UNINT,get_radio_max_bit_rate, NULL, NULL, NULL, BBFDM_BOTH},
{"OperatingFrequencyBand", &DMREAD, DMT_STRING, get_radio_frequency, NULL, NULL, NULL, BBFDM_BOTH},
{"SupportedFrequencyBands", &DMREAD, DMT_STRING, get_radio_supported_frequency_bands, NULL, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"MaxAssociations", &DMWRITE, DMT_STRING, get_radio_maxassoc, set_radio_maxassoc, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"DFSEnable", &DMWRITE, DMT_BOOL, get_radio_dfsenable, set_radio_dfsenable, NULL, NULL, BBFDM_BOTH},
{"SupportedStandards", &DMREAD, DMT_STRING, get_radio_supported_standard, NULL, NULL, NULL, BBFDM_BOTH},
{"OperatingStandards", &DMWRITE, DMT_STRING, get_radio_operating_standard, set_radio_operating_standard, NULL, NULL, BBFDM_BOTH},
{"ChannelsInUse", &DMREAD, DMT_STRING, get_radio_channel, NULL, NULL, NULL, BBFDM_BOTH},
{"Channel", &DMWRITE, DMT_UNINT, get_radio_channel, set_radio_channel, NULL, NULL, BBFDM_BOTH},
{"AutoChannelEnable", &DMWRITE, DMT_BOOL, get_radio_auto_channel_enable, set_radio_auto_channel_enable, NULL, NULL, BBFDM_BOTH},
{"PossibleChannels", &DMREAD, DMT_STRING, get_radio_possible_channels, NULL, NULL, NULL, BBFDM_BOTH},
{"AutoChannelSupported", &DMREAD, DMT_BOOL, get_WiFiRadio_AutoChannelSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"AutoChannelRefreshPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_AutoChannelRefreshPeriod, set_WiFiRadio_AutoChannelRefreshPeriod, NULL, NULL, BBFDM_BOTH},
{"MaxSupportedAssociations", &DMREAD, DMT_UNINT, get_WiFiRadio_MaxSupportedAssociations, NULL, NULL, NULL, BBFDM_BOTH},
{"FragmentationThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_FragmentationThreshold, set_WiFiRadio_FragmentationThreshold, NULL, NULL, BBFDM_BOTH},
{"RTSThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_RTSThreshold, set_WiFiRadio_RTSThreshold, NULL, NULL, BBFDM_BOTH},
{"BeaconPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_BeaconPeriod, set_WiFiRadio_BeaconPeriod, NULL, NULL, BBFDM_BOTH},
{"DTIMPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_DTIMPeriod, set_WiFiRadio_DTIMPeriod, NULL, NULL, BBFDM_BOTH},
{"SupportedOperatingChannelBandwidths", &DMREAD, DMT_STRING, get_WiFiRadio_SupportedOperatingChannelBandwidths, NULL, NULL, NULL, BBFDM_BOTH},
{"OperatingChannelBandwidth", &DMWRITE, DMT_STRING, get_WiFiRadio_OperatingChannelBandwidth, set_WiFiRadio_OperatingChannelBandwidth, NULL, NULL, BBFDM_BOTH},
{"CurrentOperatingChannelBandwidth", &DMREAD, DMT_STRING, get_WiFiRadio_CurrentOperatingChannelBandwidth, NULL, NULL, NULL, BBFDM_BOTH},
{"PreambleType", &DMWRITE, DMT_STRING, get_WiFiRadio_PreambleType, set_WiFiRadio_PreambleType, NULL, NULL, BBFDM_BOTH},
{"IEEE80211hSupported", &DMREAD, DMT_BOOL, get_WiFiRadio_IEEE80211hSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"IEEE80211hEnabled", &DMWRITE, DMT_BOOL, get_WiFiRadio_IEEE80211hEnabled, set_WiFiRadio_IEEE80211hEnabled, NULL, NULL, BBFDM_BOTH},
{"TransmitPower", &DMWRITE, DMT_INT, get_WiFiRadio_TransmitPower, set_WiFiRadio_TransmitPower, NULL, NULL, BBFDM_BOTH},
{"RegulatoryDomain", &DMWRITE, DMT_STRING, get_WiFiRadio_RegulatoryDomain, set_WiFiRadio_RegulatoryDomain, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.Radio.{i}.Stats. *** */
DMLEAF tWiFiRadioStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNINT, get_radio_statistics_tx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_radio_statistics_rx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_radio_statistics_tx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_radio_statistics_rx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_radio_statistics_tx_errors, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_radio_statistics_rx_errors, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_radio_statistics_tx_discardpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_radio_statistics_rx_discardpackets, NULL, NULL, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_INT, get_WiFiRadioStats_Noise, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic. *** */
DMOBJ tWiFiNeighboringWiFiDiagnosticObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Result", &DMREAD, NULL, NULL, NULL, browseWifiNeighboringWiFiDiagnosticResultInst, NULL, NULL, NULL, NULL, tWiFiNeighboringWiFiDiagnosticResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tWiFiNeighboringWiFiDiagnosticParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_neighboring_wifi_diagnostics_diagnostics_state, set_neighboring_wifi_diagnostics_diagnostics_state, NULL, NULL, BBFDM_CWMP},
{"ResultNumberOfEntries", &DMREAD, DMT_UNINT, get_neighboring_wifi_diagnostics_result_number_entries, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}. *** */
DMLEAF tWiFiNeighboringWiFiDiagnosticResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"SSID", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_ssid, NULL, NULL, NULL, BBFDM_CWMP},
{"BSSID", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_bssid, NULL, NULL, NULL, BBFDM_CWMP},
{"Channel", &DMREAD, DMT_UNINT, get_neighboring_wifi_diagnostics_result_channel, NULL, NULL, NULL, BBFDM_CWMP},
{"SignalStrength", &DMREAD, DMT_INT, get_neighboring_wifi_diagnostics_result_signal_strength, NULL, NULL, NULL, BBFDM_CWMP},
{"OperatingFrequencyBand", &DMREAD, DMT_STRING, get_neighboring_wifi_diagnostics_result_operating_frequency_band, NULL, NULL, NULL, BBFDM_CWMP},
{"Noise", &DMREAD, DMT_INT, get_neighboring_wifi_diagnostics_result_noise, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.WiFi.SSID.{i}. *** */
DMOBJ tWiFiSSIDObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiSSIDStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiSSIDParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_ssid_alias, set_ssid_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_wifi_enable, set_wifi_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_wifi_status, NULL, NULL, NULL, BBFDM_BOTH},
{"SSID", &DMWRITE, DMT_STRING, get_wlan_ssid, set_wlan_ssid, NULL, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING,  get_wlan_ssid, set_wlan_ssid, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_ssid_lower_layer, set_ssid_lower_layer, NULL, NULL, BBFDM_BOTH},
{"BSSID", &DMREAD, DMT_STRING, get_wlan_bssid, NULL, NULL, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiSSID_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.SSID.{i}.Stats. *** */
DMLEAF tWiFiSSIDStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNINT, get_ssid_statistics_tx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_ssid_statistics_rx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_ssid_statistics_tx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_ssid_statistics_rx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNINT, get_WiFiSSIDStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}. *** */
DMOBJ tWiFiAccessPointObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Security", &DMWRITE, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointSecurityParams, NULL, BBFDM_BOTH},
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_wifi_associated_device, NULL, NULL, NULL, tWiFiAccessPointAssociatedDeviceObj, tWiFiAccessPointAssociatedDeviceParams, get_linker_associated_device, BBFDM_BOTH},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointWPSParams, NULL, BBFDM_BOTH},
{"Accounting", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAccountingParams, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"IEEE80211r", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAcessPointIEEE80211rParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiAccessPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_access_point_alias, set_access_point_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL,  get_wifi_enable, set_wifi_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_wifi_status, NULL, NULL, NULL, BBFDM_BOTH},
{"SSIDReference", &DMREAD, DMT_STRING, get_ap_ssid_ref, NULL, NULL, NULL, BBFDM_BOTH},
{"SSIDAdvertisementEnabled", &DMWRITE, DMT_BOOL, get_wlan_ssid_advertisement_enable, set_wlan_ssid_advertisement_enable, NULL, NULL, BBFDM_BOTH},
{"WMMEnable", &DMWRITE, DMT_BOOL, get_wmm_enabled, set_wmm_enabled, NULL, NULL, BBFDM_BOTH},
{"UAPSDEnable", &DMWRITE, DMT_BOOL, get_WiFiAccessPoint_UAPSDEnable, set_WiFiAccessPoint_UAPSDEnable, NULL, NULL, BBFDM_BOTH},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_access_point_total_associations, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxAssociatedDevices", &DMWRITE, DMT_UNINT, get_access_point_maxassoc, set_access_point_maxassoc, NULL, NULL, BBFDM_BOTH},
{"MACAddressControlEnabled", &DMWRITE, DMT_BOOL, get_access_point_control_enable, set_access_point_control_enable, NULL, NULL, BBFDM_BOTH},
{"UAPSDCapability", &DMREAD, DMT_BOOL, get_WiFiAccessPoint_UAPSDCapability, NULL, NULL, NULL, BBFDM_BOTH},
{"WMMCapability", &DMREAD, DMT_BOOL, get_WiFiAccessPoint_WMMCapability, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxAllowedAssociations", &DMWRITE, DMT_UNINT, get_WiFiAccessPoint_MaxAllowedAssociations, set_WiFiAccessPoint_MaxAllowedAssociations, NULL, NULL, BBFDM_BOTH},
{"IsolationEnable", &DMWRITE, DMT_BOOL, get_WiFiAccessPoint_IsolationEnable, set_WiFiAccessPoint_IsolationEnable, NULL, NULL, BBFDM_BOTH},
{"AllowedMACAddress", &DMWRITE, DMT_STRING, get_WiFiAccessPoint_AllowedMACAddress, set_WiFiAccessPoint_AllowedMACAddress, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.Security. *** */
DMLEAF tWiFiAccessPointSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ModesSupported", &DMREAD, DMT_STRING, get_access_point_security_supported_modes, NULL, NULL, NULL, BBFDM_BOTH},
{"ModeEnabled", &DMWRITE, DMT_STRING ,get_access_point_security_modes, set_access_point_security_modes, NULL, NULL, BBFDM_BOTH},
{"WEPKey", &DMWRITE, DMT_STRING, get_empty, set_access_point_security_wepkey, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"WEPKeyIndex", &DMWRITE, DMT_UNINT, get_access_point_security_wepkey_index, set_access_point_security_wepkey_index, NULL, NULL, BBFDM_BOTH},
{"PreSharedKey", &DMWRITE, DMT_STRING, get_empty, set_access_point_security_shared_key, NULL, NULL, BBFDM_BOTH},
{"KeyPassphrase", &DMWRITE, DMT_STRING, get_empty, set_access_point_security_passphrase, NULL, NULL, BBFDM_BOTH},
{"RekeyingInterval", &DMWRITE, DMT_UNINT, get_access_point_security_rekey_interval, set_access_point_security_rekey_interval, NULL, NULL, BBFDM_BOTH},
{"RadiusServerIPAddr", &DMWRITE, DMT_STRING, get_access_point_security_radius_ip_address, set_access_point_security_radius_ip_address, NULL, NULL, BBFDM_BOTH},
{"RadiusServerPort", &DMWRITE, DMT_UNINT, get_access_point_security_radius_server_port, set_access_point_security_radius_server_port, NULL, NULL, BBFDM_BOTH},
{"RadiusSecret", &DMWRITE, DMT_STRING,get_empty, set_access_point_security_radius_secret, NULL, NULL, BBFDM_BOTH},
{"MFPConfig", &DMWRITE, DMT_STRING, get_WiFiAccessPointSecurity_MFPConfig, set_WiFiAccessPointSecurity_MFPConfig, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.WPS. *** */
DMLEAF tWiFiAccessPointWPSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiAccessPointWPS_Enable, set_WiFiAccessPointWPS_Enable, NULL, NULL, BBFDM_BOTH},
{"ConfigMethodsSupported", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_ConfigMethodsSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"ConfigMethodsEnabled", &DMWRITE, DMT_STRING, get_WiFiAccessPointWPS_ConfigMethodsEnabled, set_WiFiAccessPointWPS_ConfigMethodsEnabled, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_Version, NULL, NULL, NULL, BBFDM_BOTH},
{"PIN", &DMWRITE, DMT_STRING, get_WiFiAccessPointWPS_PIN, set_WiFiAccessPointWPS_PIN, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}. *** */
DMOBJ tWiFiAccessPointAssociatedDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAssociatedDeviceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiAccessPointAssociatedDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Active", &DMREAD, DMT_BOOL, get_access_point_associative_device_active, NULL, NULL, NULL, BBFDM_BOTH},
{"Noise", &DMREAD, DMT_INT, get_WiFiAccessPointAssociatedDevice_Noise, NULL, NULL, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING ,get_access_point_associative_device_mac, NULL, NULL, NULL, BBFDM_BOTH},
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_access_point_associative_device_lastdatadownlinkrate, NULL, NULL, NULL, BBFDM_BOTH},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_access_point_associative_device_lastdatauplinkrate, NULL, NULL, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_INT, get_access_point_associative_device_signalstrength, NULL, NULL, NULL, BBFDM_BOTH},
{"Retransmissions", &DMREAD, DMT_UNINT, get_WiFiAccessPointAssociatedDevice_Retransmissions, NULL, NULL, NULL, BBFDM_BOTH},
{"AssociationTime", &DMREAD, DMT_TIME, get_WiFiAccessPointAssociatedDevice_AssociationTime, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats. *** */
DMLEAF tWiFiAccessPointAssociatedDeviceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_tx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_rx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_tx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_rx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_tx_errors, NULL, NULL, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_retrans_count, NULL, NULL, NULL, BBFDM_BOTH},
{"FailedRetransCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_failed_retrans_count, NULL, NULL, NULL, BBFDM_BOTH},
{"RetryCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_retry_count, NULL, NULL, NULL, BBFDM_BOTH},
{"MultipleRetryCount", &DMREAD, DMT_UNINT, get_access_point_associative_device_statistics_multiple_retry_count, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.Accounting. *** */
DMLEAF tWiFiAccessPointAccountingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_WiFiAccessPointAccounting_Enable, set_WiFiAccessPointAccounting_Enable, NULL, NULL, BBFDM_BOTH},
{"ServerIPAddr", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_ServerIPAddr, set_WiFiAccessPointAccounting_ServerIPAddr, NULL, NULL, BBFDM_BOTH},
//{"SecondaryServerIPAddr", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_SecondaryServerIPAddr, set_WiFiAccessPointAccounting_SecondaryServerIPAddr, NULL, NULL, BBFDM_BOTH},
{"ServerPort", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_ServerPort, set_WiFiAccessPointAccounting_ServerPort, NULL, NULL, BBFDM_BOTH},
//{"SecondaryServerPort", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_SecondaryServerPort, set_WiFiAccessPointAccounting_SecondaryServerPort, NULL, NULL, BBFDM_BOTH},
{"Secret", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_Secret, set_WiFiAccessPointAccounting_Secret, NULL, NULL, BBFDM_BOTH},
//{"SecondarySecret", &DMWRITE, DMT_STRING, get_WiFiAccessPointAccounting_SecondarySecret, set_WiFiAccessPointAccounting_SecondarySecret, NULL, NULL, BBFDM_BOTH},
//{"InterimInterval", &DMWRITE, DMT_UNINT, get_WiFiAccessPointAccounting_InterimInterval, set_WiFiAccessPointAccounting_InterimInterval, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** WiFi.AccessPoint.X_IOPSYS_EU_IEEE80211r. ***/
DMLEAF tWiFiAcessPointIEEE80211rParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_access_point_ieee80211r_enable, set_access_point_ieee80211r_enable, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}. *** */
DMOBJ tWiFiEndPointObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointStatsParams, NULL, BBFDM_BOTH},
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointSecurityParams, NULL, BBFDM_BOTH},
{"Profile", &DMREAD, NULL, NULL, NULL, browseWiFiEndPointProfileInst, NULL, NULL, NULL, tWiFiEndPointProfileObj, tWiFiEndPointProfileParams, NULL, BBFDM_BOTH},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointWPSParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiEndPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPoint_Enable, set_WiFiEndPoint_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPoint_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_WiFiEndPoint_Alias, set_WiFiEndPoint_Alias, NULL, NULL, BBFDM_BOTH},
//{"ProfileReference", &DMWRITE, DMT_STRING, get_WiFiEndPoint_ProfileReference, set_WiFiEndPoint_ProfileReference, NULL, NULL, BBFDM_BOTH},
{"SSIDReference", &DMREAD, DMT_STRING, get_WiFiEndPoint_SSIDReference, NULL, NULL, NULL, BBFDM_BOTH},
//{"ProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_WiFiEndPoint_ProfileNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Stats. *** */
DMLEAF tWiFiEndPointStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_LastDataDownlinkRate, NULL, NULL, NULL, BBFDM_BOTH},
{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_LastDataUplinkRate, NULL, NULL, NULL, BBFDM_BOTH},
{"SignalStrength", &DMREAD, DMT_INT, get_WiFiEndPointStats_SignalStrength, NULL, NULL, NULL, BBFDM_BOTH},
{"Retransmissions", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_Retransmissions, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Security. *** */
DMLEAF tWiFiEndPointSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ModesSupported", &DMREAD, DMT_STRING, get_WiFiEndPointSecurity_ModesSupported, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Profile.{i}. *** */
DMOBJ tWiFiEndPointProfileObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointProfileSecurityParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiEndPointProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPointProfile_Enable, set_WiFiEndPointProfile_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPointProfile_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_Alias, set_WiFiEndPointProfile_Alias, NULL, NULL, BBFDM_BOTH},
{"SSID", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_SSID, set_WiFiEndPointProfile_SSID, NULL, NULL, BBFDM_BOTH},
{"Location", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_Location, set_WiFiEndPointProfile_Location, NULL, NULL, BBFDM_BOTH},
{"Priority", &DMWRITE, DMT_UNINT, get_WiFiEndPointProfile_Priority, set_WiFiEndPointProfile_Priority, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Profile.{i}.Security. *** */
DMLEAF tWiFiEndPointProfileSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ModeEnabled", &DMWRITE, DMT_STRING, get_WiFiEndPointProfileSecurity_ModeEnabled, set_WiFiEndPointProfileSecurity_ModeEnabled, NULL, NULL, BBFDM_BOTH},
{"WEPKey", &DMWRITE, DMT_HEXBIN, get_empty, set_WiFiEndPointProfileSecurity_WEPKey, NULL, NULL, BBFDM_BOTH},
{"PreSharedKey", &DMWRITE, DMT_HEXBIN, get_empty, set_WiFiEndPointProfileSecurity_PreSharedKey, NULL, NULL, BBFDM_BOTH},
{"KeyPassphrase", &DMWRITE, DMT_STRING, get_empty, set_WiFiEndPointProfileSecurity_KeyPassphrase, NULL, NULL, BBFDM_BOTH},
{"MFPConfig", &DMWRITE, DMT_STRING, get_WiFiEndPointProfileSecurity_MFPConfig, set_WiFiEndPointProfileSecurity_MFPConfig, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.WPS. *** */
DMLEAF tWiFiEndPointWPSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPointWPS_Enable, set_WiFiEndPointWPS_Enable, NULL, NULL, BBFDM_BOTH},
{"ConfigMethodsSupported", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_ConfigMethodsSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"ConfigMethodsEnabled", &DMWRITE, DMT_STRING, get_WiFiEndPointWPS_ConfigMethodsEnabled, set_WiFiEndPointWPS_ConfigMethodsEnabled, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_Version, NULL, NULL, NULL, BBFDM_BOTH},
{"PIN", &DMWRITE, DMT_UNINT, get_WiFiEndPointWPS_PIN, set_WiFiEndPointWPS_PIN, NULL, NULL, BBFDM_BOTH},
{0}
};

/**************************************************************************
* LINKER
***************************************************************************/
int get_linker_Wifi_Radio(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker) {
	if(data && ((struct wifi_radio_args *)data)->wifi_radio_sec) {
		*linker = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
		return 0;
	}
	*linker = "";
	return 0;
}

int get_linker_Wifi_Ssid(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker) {
	if(data && ((struct wifi_ssid_args *)data)->ifname) {
		*linker = ((struct wifi_ssid_args *)data)->ifname;
		return 0;
	}
	*linker = "";
	return 0;
}

int get_linker_associated_device(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker) {
	struct wifi_associative_device_args* cur_wifi_associative_device_args = (struct wifi_associative_device_args*)data;
	if(data && cur_wifi_associative_device_args->macaddress) {
		*linker= cur_wifi_associative_device_args->macaddress;
		return 0;
	}
	*linker = "";
	return 0;
}
/**************************************************************************
* INIT
***************************************************************************/
inline int init_wifi_radio(struct wifi_radio_args *args, struct uci_section *s)
{
	args->wifi_radio_sec = s;
	return 0;
}

inline int init_wifi_ssid(struct wifi_ssid_args *args, struct uci_section *s, char *wiface, char *linker)
{
	args->wifi_ssid_sec = s;
	args->ifname = wiface;
	args->linker = linker;
	return 0;
}

inline int init_wifi_acp(struct wifi_acp_args *args, struct uci_section *s, char *wiface)
{
	args->wifi_acp_sec = s;
	args->ifname = wiface;
	return 0;
}

inline int init_wifi_enp(struct wifi_enp_args *args, struct uci_section *s, char *wiface)
{
	args->wifi_enp_sec = s;
	args->ifname = wiface;
	return 0;
}
/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.WiFi.RadioNumberOfEntries!UCI:wireless/wifi-device/*/
int get_WiFi_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre= 0;

	uci_foreach_sections("wireless", "wifi-device", s) {
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.SSIDNumberOfEntries!UCI:wireless/wifi-iface/*/
int get_WiFi_SSIDNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre= 0;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.AccessPointNumberOfEntries!UCI:wireless/wifi-iface/*/
int get_WiFi_AccessPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre= 0;
	char *mode= NULL;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		dmuci_get_value_by_section_string(s, "mode", &mode);
		if((strlen(mode)>0 || mode[0] != '\0') && strcmp(mode, "ap") != 0)
			continue;
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.EndPointNumberOfEntries!UCI:wireless/wifi-iface/*/
int get_WiFi_EndPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre= 0;
	char *mode= NULL;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		dmuci_get_value_by_section_string(s, "mode", &mode);
		if(strcmp(mode, "wet") == 0 || strcmp(mode, "sta") == 0)
			nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

int get_wifi_bandsteering_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("wireless", "bandsteering", "enabled", value);
	return 0;
}

int set_wifi_bandsteering_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				dmuci_set_value("wireless", "bandsteering", "enabled", "1");
			}
			else {
				dmuci_set_value("wireless", "bandsteering", "enabled", "0");
			}
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
int get_wifi_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", &val);
	if ((val[0] == '\0') || (val[0] == '0'))
		*value = "1";
	else
		*value = "0";
	return 0;
}

int set_wifi_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", "0");
			else
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", "1");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.Status!UCI:wireless/wifi-iface,@i-1/disabled*/
int get_wifi_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", value);
	if ((*value)[0] == '\0' || (*value)[0] == '0')
		*value = "Up";
	else
		*value = "Down";
	return 0;
}

/*#Device.WiFi.SSID.{i}.SSID!UCI:wireless/wifi-iface,@i-1/ssid*/
static int get_wlan_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "ssid", value);
	return 0;
}

static int set_wlan_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "ssid", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.BSSID!UBUS:router.wireless/status/vif,@Name/bssid*/
static int get_wlan_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.wireless", "status", UBUS_ARGS{{"vif", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "bssid");
	return 0;
}

/*#Device.WiFi.SSID.{i}.MACAddress!UBUS:router.device/status/name,@Name/macaddr*/
int get_WiFiSSID_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "macaddr");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Enable!UCI:wireless/wifi-device,@i-1/disabled*/
int get_radio_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", &val);

	if (val[0] == '1')
		*value = "0";
	else
		*value = "1";
	return 0;
}

int set_radio_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", "0");
			else
				dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", "1");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.Status!UCI:wireless/wifi-device,@i-1/disabled*/
int get_radio_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", value);
	if ((*value)[0] == '1')
		*value = "Down";
	else
		*value = "Up";
	return 0;
}

int get_WiFiRadio_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int set_WiFiRadio_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			return FAULT_9007;
		case VALUESET:
			break;
	}
	return 0;
}

int get_WiFiRadio_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	return 0;
}

/*#Device.WiFi.Radio.{i}.MaxBitRate!UBUS:router.wireless/radios//@Name.rate*/
int get_radio_max_bit_rate (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *wlan_name, *rate;

	*value = "";
	wlan_name = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
	dmubus_call("router.wireless", "radios", UBUS_ARGS{}, 0, &res);
	if(res) {
		rate = dmjson_get_value(res, 2, wlan_name, "rate");
		*value = strtok(rate, " Mbps");
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingFrequencyBand!UBUS:router.wireless/status/vif,@Name/frequency*/
int get_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *freq;
	json_object *res;
	char *wlan_name = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
	dmubus_call("router.wireless", "status", UBUS_ARGS{{"vif", wlan_name, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	freq = dmjson_get_value(res, 1, "frequency");
	if(strcmp(freq, "2") == 0 ) {
		dmastrcat(value, freq, ".4GHz");  // MEM WILL BE FREED IN DMMEMCLEAN
		return 0;
	}
	dmastrcat(value, freq, "GHz");  // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingChannelBandwidth!UCI:wireless/wifi-device,@i-1/bandwidth&UBUS:router.wireless/status/vif,@Name/bandwidth*/
int get_radio_operating_channel_bandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *bandwith;
	json_object *res;
	char *wlan_name;
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "bandwidth", value);
	if (value[0] == '\0')
	{
		wlan_name = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
		dmubus_call("router.wireless", "status", UBUS_ARGS{{"vif", wlan_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		bandwith = dmjson_get_value(res, 1, "bandwidth");
		dmastrcat(value, bandwith, "MHz"); // MEM WILL BE FREED IN DMMEMCLEAN
	}
	else
		dmastrcat(value, *value, "MHz"); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

int set_radio_operating_channel_bandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *pch, *spch, *dup;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dup = dmstrdup(value);
			pch = strtok_r(dup, "Mm", &spch);
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "bandwidth", pch);
			dmfree(dup);
			return 0;
	}
	return 0;
}

int get_radio_maxassoc(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "maxassoc", value);
	return 0;
}

int set_radio_maxassoc(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "maxassoc", value);
			return 0;
	}
	return 0;
}

int get_radio_dfsenable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "band", &val);
	if (val[0] == 'a') {
		dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "dfsc", value);
		if ((*value)[0] == '\0')
			*value = "0";
	}
	return 0;
}

int set_radio_dfsenable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *val;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "band", &val);
			if (val[0] == 'a') {
				string_to_bool(value, &b);
				if (b)
					dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "dfsc", "1");
				else
					dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "dfsc", "0");
			}
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedStandards!UBUS:router.wireless/radios//hwmodes*/
int get_radio_supported_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *freq, *wlan_name;
	json_object *res;

	wlan_name = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
	dmubus_call("router.wireless", "radios", UBUS_ARGS{}, 0, &res);
	json_object_object_foreach(res, key, radio_obj) {
		if(strcmp(wlan_name, key) == 0) {
			*value = dmjson_get_value_array_all(radio_obj, DELIMITOR, 1, "hwmodes");
		}
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingStandards!UBUS:router.wireless/radios//opmode*/
int get_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call("router.wireless", "radios", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	json_object_object_foreach(res, key, radio_obj) {
		if(strcmp(section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), key) == 0) {
			*value = dmjson_get_value(radio_obj, 1, "opmode");
			break;
		}
	}
	return 0;
}

int set_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *freq, *wlan_name;
	json_object *res;
	switch (action) {
			case VALUECHECK:
				return 0;
			case VALUESET:
				wlan_name = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
				dmubus_call("router.wireless", "status", UBUS_ARGS{{"vif", wlan_name, String}}, 1, &res);
				freq = dmjson_get_value(res, 1, "frequency");
				if (strcmp(freq, "5") == 0) {
					 if (strcmp(value, "n") == 0)
						value = "11n"; 
					 else if (strcmp(value, "ac") == 0)
						value = "11ac";
					dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "hwmode", value);
				} else {
					if (strcmp(value, "b") == 0)
						value = "11b";
					else if (strcmp(value, "b,g") == 0 || strcmp(value, "g,b") == 0)
						value = "11bg";
					else if (strcmp(value, "g") == 0)
						value = "11g";
					 else if (strcmp(value, "n") == 0)
						value = "11n";
					dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "hwmode", value);
				}
				return 0;
		}
		return 0;
}

/*#Device.WiFi.Radio.{i}.PossibleChannels!UBUS:router.wireless/radios//@Name.channels*/
int get_radio_possible_channels(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *wlan_name;
	
	*value = "";
	wlan_name = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
	dmubus_call("router.wireless", "radios", UBUS_ARGS{}, 0, &res);
	if(res)
		*value = dmjson_get_value_array_all(res, DELIMITOR, 2, wlan_name, "channels");
	return 0;
}

int get_WiFiRadio_AutoChannelSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="true";
	return 0;
}

/*#Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod!UCI:wireless/wifi-device,@i-1/scantimer*/
int get_WiFiRadio_AutoChannelRefreshPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "scantimer", value);
	return 0;
}

int set_WiFiRadio_AutoChannelRefreshPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "scantimer", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.MaxSupportedAssociations!UCI:wireless/wifi-device,@i-1/maxassoc*/
int get_WiFiRadio_MaxSupportedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "maxassoc", value);
	return 0;
}

/*#Device.WiFi.Radio.{i}.FragmentationThreshold!UCI:wireless/wifi-device,@i-1/frag*/
int get_WiFiRadio_FragmentationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "frag", value);
	return 0;
}

int set_WiFiRadio_FragmentationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "frag", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.RTSThreshold!UCI:wireless/wifi-device,@i-1/rts*/
int get_WiFiRadio_RTSThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "rts", value);
	return 0;
}

int set_WiFiRadio_RTSThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "rts", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.BeaconPeriod!UCI:wireless/wifi-device,@i-1/beacon_int*/
int get_WiFiRadio_BeaconPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "beacon_int", value);
	return 0;
}

int set_WiFiRadio_BeaconPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "beacon_int", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.DTIMPeriod!UCI:wireless/wifi-device,@i-1/dtim_period*/
int get_WiFiRadio_DTIMPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "dtim_period", value);
	return 0;
}

int set_WiFiRadio_DTIMPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "dtim_period", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedOperatingChannelBandwidths!UBUS:router.wireless/radios//@Name.bandwidth*/
int get_WiFiRadio_SupportedOperatingChannelBandwidths(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res, *jobj;

	dmubus_call("router.wireless", "radios", UBUS_ARGS{{}}, 0, &res);
	if(res)
		*value = dmjson_get_value_array_all(res, DELIMITOR, 2, section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), "bwcaps");

	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingChannelBandwidth!UCI:wireless/wifi-device,@i-1/bandwidth*/
int get_WiFiRadio_OperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "bandwidth", value);
	if(*value[0] == '\0') {
		*value= "";
		return 0;
	}
	dmastrcat(value, *value, "MHz");
	return 0;
}

int set_WiFiRadio_OperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "bandwidth", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.CurrentOperatingChannelBandwidth!UBUS:router.wireless/radios//@Name.bandwidth*/
int get_WiFiRadio_CurrentOperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	dmubus_call("router.wireless", "status", UBUS_ARGS{{"vif", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	if(res)
		*value = dmjson_get_value(res, 1, "bandwidth");
	return 0;
}

/*#Device.WiFi.Radio.{i}.PreambleType!UCI:wireless/wifi-device,@i-1/short_preamble*/
int get_WiFiRadio_PreambleType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *preamble= NULL;

	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "short_preamble", &preamble);
	if (preamble[0] == '\0' || strlen(preamble) == 0 || strcmp(preamble, "1") != 0)
		*value= "long";
	else
		*value= "short";
	return 0;
}

int set_WiFiRadio_PreambleType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			if(strcmp(value, "short") == 0)
				dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "short_preamble", "1");
			else
				dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "short_preamble", "0");
			break;
	}
	return 0;
}

int get_WiFiRadio_IEEE80211hSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= "true";
	return 0;
}

/*#Device.WiFi.Radio.{i}.IEEE80211hEnabled!UCI:wireless/wifi-device,@i-1/doth*/
int get_WiFiRadio_IEEE80211hEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "doth", value);
	return 0;
}

int set_WiFiRadio_IEEE80211hEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if(b)
				dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "doth", "1");
			else
				dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "doth", "0");
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.TransmitPower!UCI:wireless/wifi-device,@i-1/txpower*/
int get_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "txpower", value);
	return 0;
}

int set_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "txpower", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.RegulatoryDomain!UCI:wireless/wifi-device,@i-1/country*/
int get_WiFiRadio_RegulatoryDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *country, **arr;
	int length;

	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "country", &country);
	arr= strsplit(country, "/", &length);
	if(strlen(arr[0]) > 0)
		dmasprintf(value, "%s", arr[0]);
	else
		*value= "";

	return 0;
}

int set_WiFiRadio_RegulatoryDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *country, **arr;
	int length;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "country", &country);
			if(strlen(country)>0){
				arr= strsplit(country, "/", &length);
				dmasprintf(&country, "%s/%s", value, arr[1]);
			} else
				dmasprintf(&country, "%s/1", value);
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "country", country);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.ChannelsInUse!UCI:wireless/wifi-device,@i-1/channel*/
int get_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char *wlan_name;
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
	if (strcmp(*value, "auto") == 0 || (*value)[0] == '\0') {
		wlan_name = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
		dmubus_call("router.wireless", "status", UBUS_ARGS{{"vif", wlan_name, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		*value = dmjson_get_value(res, 1, "channel");
	}
	return 0;
}

int set_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.AutoChannelEnable!UCI:wireless/wifi-device,@i-1/channel*/
int get_radio_auto_channel_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
	if (strcmp(*value, "auto") == 0 || (*value)[0] == '\0')
		*value = "1";
	else
		*value = "0";
	return 0;
}

int set_radio_auto_channel_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	json_object *res;
	char *wlan_name;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				value = "auto";
			else {
				wlan_name = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
				dmubus_call("router.wireless", "status", UBUS_ARGS{{"vif", wlan_name, String}}, 1, &res);
				if(res == NULL)
					return 0;
				else
					value = dmjson_get_value(res, 1, "channel");
			}
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
			return 0;
	}
	return 0;
}

/*************************************************************
 * GET STAT
/*************************************************************/
/*#Device.WiFi.Radio.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
int get_radio_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "tx_bytes");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.BytesReceived!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
int get_radio_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "rx_bytes");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
int get_radio_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "tx_packets");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
int get_radio_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "rx_packets");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsSent!UBUS:network.device/status/name,@Name/statistics.tx_errors*/
int get_radio_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "tx_errors");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsReceived!UBUS:network.device/status/name,@Name/statistics.rx_errors*/
int get_radio_statistics_rx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "rx_errors");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_dropped*/
int get_radio_statistics_tx_discardpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "tx_dropped");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_dropped*/
int get_radio_statistics_rx_discardpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "rx_dropped");
	return 0;
}

int get_WiFiRadioStats_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	dmubus_call("router.wireless", "status", UBUS_ARGS{{"vif", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	if(res)
		*value = dmjson_get_value(res, 1, "noise");
	return 0;
}

/*#Device.WiFi.SSID.{i}.Stats.BytesSent!UBUS:network.device/status/name,@Name/statistics.tx_bytes*/
int get_ssid_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "tx_bytes");
	return 0;
}

/*#Device.WiFi.SSID.{i}.Stats.BytesReceived!UBUS:network.device/status/name,@Name/statistics.rx_bytes*/
int get_ssid_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "rx_bytes");
	return 0;
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_packets*/
int get_ssid_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "tx_packets");
	return 0;
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_packets*/
int get_ssid_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "rx_packets");
	return 0;
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsSent!UBUS:network.device/status/name,@Name/statistics.tx_errors*/
int get_WiFiSSIDStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "tx_errors");
	return 0;
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsReceived!UBUS:network.device/status/name,@Name/statistics.rx_errors*/
int get_WiFiSSIDStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "rx_errors");
	return 0;
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent!UBUS:network.device/status/name,@Name/statistics.tx_dropped*/
int get_WiFiSSIDStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "tx_dropped");
	return 0;
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived!UBUS:network.device/status/name,@Name/statistics.rx_dropped*/
int get_WiFiSSIDStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "statistics", "rx_dropped");
	return 0;
}

int get_WiFiSSIDStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct wifi_ssid_args *)data)->ifname && strlen(((struct wifi_ssid_args *)data)->ifname)>0)
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(((struct wifi_ssid_args *)data)->ifname, "TX", "unicast"));
	return 0;
}

int get_WiFiSSIDStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct wifi_ssid_args *)data)->ifname && strlen(((struct wifi_ssid_args *)data)->ifname)>0)
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(((struct wifi_ssid_args *)data)->ifname, "RX", "unicast"));
	return 0;
}

int get_WiFiSSIDStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct wifi_ssid_args *)data)->ifname && strlen(((struct wifi_ssid_args *)data)->ifname)>0)
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(((struct wifi_ssid_args *)data)->ifname, "TX", "multicast"));
	return 0;
}

int get_WiFiSSIDStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct wifi_ssid_args *)data)->ifname && strlen(((struct wifi_ssid_args *)data)->ifname)>0)
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(((struct wifi_ssid_args *)data)->ifname, "RX", "multicast"));
	return 0;
}

int get_WiFiSSIDStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct wifi_ssid_args *)data)->ifname && strlen(((struct wifi_ssid_args *)data)->ifname)>0)
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(((struct wifi_ssid_args *)data)->ifname, "TX", "broadcast"));
	return 0;
}

int get_WiFiSSIDStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct wifi_ssid_args *)data)->ifname && strlen(((struct wifi_ssid_args *)data)->ifname)>0)
		dmasprintf(value, "%d", get_stats_from_ifconfig_command(((struct wifi_ssid_args *)data)->ifname, "RX", "broadcast"));
	return 0;
}

static char *get_associative_device_statistics(struct wifi_associative_device_args *wifi_associative_device, char *key)
{
	json_object *res, *jobj;
	char *macaddr, *stats = "0";
	int entries = 0;

	dmubus_call("wifix", "stations", UBUS_ARGS{{"vif", wifi_associative_device->wdev, String}}, 1, &res);
	while (res) {
		jobj = dmjson_select_obj_in_array_idx(res, entries, 1, "stations");
		if(jobj) {
			macaddr = dmjson_get_value(jobj, 1, "macaddr");
			if (!strcmp(macaddr, wifi_associative_device->macaddress)) {
				stats = dmjson_get_value(jobj, 2, "stats", key);
				if(*stats != '\0')
					return stats;
			}
			entries++;
		}
		else
			break;
	}
	return stats;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.BytesSent!UBUS:wifix/stations/vif,@Name/stats.tx_total_bytes*/
int get_access_point_associative_device_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "tx_total_bytes");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.BytesReceived!UBUS:wifix/stations/vif,@Name/stats.rx_data_bytes*/
int get_access_point_associative_device_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "rx_data_bytes");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.PacketsSent!UBUS:wifix/stations/vif,@Name/stats.tx_total_pkts*/
int get_access_point_associative_device_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "tx_total_pkts");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.PacketsReceived!UBUS:wifix/stations/vif,@Name/stats.rx_data_pkts*/
int get_access_point_associative_device_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "rx_data_pkts");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.ErrorsSent!UBUS:wifix/stations/vif,@Name/stats.tx_failures*/
int get_access_point_associative_device_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "tx_failures");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.RetransCount!UBUS:wifix/stations/vif,@Name/stats.tx_pkts_retries*/
int get_access_point_associative_device_statistics_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "tx_pkts_retries");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.FailedRetransCount!UBUS:wifix/stations/vif,@Name/stats.tx_pkts_retry_exhausted*/
int get_access_point_associative_device_statistics_failed_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "tx_pkts_retry_exhausted");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.RetryCount!UBUS:wifix/stations/vif,@Name/stats.tx_pkts_retries*/
int get_access_point_associative_device_statistics_retry_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "tx_pkts_retries");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Stats.MultipleRetryCount!UBUS:wifix/stations/vif,@Name/stats.tx_data_pkts_retried*/
int get_access_point_associative_device_statistics_multiple_retry_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr = (struct wifi_associative_device_args*)data;

	*value = get_associative_device_statistics(cur_wifi_associative_device_args_ptr, "tx_data_pkts_retried");
	return 0;
}

/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.WiFi.SSID.{i}.SSIDAdvertisementEnabled!UCI:wireless/wifi-iface,@i-1/hidden*/
static int get_wlan_ssid_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *hidden;
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "hidden", &hidden);
	if (hidden[0] == '1' && hidden[1] == '\0')
		*value = "0";
	else
		*value = "1";
	return 0;
}

static int set_wlan_ssid_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "hidden", "");
			else
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "hidden", "1");
			return 0;

	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WMMEnable!UCI:wireless/wifi-device,@i-1/wmm*/
static int get_wmm_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", value);
	dmuci_get_option_value_string("wireless", *value, "wmm", value);
	string_to_bool(*value, &b);
		if (b)
			*value = "true";
		else
			*value = "false";

	return 0;
}

static int set_wmm_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *device;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", &device);
			if (b) {
				dmuci_set_value("wireless", device, "wmm", "1");
				dmuci_set_value("wireless", device, "wmm_noack", "1");
				dmuci_set_value("wireless", device, "wmm_apsd", "1");
			}
			else {
				dmuci_set_value("wireless", device, "wmm", "0");
				dmuci_set_value("wireless", device, "wmm_noack", "");
				dmuci_set_value("wireless", device, "wmm_apsd", "");
			}
			return 0;
	}
	return 0;
}

int get_access_point_total_associations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res, *jobj;
	int entries = 0;
	dmubus_call("wifix", "stations", UBUS_ARGS{{"vif", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);

	while (1) {
		jobj = dmjson_select_obj_in_array_idx(res, entries, 1, "stations");
		if (jobj == NULL)
			break;
		entries++;
	}
	dmasprintf(value, "%d", entries); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices!UCI:wireless/wifi-iface,@i-1/maxassoc*/
int get_access_point_maxassoc(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device;
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "device", &device);
	dmuci_get_option_value_string("wireless", device, "maxassoc", value);
	return 0;
}

int set_access_point_maxassoc(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *device;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", &device);
			dmuci_set_value("wireless", device, "maxassoc", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MACAddressControlEnabled!UCI:wireless/wifi-iface,@i-1/macfilter*/
int get_access_point_control_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *macfilter;
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "macfilter", &macfilter);
	if (strcmp(macfilter, "deny") == 0 || strcmp(macfilter, "disable") == 0)
		*value = "false";
	else
		*value = "true";
	return 0;
}

int get_WiFiAccessPoint_WMMCapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= "true";
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MaxAllowedAssociations!UCI:wireless/wifi-iface,@i-1/maxassoc*/
int get_WiFiAccessPoint_MaxAllowedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *device;
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", &device);
	dmuci_get_option_value_string("wireless", device, "maxassoc", value);
	return 0;
}

int set_WiFiAccessPoint_MaxAllowedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *device;
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", &device);
			dmuci_set_value("wireless", device, "maxassoc", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.IsolationEnable!UCI:wireless/wifi-iface,@i-1/isolate*/
int get_WiFiAccessPoint_IsolationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "isolate", value);
	return 0;
}

int set_WiFiAccessPoint_IsolationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if(b)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "isolate", "1");
			else
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "isolate", "0");
			break;
	}
	return 0;
}

int get_WiFiAccessPoint_AllowedMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val;
	dmuci_get_value_by_section_list(((struct wifi_acp_args *)data)->wifi_acp_sec, "maclist", &val);
	if (val)
		*value = dmuci_list_to_string(val, " ");
	else
		*value = "";
	return 0;
}

int set_WiFiAccessPoint_AllowedMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	int length, i;
	char **arr;
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			arr= strsplit(value, " ", &length);
			for (i=0; i<length; i++){
				dmuci_add_list_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "maclist", arr[i]);
			}
			break;
	}
	return 0;
}

int get_WiFiAccessPoint_UAPSDCapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= "true";
	return 0;
}

int set_access_point_control_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "macfilter", "allow");
			else
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "macfilter", "disable");

			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.UAPSDEnable!UCI:wireless/wifi-iface,@i-1/wmm_apsd*/
int get_WiFiAccessPoint_UAPSDEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wmm_apsd", value);
	return 0;
}

int set_WiFiAccessPoint_UAPSDEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				value = "1";
			else
				value = "0";
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wmm_apsd", value);
			break;
	}
	return 0;
}
int get_access_point_security_supported_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "None, WEP-64, WEP-128, WPA-Personal, WPA2-Personal, WPA-WPA2-Personal, WPA-Enterprise, WPA2-Enterprise, WPA-WPA2-Enterprise";
	return 0;
}

static void get_value_security_mode(char **value, char *encryption, char *cipher)
{
	if (strcmp(encryption, "none") == 0)
		*value = "None";
	else if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0)
		*value = "WEP-64";
	else if (strcmp(encryption, "psk") == 0)
		*value = "WPA-Personal";
	else if (strcmp(encryption, "wpa") == 0)
		*value = "WPA-Enterprise";
	else if ((strcmp(encryption, "psk2") == 0 && strcmp(cipher, "auto") == 0) || (strcmp(encryption, "psk2") == 0 && strcmp(cipher, "ccmp") == 0) || (strcmp(encryption, "psk2") == 0 && *cipher == '\0'))
		*value = "WPA2-Personal";
	else if (strcmp(encryption, "wpa2") == 0)
		*value = "WPA2-Enterprise";
	else if ((strcmp(encryption, "mixed-psk") == 0 && strcmp(cipher, "auto") == 0) || (strcmp(encryption, "mixed-psk") == 0 && strcmp(cipher, "ccmp") == 0) || (strcmp(encryption, "mixed-psk") == 0 && strcmp(cipher, "tkip+ccmp") == 0) || (strcmp(encryption, "mixed-psk") == 0 && *cipher == '\0'))
		*value = "WPA-WPA2-Personal";
	else if (strcmp(encryption, "wpa-mixed") == 0 || strcmp(encryption, "mixed-wpa") == 0)
		*value = "WPA-WPA2-Enterprise";
}

int get_access_point_security_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *encryption, *cipher, *mode;

	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "cipher", &cipher);
	if (*encryption == '\0' && *cipher == '\0') {
		*value = "None";
		return 0;
	}
	else
		get_value_security_mode(&mode, encryption, cipher);

	*value = mode;
	return 0;
}

int set_access_point_security_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *option, *gnw;
	char *encryption, *cipher, *mode;
	char strk64[4][11];

	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "cipher", &cipher);
	get_value_security_mode(&mode, encryption, cipher);
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (strcmp(value, mode) != 0) {
				if (strcmp(value, "None") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "none");
				}
				else if (strcmp(value, "WEP-64") == 0 || strcmp(value, "WEP-128") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "wep-open");
					wepkey64("Iopsys", strk64);
					int i = 0;
					while (i < 4) {
						dmasprintf(&option, "key%d", i + 1);
						dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, option, strk64[i]);
						dmfree(option);
						i++;
					}
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", "1");
				}
				else if (strcmp(value, "WPA-Personal") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					gnw = get_nvram_wpakey();
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "psk");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", gnw);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "cipher", "tkip");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "gtk_rekey", "3600");
					dmfree(gnw);
				}
				else if (strcmp(value, "WPA-Enterprise") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "wpa");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_server", "");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_port", "1812");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_secret", "");
				}
				else if (strcmp(value, "WPA2-Personal") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					gnw = get_nvram_wpakey();
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "psk2");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", gnw);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "cipher", "ccmp");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "gtk_rekey", "3600");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", "1");
					dmfree(gnw);
				}
				else if (strcmp(value, "WPA2-Enterprise") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "wpa2");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_server", "");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_port", "1812");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_secret", "");
				}
				else if (strcmp(value, "WPA-WPA2-Personal") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					gnw = get_nvram_wpakey();
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "mixed-psk");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", gnw);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "cipher", "tkip+ccmp");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "gtk_rekey", "3600");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", "1");
					dmfree(gnw);
				}
				else if (strcmp(value, "WPA-WPA2-Enterprise") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "wpa-mixed");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_server", "");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_port", "1812");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_secret", "");
				}
			}
			return 0;
	}
	return 0;
}

int set_access_point_security_wepkey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *key_index, *encryption;
	char buf[8];
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0 ) {
				dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "key_index", &key_index);
				sprintf(buf,"key%s", key_index);
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, buf, value);
			}
			return 0;
	}
	return 0;
}

int get_access_point_security_wepkey_index(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *key_index;

	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "key_index", &key_index);
	if (*key_index == '\0')
		*value = "1";
	else
		*value = key_index;
	return 0;
}

int set_access_point_security_wepkey_index(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (atoi(value)>=1 && atoi(value)<=4) {
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key_index", value);
			}
			return 0;
	}
	return 0;
}

int set_access_point_security_shared_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 ) {
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", value);
			}
			return 0;
	}
	return 0;
}

int set_access_point_security_passphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 ) {
				set_access_point_security_shared_key(refparam, ctx, data, instance, value, action);
			}
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RekeyingInterval!UCI:wireless/wifi-iface,@i-1/gtk_rekey*/
int get_access_point_security_rekey_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "gtk_rekey", value);
	return 0;
}

int set_access_point_security_rekey_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *key_index, *encryption;
	char buf[8];
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0 || strcmp(encryption, "none") == 0)
				return 0;
			else {
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "gtk_rekey", value);
			}
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr!UCI:wireless/wifi-iface,@i-1/radius_server*/
int get_access_point_security_radius_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_server", value);
	return 0;
}

int set_access_point_security_radius_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *key_index, *encryption;
	char buf[8];
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_server", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort!UCI:wireless/wifi-iface,@i-1/radius_port*/
int get_access_point_security_radius_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_port", value);
	return 0;
}

int set_access_point_security_radius_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *key_index, *encryption;
	char buf[8];
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_port", value);
			return 0;
	}
	return 0;
}

int set_access_point_security_radius_secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *key_index, *encryption;
	char buf[8];
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "radius_secret", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.MFPConfig!UCI:wireless/wifi-iface,@i-1/ieee80211w*/
int get_WiFiAccessPointSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "ieee80211w", value);
	return 0;
}

int set_WiFiAccessPointSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "ieee80211w", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps*/
int get_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", value);
	if(*value[0] == '\0')
		*value= "0";
	return 0;
}

int set_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *boolS;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if(b)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", "1");
			else
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", "0");
			break;
	}
	return 0;
}

int get_WiFiAccessPointWPS_ConfigMethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= "PushButton,Label,PIN";
	return 0;
}

int get_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pushbut= NULL, *label= NULL, *pin= NULL, *methodenabled= NULL, *tmp, *str1, *str2, *str3;
	bool a, b, c;
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pushbutton", &pushbut);
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_label", &label);
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", &pin);

	if(pushbut == NULL || pushbut[0]=='\0' || strcmp(pushbut, "1")!=0)
		str1= dmstrdup("");
	else
		str1= dmstrdup("PushButton");

	if(label == NULL || label[0]=='\0' || strcmp(label, "1")!=0)
		str2= dmstrdup("");
	else {
		if(pushbut == NULL || pushbut[0]=='\0' || strcmp(pushbut, "1")!=0)
			str2= dmstrdup("Label");
		else
			str2= dmstrdup(",Label");
	}

	if(pin == NULL || pin[0]=='\0')
		str3= dmstrdup("");
	else {
		if((pushbut != NULL && pushbut[0]!='\0' && strcmp(pushbut, "1")==0) || (label != NULL && label[0]!='\0' && strcmp(label, "1")==0))
			str3= dmstrdup(",PIN");
		else
			str3= dmstrdup("PIN");
	}

	dmasprintf(value,"%s%s%s", str1, str2, str3);
	return 0;
}

int set_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps*/
int get_WiFiAccessPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", &wps_status);
	if(strcmp(wps_status, "0") == 0)
		*value= "Disabled";
	else
		*value= "Configured";
	return 0;
}

int get_WiFiAccessPointWPS_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.PIN!UCI:wireless/wifi-iface,@i-1/wps_pin*/
int get_WiFiAccessPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps_pin", value);
	return 0;
}

int set_WiFiAccessPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps_pin", value);
			break;
	}
	return 0;
}

int get_WiFiAccessPointAccounting_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_WiFiAccessPointAccounting_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.WiFi.AccessPoint.{i}.Accounting.ServerIPAddr!UCI:wireless/wifi-iface,@i-1/acct_server*/
int get_WiFiAccessPointAccounting_ServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_server", value);
	return 0;
}

int set_WiFiAccessPointAccounting_ServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_server", value);
			break;
	}
	return 0;
}

int get_WiFiAccessPointAccounting_SecondaryServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_WiFiAccessPointAccounting_SecondaryServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.WiFi.AccessPoint.{i}.Accounting.ServerPort!UCI:wireless/wifi-iface,@i-1/acct_port*/
int get_WiFiAccessPointAccounting_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_port", value);
	return 0;
}

int set_WiFiAccessPointAccounting_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_port", value);
			break;
	}
	return 0;
}

int get_WiFiAccessPointAccounting_SecondaryServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_WiFiAccessPointAccounting_SecondaryServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.WiFi.AccessPoint.{i}.Accounting.Secret!UCI:wireless/wifi-iface,@i-1/acct_secret*/
int get_WiFiAccessPointAccounting_Secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_secret", value);
	return 0;
}

int set_WiFiAccessPointAccounting_Secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_secret", value);
			break;
	}
	return 0;
}

int get_WiFiAccessPointAccounting_SecondarySecret(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_WiFiAccessPointAccounting_SecondarySecret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_WiFiAccessPointAccounting_InterimInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_WiFiAccessPointAccounting_InterimInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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


int get_radio_supported_frequency_bands(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "2.4GHz, 5GHz";
	return 0;
}

int get_access_point_associative_device_lastdatadownlinkrate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr=(struct wifi_associative_device_args*)data;
	dmasprintf(value, "%d", cur_wifi_associative_device_args_ptr->lastdatadownloadlinkrate);
	return 0;
}

int get_access_point_associative_device_lastdatauplinkrate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr=(struct wifi_associative_device_args*)data;
	dmasprintf(value, "%d", cur_wifi_associative_device_args_ptr->lastdatauplinkrate);
	return 0;
}

int get_access_point_associative_device_signalstrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr=(struct wifi_associative_device_args*)data;
	dmasprintf(value, "%d", cur_wifi_associative_device_args_ptr->signalstrength);
	return 0;
}

int get_WiFiAccessPointAssociatedDevice_Retransmissions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr=(struct wifi_associative_device_args*)data;
	dmasprintf(value, "%d", cur_wifi_associative_device_args_ptr->retransmissions);
	return 0;
}

int get_WiFiAccessPointAssociatedDevice_AssociationTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr=(struct wifi_associative_device_args*)data;
	dmasprintf(value, "%s", cur_wifi_associative_device_args_ptr->assoctime?int_period_to_date_time_format(cur_wifi_associative_device_args_ptr->assoctime):"0");
	return 0;
}

int get_access_point_associative_device_mac(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr=(struct wifi_associative_device_args*)data;
	dmasprintf(value, cur_wifi_associative_device_args_ptr->macaddress);
	return 0;
}

int get_access_point_associative_device_active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr=(struct wifi_associative_device_args*)data;
	dmasprintf(value, "%s", cur_wifi_associative_device_args_ptr->active?"true":"false");
	return 0;
}


int get_WiFiAccessPointAssociatedDevice_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_associative_device_args *cur_wifi_associative_device_args_ptr=(struct wifi_associative_device_args*)data;
	dmasprintf(value, "%d", cur_wifi_associative_device_args_ptr->noise);
	return 0;
}

int get_access_point_ieee80211r_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "ieee80211r", value);
	if ((*value)[0] == '\0')
		*value = "0";
	return 0;
}

int set_access_point_ieee80211r_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "ieee80211r", b?"1":"0");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
int get_WiFiEndPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", &val);
	if ((val[0] == '\0') || (val[0] == '0'))
		*value = "1";
	else
		*value = "0";
	return 0;
}

int set_WiFiEndPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", "0");
			else
				dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", "1");
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Status!UCI:wireless/wifi-iface,@i-1/disabled*/
int get_WiFiEndPoint_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", value);
	if ((*value)[0] == '\0' || (*value)[0] == '0')
		*value = "Up";
	else
		*value = "Down";
	return 0;
}

int get_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_enp_args *)data)->wifi_enp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointalias", value);
	return 0;
	return 0;
}

int set_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_enp_args *)data)->wifi_enp_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "endpointalias", value);
			return 0;
	}
	return 0;
}

int get_WiFiEndPoint_ProfileReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_WiFiEndPoint_ProfileReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_WiFiEndPoint_SSIDReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_enp_args *)data)->ifname, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

int get_WiFiEndPointProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="1";
	return 0;
}

int set_WiFiEndPointProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_WiFiEndPointProfile_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="Active";
	return 0;
}

int get_WiFiEndPointProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section, *dm;
	char *epinst= NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name((struct uci_section*)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &epinst);
	get_dmmap_section_of_config_section_eq("dmmap_wireless", "ep_profile", "ep_key", epinst, &dm);
	dmuci_get_value_by_section_string(dm, "ep_profile_alias", value);
	return 0;
}

int set_WiFiEndPointProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section, *dm;
	char *epinst= NULL;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name((struct uci_section*)data), &dmmap_section);
			dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &epinst);
			get_dmmap_section_of_config_section_eq("dmmap_wireless", "ep_profile", "ep_key", epinst, &dm);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dm, "ep_profile_alias", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.SSID!UCI:wireless/wifi-iface,@i-1/ssid*/
int get_WiFiEndPointProfile_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section*)data, "ssid", value);
	return 0;
}

int set_WiFiEndPointProfile_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section*)data, "ssid", value);
			break;
	}
	return 0;
}

int get_WiFiEndPointProfile_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_WiFiEndPointProfile_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_WiFiEndPointProfile_Priority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="0";
	return 0;
}

int set_WiFiEndPointProfile_Priority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.Security.SSID!UCI:wireless/wifi-iface,@i-1/encryption*/
int get_WiFiEndPointProfileSecurity_ModeEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *encryption, *cipher, *mode;

	dmuci_get_value_by_section_string((struct uci_section *)data, "encryption", &encryption);
	dmuci_get_value_by_section_string((struct uci_section *)data, "cipher", &cipher);
	if (*encryption == '\0' && *cipher == '\0') {
		*value = "None";
		return 0;
	}
	else
		get_value_security_mode(&mode, encryption, cipher);

	*value = mode;
	return 0;
}

int set_WiFiEndPointProfileSecurity_ModeEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *option, *gnw;
	char *encryption, *cipher, *mode;
	char strk64[4][11];

	dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
	dmuci_get_value_by_section_string((struct uci_section*)data, "cipher", &cipher);
	get_value_security_mode(&mode, encryption, cipher);
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (strcmp(value, mode) != 0) {
				if (strcmp(value, "None") == 0) {
					reset_wlan((struct uci_section*)data);
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "none");
				}
				else if (strcmp(value, "WEP-64") == 0 || strcmp(value, "WEP-128") == 0) {
					reset_wlan((struct uci_section*)data);
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "wep-open");
					wepkey64("Iopsys", strk64);
					int i = 0;
					while (i < 4) {
						dmasprintf(&option, "key%d", i + 1);
						dmuci_set_value_by_section((struct uci_section*)data, option, strk64[i]);
						dmfree(option);
						i++;
					}
					dmuci_set_value_by_section((struct uci_section*)data, "key", "1");
				}
				else if (strcmp(value, "WPA-Personal") == 0) {
					reset_wlan((struct uci_section*)data);
					gnw = get_nvram_wpakey();
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "psk");
					dmuci_set_value_by_section((struct uci_section*)data, "key", gnw);
					dmuci_set_value_by_section((struct uci_section*)data, "cipher", "tkip");
					dmuci_set_value_by_section((struct uci_section*)data, "gtk_rekey", "3600");
					dmfree(gnw);
				}
				else if (strcmp(value, "WPA-Enterprise") == 0) {
						reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
						dmuci_set_value_by_section((struct uci_section*)data, "encryption", "wpa");
						dmuci_set_value_by_section((struct uci_section*)data, "radius_server", "");
						dmuci_set_value_by_section((struct uci_section*)data, "radius_port", "1812");
						dmuci_set_value_by_section((struct uci_section*)data, "radius_secret", "");
				}
				else if (strcmp(value, "WPA2-Personal") == 0) {
					reset_wlan((struct uci_section*)data);
					gnw = get_nvram_wpakey();
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "psk2");
					dmuci_set_value_by_section((struct uci_section*)data, "key", gnw);
					dmuci_set_value_by_section((struct uci_section*)data, "cipher", "ccmp");
					dmuci_set_value_by_section((struct uci_section*)data, "gtk_rekey", "3600");
					dmuci_set_value_by_section((struct uci_section*)data, "wps", "1");
					dmfree(gnw);
				}
				else if (strcmp(value, "WPA2-Enterprise") == 0) {
					reset_wlan((struct uci_section*)data);
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "wpa2");
					dmuci_set_value_by_section((struct uci_section*)data, "radius_server", "");
					dmuci_set_value_by_section((struct uci_section*)data, "radius_port", "1812");
					dmuci_set_value_by_section((struct uci_section*)data, "radius_secret", "");
				}
				else if (strcmp(value, "WPA-WPA2-Personal") == 0) {
					reset_wlan((struct uci_section*)data);
					gnw = get_nvram_wpakey();
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "mixed-psk");
					dmuci_set_value_by_section((struct uci_section*)data, "key", gnw);
					dmuci_set_value_by_section((struct uci_section*)data, "cipher", "tkip+ccmp");
					dmuci_set_value_by_section((struct uci_section*)data, "gtk_rekey", "3600");
					dmuci_set_value_by_section((struct uci_section*)data, "wps", "1");
					dmfree(gnw);
				}
				else if (strcmp(value, "WPA-WPA2-Enterprise") == 0) {
					reset_wlan((struct uci_section*)data);
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "wpa-mixed");
					dmuci_set_value_by_section((struct uci_section*)data, "radius_server", "");
					dmuci_set_value_by_section((struct uci_section*)data, "radius_port", "1812");
					dmuci_set_value_by_section((struct uci_section*)data, "radius_secret", "");
				}
			}
			return 0;
	}
	return 0;
}

int set_WiFiEndPointProfileSecurity_WEPKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *key_index, *encryption;
	char buf[8];
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0 ) {
				dmuci_get_value_by_section_string((struct uci_section*)data, "key_index", &key_index);
				sprintf(buf,"key%s", key_index);
				dmuci_set_value_by_section((struct uci_section*)data, buf, value);
			}
			return 0;
	}
	return 0;
}

int set_WiFiEndPointProfileSecurity_PreSharedKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 ) {
				dmuci_set_value_by_section((struct uci_section*)data, "key", value);
			}
			return 0;
	}
	return 0;
}

int set_WiFiEndPointProfileSecurity_KeyPassphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 ) {
				set_WiFiEndPointProfileSecurity_PreSharedKey(refparam, ctx, data, instance, value, action);
			}
			return 0;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.Security.MFPConfig!UCI:wireless/wifi-iface,@i-1/ieee80211w*/
int get_WiFiEndPointProfileSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section*)data, "ieee80211w", value);
	return 0;
}

int set_WiFiEndPointProfileSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", value);
			break;
	}
	return 0;
}

int get_WiFiEndPointStats_LastDataDownlinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_WiFiEndPointStats_LastDataUplinkRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_WiFiEndPointStats_SignalStrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_WiFiEndPointStats_Retransmissions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_WiFiEndPointSecurity_ModesSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps*/
int get_WiFiEndPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", value);
	if(*value[0] == '\0')
		*value= "0";
	return 0;
}

int set_WiFiEndPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *boolS;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if(b)
				dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", "1");
			else
				dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", "0");
			break;
	}
	return 0;
}

int get_WiFiEndPointWPS_ConfigMethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= "PushButton,Label,PIN";
	return 0;
}

int get_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pushbut= NULL, *label= NULL, *pin= NULL, *methodenabled= NULL, *tmp, *str1, *str2, *str3;
	bool a, b, c;
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pushbutton", &pushbut);
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_label", &label);
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", &pin);

	if(pushbut == NULL || pushbut[0]=='\0' || strcmp(pushbut, "1")!=0)
		str1= dmstrdup("");
	else
		str1= dmstrdup("PushButton");

	if(label == NULL || label[0]=='\0' || strcmp(label, "1")!=0)
		str2= dmstrdup("");
	else {
		if(pushbut == NULL || pushbut[0]=='\0' || strcmp(pushbut, "1")!=0)
			str2= dmstrdup("Label");
		else
			str2= dmstrdup(",Label");
	}

	if(pin == NULL || pin[0]=='\0')
		str3= dmstrdup("");
	else {
		if((pushbut != NULL && pushbut[0]!='\0' && strcmp(pushbut, "1")==0) || (label != NULL && label[0]!='\0' && strcmp(label, "1")==0))
			str3= dmstrdup(",PIN");
		else
			str3= dmstrdup("PIN");
	}

	dmasprintf(value,"%s%s%s", str1, str2, str3);
	return 0;
}

int set_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.WiFi.EndPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps*/
int get_WiFiEndPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", &wps_status);
	if(strcmp(wps_status, "0") == 0 || *value[0] == '\0')
		*value= "Disabled";
	else
		*value= "Configured";
	return 0;
}

int get_WiFiEndPointWPS_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.PIN!UCI:wireless/wifi-iface,@i-1/wps_pin*/
int get_WiFiEndPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", value);
	return 0;
}

int set_WiFiEndPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", value);
			break;
	}
	return 0;
}

int get_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss;
	json_object *res, *neighboring_wifi_obj;

	uci_foreach_sections("wireless", "wifi-device", ss) {
		dmubus_call("router.wireless", "scanresults", UBUS_ARGS{{"radio", section_name(ss), String}}, 1, &res);
		neighboring_wifi_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "access_points");
		if(neighboring_wifi_obj) {
			*value = "Complete";
			break;
		}
		else
			*value = "None";
	}
	return 0;
}

int set_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *ss;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				uci_foreach_sections("wireless", "wifi-device", ss) {
					dmubus_call_set("router.wireless", "scan", UBUS_ARGS{{"radio", section_name(ss), String}}, 1);
				}
				dmubus_call_set("tr069", "inform", UBUS_ARGS{{"event", "8 DIAGNOSTICS COMPLETE", String}}, 1);
			}
			return 0;
	}
	return 0;
}

int get_neighboring_wifi_diagnostics_result_number_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss;
	json_object *res, *jobj;
	int entries = 0, result = 0;
	*value = "0";

	uci_foreach_sections("wireless", "wifi-device", ss) {
		dmubus_call("router.wireless", "scanresults", UBUS_ARGS{{"radio", section_name(ss), String}}, 1, &res);
		while (res) {
			jobj = dmjson_select_obj_in_array_idx(res, entries, 1, "access_points");
			if(jobj)
				entries++;
			else
				break;
		}
		result = result + entries;
		entries = 0;
	}
	dmasprintf(value, "%d", result); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

int get_neighboring_wifi_diagnostics_result_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_neighboring_diagnostic_args *cur_wifi_neighboring_diagnostic_args_ptr=(struct wifi_neighboring_diagnostic_args*)data;
	dmasprintf(value, cur_wifi_neighboring_diagnostic_args_ptr->ssid);
	return 0;
}

int get_neighboring_wifi_diagnostics_result_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_neighboring_diagnostic_args *cur_wifi_neighboring_diagnostic_args_ptr=(struct wifi_neighboring_diagnostic_args*)data;
	dmasprintf(value, cur_wifi_neighboring_diagnostic_args_ptr->bssid);
	return 0;
}

int get_neighboring_wifi_diagnostics_result_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_neighboring_diagnostic_args *cur_wifi_neighboring_diagnostic_args_ptr=(struct wifi_neighboring_diagnostic_args*)data;
	dmasprintf(value, "%d", cur_wifi_neighboring_diagnostic_args_ptr->channel);
	return 0;
}

int get_neighboring_wifi_diagnostics_result_signal_strength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_neighboring_diagnostic_args *cur_wifi_neighboring_diagnostic_args_ptr=(struct wifi_neighboring_diagnostic_args*)data;
	dmasprintf(value, "%d", cur_wifi_neighboring_diagnostic_args_ptr->signalstrength);
	return 0;
}

int get_neighboring_wifi_diagnostics_result_operating_frequency_band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_neighboring_diagnostic_args *cur_wifi_neighboring_diagnostic_args_ptr=(struct wifi_neighboring_diagnostic_args*)data;
	dmasprintf(value, cur_wifi_neighboring_diagnostic_args_ptr->operatingfrequencyband);
	return 0;
}

int get_neighboring_wifi_diagnostics_result_noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct wifi_neighboring_diagnostic_args *cur_wifi_neighboring_diagnostic_args_ptr=(struct wifi_neighboring_diagnostic_args*)data;
	dmasprintf(value, "%d", cur_wifi_neighboring_diagnostic_args_ptr->noise);
	return 0;
}

/**************************************************************************
* SET AND GET ALIAS
***************************************************************************/
static int get_radio_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-device", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "radioalias", value);
	return 0;
}

static int set_radio_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-device", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "radioalias", value);
			return 0;
	}
	return 0;
}

int get_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ssidalias", value);
	return 0;
}

int set_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(dmmap_section, "ssidalias", value);
			return 0;
	}
	return 0;
}

int get_access_point_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_acp_args *)data)->wifi_acp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "accesspointalias", value);
	return 0;
}

int set_access_point_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_acp_args *)data)->wifi_acp_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "accesspointalias", value);
			return 0;
	}
	return 0;
}
/*************************************************************
 * GET & SET LOWER LAYER
/*************************************************************/
int get_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct wifi_ssid_args *)data)->linker[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_ssid_args *)data)->linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

int set_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker, *newvalue= NULL;
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (value[strlen(value)-1]!='.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else
				adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "device", linker);
				dmfree(linker);
			} else {
				return FAULT_9005;
			}
			return 0;
	}
	return 0;
}

int get_ap_ssid_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_acp_args *)data)->ifname, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

/*************************************************************
 * ADD DEL OBJ
/*************************************************************/
int add_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value, *v;
	char ssid[16] = {0};
	char *inst;
	struct uci_section *s = NULL;
	struct uci_section *dmmap_wifi=NULL;

	check_create_dmmap_package("dmmap_wireless");
	inst = get_last_instance_bbfdm("dmmap_wireless", "wifi-iface", "ssidinstance");
	sprintf(ssid, "Iopsys_%d", inst ? (atoi(inst)+1) : 1);
	dmuci_add_section("wireless", "wifi-iface", &s, &value);
	dmuci_set_value_by_section(s, "device", "wl0");
	dmuci_set_value_by_section(s, "encryption", "none");
	dmuci_set_value_by_section(s, "macfilter", "0");
	dmuci_set_value_by_section(s, "mode", "ap");
	dmuci_set_value_by_section(s, "ssid", ssid);

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi, &v);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_wifi, inst, "ssidinstance");
	return 0;
}

int delete_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	char *lan_name;
	struct uci_section *s = NULL;
	struct uci_section *ss = NULL, *dmmap_section= NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
			if(dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("wireless", "wifi-iface", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL){
				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

int addObjWiFiEndPoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value, *v, *ssid;
	char *instancepara, *instancepara1, *instancepara2;
	struct uci_section *endpoint_sec = NULL, *dmmap_sec= NULL;
	int inst;

	check_create_dmmap_package("dmmap_wireless");
	instancepara1 = get_last_instance_lev2_bbfdm("wireless", "wifi-iface", "dmmap_wireless", "endpointinstance", "mode", "wet")?get_last_instance_lev2_bbfdm("wireless", "wifi-iface", "dmmap_wireless", "endpointinstance", "mode", "wet"):"0";
	instancepara2 = get_last_instance_lev2_bbfdm("wireless", "wifi-iface", "dmmap_wireless", "endpointinstance", "mode", "sta")?get_last_instance_lev2_bbfdm("wireless", "wifi-iface", "dmmap_wireless", "endpointinstance", "mode", "sta"):"0";
	instancepara=atoi(instancepara1)>atoi(instancepara2)?dmstrdup(instancepara1):dmstrdup(instancepara2);
	dmuci_add_section("wireless", "wifi-iface", &endpoint_sec, &value);
	dmuci_set_value_by_section(endpoint_sec, "device", "wl1");
	dmuci_set_value_by_section(endpoint_sec, "mode", "wet");
	dmuci_set_value_by_section(endpoint_sec, "network", "lan");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_sec, &v);
	dmuci_set_value_by_section(dmmap_sec, "section_name", section_name(endpoint_sec));
	*instance = update_instance_bbfdm(dmmap_sec, instancepara, "endpointinstance");
	return 0;
}

int delObjWiFiEndPoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL;
	struct uci_section *ss = NULL;
	struct uci_section *dmmap_section;
	char *mode;
	int found = 0;

	switch (del_action) {
	case DEL_INST:
		get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
		if(dmmap_section != NULL)
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "endpointinstance", "");
		dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "mode", "");
		break;
	case DEL_ALL:
		uci_foreach_sections("wireless", "wifi-iface", s) {
			dmuci_get_value_by_section_string(s, "mode", &mode);
			if(strcmp(mode, "sta")!=0 && strcmp(mode, "wet")!=0)
				continue;
			dmuci_set_value_by_section(s, "mode", "");
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(s), &dmmap_section);
			if(dmmap_section != NULL)
				dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "endpointinstance", "");
		}
	}
	return 0;
}
/*************************************************************
 * ENTRY METHOD
/*************************************************************/
/*#Device.WiFi.Radio.{i}.!UCI:wireless/wifi-device/dmmap_wireless*/
int browseWifiRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *wnum_last = NULL;
	char buf[12];
	struct uci_section *s = NULL;
	struct wifi_radio_args curr_wifi_radio_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-device", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		init_wifi_radio(&curr_wifi_radio_args, p->config_section);
		wnum =  handle_update_instance(1, dmctx, &wnum_last, update_instance_alias, 3, p->dmmap_section, "radioinstance", "radioalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_radio_args, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.SSID.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
int browseWifiSsidInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *ssid_last = NULL, *ifname, *acpt_last = NULL, *linker;
	struct uci_section *ss = NULL;
	json_object *res;
	struct wifi_ssid_args curr_wifi_ssid_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		dmuci_get_value_by_section_string(p->config_section, "device", &linker);
		init_wifi_ssid(&curr_wifi_ssid_args, p->config_section, ifname, linker);
		wnum =  handle_update_instance(1, dmctx, &ssid_last, update_instance_alias, 3, p->dmmap_section, "ssidinstance", "ssidalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_ssid_args, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
int browseWifiAccessPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *ssid_last = NULL, *ifname, *acpt_last = NULL, *mode= NULL;
	struct uci_section *ss = NULL;
	json_object *res;
	struct wifi_acp_args curr_wifi_acp_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if ((strlen(mode)>0 || mode[0] != '\0') &&strcmp(mode, "ap") != 0)
			continue;
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		init_wifi_acp(&curr_wifi_acp_args, p->config_section, ifname);
		wnum =  handle_update_instance(1, dmctx, &acpt_last, update_instance_alias, 3, p->dmmap_section, "accesspointinstance", "accesspointalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_acp_args, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
int browseWiFiEndPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *ssid_last = NULL, *ifname, *acpt_last = NULL, *mode= NULL;
	struct uci_section *ss = NULL;
	json_object *res;
	struct wifi_enp_args curr_wifi_enp_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if(strcmp(mode, "wet")!=0 && strcmp(mode, "sta")!=0)
			continue;
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		init_wifi_enp(&curr_wifi_enp_args, p->config_section, ifname);
		wnum =  handle_update_instance(1, dmctx, &acpt_last, update_instance_alias, 3, p->dmmap_section, "endpointinstance", "endpointalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_enp_args, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int browse_wifi_associated_device(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res, *associated_client_obj;
	struct uci_section *ss = NULL;
	char *value, *ap_ifname, *idx, *idx_last = NULL;
	int id = 0, entries = 0;
	char *macaddr= NULL, *active= NULL, *lastdatadownloadlinkrate= NULL, *lastdatauplinkrate= NULL, *signalstrength= NULL, *noise= NULL, *retrans= NULL, *assoctimestr= NULL;
	struct wifi_associative_device_args cur_wifi_associative_device_args = {0};
	struct uci_section *dmmap_section;

	uci_foreach_sections("wireless", "wifi-iface", ss) {
		get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "accesspointinstance", &value);
		if(!strcmp(value, prev_instance)){
			dmuci_get_value_by_section_string(ss, "ifname", &ap_ifname);
			break;
		}
	}

	dmubus_call("wifix", "stations", UBUS_ARGS{{"vif", ap_ifname, String}}, 1, &res);
	while (res) {
		associated_client_obj = dmjson_select_obj_in_array_idx(res, entries, 1, "stations");
		if(associated_client_obj) {
			cur_wifi_associative_device_args.wdev = ap_ifname;
			macaddr = dmjson_get_value(associated_client_obj, 1, "macaddr");
			if(macaddr!=NULL && strlen(macaddr)>0)
				dmasprintf(&(cur_wifi_associative_device_args.macaddress),dmjson_get_value(associated_client_obj, 1, "macaddr"));
			cur_wifi_associative_device_args.active = 1;
			lastdatadownloadlinkrate = dmjson_get_value(associated_client_obj, 2, "stats", "rate_of_last_rx_pkt");
			if(lastdatadownloadlinkrate!=NULL && strlen(lastdatadownloadlinkrate)>0)
				cur_wifi_associative_device_args.lastdatadownloadlinkrate = atoi(lastdatadownloadlinkrate);
			else
				cur_wifi_associative_device_args.lastdatadownloadlinkrate = 0;
			lastdatauplinkrate = dmjson_get_value(associated_client_obj, 2, "stats", "rate_of_last_tx_pkt");
			if(lastdatauplinkrate!=NULL && strlen(lastdatauplinkrate)>0)
				cur_wifi_associative_device_args.lastdatauplinkrate = atoi(lastdatauplinkrate);
			else
				cur_wifi_associative_device_args.lastdatauplinkrate = 0;
			signalstrength=dmjson_get_value(associated_client_obj, 1, "rssi");
			if(signalstrength!=NULL && strlen(signalstrength)>0)
				cur_wifi_associative_device_args.signalstrength = atoi(signalstrength);
			else
				cur_wifi_associative_device_args.signalstrength = 0;
			noise=dmjson_get_value(associated_client_obj, 1, "snr");
			if(noise!=NULL && strlen(noise)>0)
				cur_wifi_associative_device_args.noise = atoi(noise);
			else
				cur_wifi_associative_device_args.noise = 0;
			retrans= dmjson_get_value(associated_client_obj, 2, "stats", "tx_pkts_retries");
			cur_wifi_associative_device_args.retransmissions= atoi(retrans);

			assoctimestr=dmjson_get_value(associated_client_obj, 1, "in_network");
			if(assoctimestr!=NULL && strlen(assoctimestr)>0)
				cur_wifi_associative_device_args.assoctime = atoi(assoctimestr);
			else
				cur_wifi_associative_device_args.assoctime = 0;

			entries++;
			idx = handle_update_instance(3, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&cur_wifi_associative_device_args, idx) == DM_STOP)
				break;
		}
		else
			break;
	}
	return 0;
}

int browseWifiNeighboringWiFiDiagnosticResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct wifi_neighboring_diagnostic_args cur_wifi_neighboring_diagnostic_args = {0};
	json_object *res, *neighboring_wifi_obj;
	struct uci_section *ss;
	char *bssid, *ssid, *signalstrength, *channel, *frequency, *noise, *idx, *idx_last = NULL;
	int entries = 0, id = 0;

	uci_foreach_sections("wireless", "wifi-device", ss) {
		dmubus_call("router.wireless", "scanresults", UBUS_ARGS{{"radio", section_name(ss), String}}, 1, &res);
		while (res) {
			neighboring_wifi_obj = dmjson_select_obj_in_array_idx(res, entries, 1, "access_points");
			if(neighboring_wifi_obj) {
				bssid=dmjson_get_value(neighboring_wifi_obj, 1, "bssid");
				if(bssid!=NULL && strlen(bssid)>0)
					dmasprintf(&(cur_wifi_neighboring_diagnostic_args.bssid),dmjson_get_value(neighboring_wifi_obj, 1, "bssid"));
				ssid=dmjson_get_value(neighboring_wifi_obj, 1, "ssid");
				if(ssid!=NULL && strlen(ssid)>0)
					dmasprintf(&(cur_wifi_neighboring_diagnostic_args.ssid),dmjson_get_value(neighboring_wifi_obj, 1, "ssid"));
				channel=dmjson_get_value(neighboring_wifi_obj, 1, "channel");
				if(channel!=NULL && strlen(channel)>0)
					cur_wifi_neighboring_diagnostic_args.channel= atoi(channel);
				else
					cur_wifi_neighboring_diagnostic_args.channel = 0;
				signalstrength=dmjson_get_value(neighboring_wifi_obj, 1, "rssi");
				if(signalstrength!=NULL && strlen(signalstrength)>0)
					cur_wifi_neighboring_diagnostic_args.signalstrength= atoi(signalstrength);
				else
					cur_wifi_neighboring_diagnostic_args.signalstrength = 0;
				frequency=dmjson_get_value(neighboring_wifi_obj, 1, "frequency");
				if(frequency!=NULL && strlen(frequency)>0)
					dmasprintf(&(cur_wifi_neighboring_diagnostic_args.operatingfrequencyband),dmjson_get_value(neighboring_wifi_obj, 1, "frequency"));
				noise=dmjson_get_value(neighboring_wifi_obj, 1, "snr");
				if(noise!=NULL && strlen(noise)>0)
					cur_wifi_neighboring_diagnostic_args.noise= atoi(noise);
				else
					cur_wifi_neighboring_diagnostic_args.noise = 0;
				entries++;
				idx = handle_update_instance(3, dmctx, &idx_last, update_instance_without_section, 1, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&cur_wifi_neighboring_diagnostic_args, idx) == DM_STOP)
					break;
			}
			else
				break;
		}
		entries = 0;
	}
	return 0;
}

int browseWiFiEndPointProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s= NULL;
	char *v, *instance, *instnbr = NULL, *ep_instance;
	struct wifi_enp_args *ep_args = (struct wifi_enp_args *)prev_data;
	struct uci_section *dmmap_section= NULL;

	check_create_dmmap_package("dmmap_wireless");

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ep_args->wifi_enp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &ep_instance);
	s=is_dmmap_section_exist_eq("dmmap_wireless", "ep_profile", "ep_key", ep_instance);
	if(!s)
		dmuci_add_section_bbfdm("dmmap_wireless", "ep_profile", &s, &v);
	DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "ep_key", ep_instance);
	instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias, 3, s, "ep_profile_instance", "ep_profile_alias");

	DM_LINK_INST_OBJ(dmctx, parent_node, ep_args->wifi_enp_sec, "1");
	return 0;
}
