/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "wepkey.h"
#include "wifi.h"
#include "os.h"


/**************************************************************************
* LINKER
***************************************************************************/
static int get_linker_Wifi_Radio(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct wifi_radio_args *)data)->wifi_radio_sec)
		*linker = section_name(((struct wifi_radio_args *)data)->wifi_radio_sec);
	else
		*linker = "";
	return 0;
}

static int get_linker_Wifi_Ssid(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct wifi_ssid_args *)data)->ifname)
		*linker = ((struct wifi_ssid_args *)data)->ifname;
	else
		*linker = "";
	return 0;
}

static int get_linker_associated_device(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data)
		*linker = dmjson_get_value((json_object *)data, 1, "macaddr");
	else
		*linker = "";
	return 0;
}
/**************************************************************************
* INIT
***************************************************************************/
static inline int init_wifi_radio(struct wifi_radio_args *args, struct uci_section *s)
{
	args->wifi_radio_sec = s;
	return 0;
}

static inline int init_wifi_ssid(struct wifi_ssid_args *args, struct uci_section *s, char *wiface, char *linker)
{
	args->wifi_ssid_sec = s;
	args->ifname = wiface;
	args->linker = linker;
	return 0;
}

static inline int init_wifi_acp(struct wifi_acp_args *args, struct uci_section *s, char *wiface)
{
	args->wifi_acp_sec = s;
	args->ifname = wiface;
	return 0;
}

static inline int init_wifi_enp(struct wifi_enp_args *args, struct uci_section *s, char *wiface)
{
	args->wifi_enp_sec = s;
	args->ifname = wiface;
	return 0;
}
/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.WiFi.RadioNumberOfEntries!UCI:wireless/wifi-device/*/
static int get_WiFi_RadioNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre = 0;

	uci_foreach_sections("wireless", "wifi-device", s) {
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.SSIDNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_SSIDNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre = 0;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.AccessPointNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_AccessPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre = 0;
	char *mode = NULL;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		dmuci_get_value_by_section_string(s, "mode", &mode);
		if ((strlen(mode) > 0 || mode[0] != '\0') && strcmp(mode, "ap") != 0)
			continue;
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.EndPointNumberOfEntries!UCI:wireless/wifi-iface/*/
static int get_WiFi_EndPointNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre = 0;
	char *mode = NULL;

	uci_foreach_sections("wireless", "wifi-iface", s) {
		dmuci_get_value_by_section_string(s, "mode", &mode);
		if (strcmp(mode, "wet") == 0 || strcmp(mode, "sta") == 0)
			nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

/*#Device.WiFi.SSID.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
/*#Device.WiFi.AccessPoint.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_wifi_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_wifi_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.Status!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_wifi_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "disabled", value);
	*value = ((*value)[0] == '1') ? "Down" : "Up";
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
			if (dm_validate_string(value, -1, 32, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "ssid", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.MACAddress!UBUS:network.device/status/name,@Name/macaddr*/
static int get_WiFiSSID_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	dmubus_call("network.device", "status", UBUS_ARGS{{"name", ((struct wifi_ssid_args *)data)->ifname, String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "macaddr");
	return 0;
}

/*#Device.WiFi.Radio.{i}.Enable!UCI:wireless/wifi-device,@i-1/disabled*/
static int get_radio_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_radio_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.Status!UCI:wireless/wifi-device,@i-1/disabled*/
static int get_radio_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "disabled", value);
	*value = ((*value)[0] == '1') ? "Down" : "Up";
	return 0;
}

static int get_WiFiRadio_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_WiFiRadio_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_WiFiRadio_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	return 0;
}

static int set_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *freq;

	switch (action) {
			case VALUECHECK:
				if (dm_validate_string_list(value, -1, -1, -1, -1, -1, SupportedStandards, 6, NULL, 0))
					return FAULT_9007;
				return 0;
			case VALUESET:
				freq = os__get_radio_frequency_nocache(data);
				if (strcmp(freq, "5Ghz") == 0) {
					 if (strcmp(value, "n") == 0)
						value = "11n"; 
					 else if (strcmp(value, "ac") == 0)
						value = "11ac";
				} else {
					if (strcmp(value, "b") == 0)
						value = "11b";
					else if (strcmp(value, "b,g") == 0 || strcmp(value, "g,b") == 0) //TODO: Not supported in TR181 (to check)
						value = "11bg";
					else if (strcmp(value, "g") == 0)
						value = "11g";
					 else if (strcmp(value, "n") == 0)
						value = "11n";
				}
				dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "hwmode", value);
				return 0;
		}
		return 0;
}

static int get_WiFiRadio_AutoChannelSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.Radio.{i}.AutoChannelRefreshPeriod!UCI:wireless/wifi-device,@i-1/scantimer*/
static int get_WiFiRadio_AutoChannelRefreshPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "scantimer", value);
	return 0;
}

static int set_WiFiRadio_AutoChannelRefreshPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "scantimer", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.MaxSupportedAssociations!UCI:wireless/wifi-device,@i-1/maxassoc*/
static int get_WiFiRadio_MaxSupportedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "maxassoc", value);
	return 0;
}

/*#Device.WiFi.Radio.{i}.FragmentationThreshold!UCI:wireless/wifi-device,@i-1/frag*/
static int get_WiFiRadio_FragmentationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "frag", value);
	return 0;
}

static int set_WiFiRadio_FragmentationThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "frag", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.RTSThreshold!UCI:wireless/wifi-device,@i-1/rts*/
static int get_WiFiRadio_RTSThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "rts", value);
	return 0;
}

static int set_WiFiRadio_RTSThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "rts", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.BeaconPeriod!UCI:wireless/wifi-device,@i-1/beacon_int*/
static int get_WiFiRadio_BeaconPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "beacon_int", value);
	return 0;
}

static int set_WiFiRadio_BeaconPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "beacon_int", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.DTIMPeriod!UCI:wireless/wifi-device,@i-1/dtim_period*/
static int get_WiFiRadio_DTIMPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "dtim_period", value);
	return 0;
}

static int set_WiFiRadio_DTIMPeriod(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "dtim_period", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingChannelBandwidth!UCI:wireless/wifi-device,@i-1/htmode*/
static int get_WiFiRadio_OperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "htmode", value);
	if(*value[0] == '\0') {
		*value = "";
		return 0;
	}
	if (strncmp(*value, "NOHT", 4) == 0)
		*value = "20MHz";
	else if (strncmp(*value, "HT20", 4) == 0)
		*value = "20MHz";
	else if (strncmp(*value, "HT40", 4) == 0)
		*value = "40MHz";
	else if (strncmp(*value, "VHT20", 5) == 0)
		*value = "20MHz";
	else if (strncmp(*value, "VHT40", 5) == 0)
		*value = "40MHz";
	else if (strncmp(*value, "VHT80", 5) == 0)
		*value = "80MHz";
	else if (strncmp(*value, "VHT160", 6) == 0)
		*value = "160MHz";

	return 0;
}

static int set_WiFiRadio_OperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[6];
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SupportedOperatingChannelBandwidth, 6, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			sscanf(value,"%[^M]", buf);
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "bandwidth", buf);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.PreambleType!UCI:wireless/wifi-device,@i-1/short_preamble*/
static int get_WiFiRadio_PreambleType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "short_preamble", value);
	*value = ((*value)[0] == '0') ? "short" : "long";
	return 0;
}

static int set_WiFiRadio_PreambleType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, PreambleType, 3, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "short_preamble", (strcmp(value, "short") == 0) ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiRadio_IEEE80211hSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.Radio.{i}.IEEE80211hEnabled!UCI:wireless/wifi-device,@i-1/doth*/
static int get_WiFiRadio_IEEE80211hEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "doth", value);
	return 0;
}

static int set_WiFiRadio_IEEE80211hEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "doth", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.TransmitPower!UCI:wireless/wifi-device,@i-1/txpower*/
static int get_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "txpower", value);
	return 0;
}

static int set_WiFiRadio_TransmitPower(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","100"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "txpower", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.RegulatoryDomain!UCI:wireless/wifi-device,@i-1/country*/
static int get_WiFiRadio_RegulatoryDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *country, **arr;
	size_t length;

	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "country", &country);
	arr = strsplit(country, "/", &length);
	if (arr && arr[0])
		dmasprintf(value, "%s ", arr[0]);
	return 0;
}

static int set_WiFiRadio_RegulatoryDomain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *country, **arr;
	size_t length;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, 3, 3, NULL, 0, RegulatoryDomain, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "country", &country);
			if (strlen(country) > 0) {
				arr = strsplit(country, "/", &length);
				dmasprintf(&country, "%s/%s", value, arr[1]);
			} else
				dmasprintf(&country, "%s/1", value);
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "country", country);
			break;
	}
	return 0;
}

static int set_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","255"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.AutoChannelEnable!UCI:wireless/wifi-device,@i-1/channel*/
static int get_radio_auto_channel_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
	if (strcmp(*value, "auto") == 0 || (*value)[0] == '\0')
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_radio_auto_channel_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				value = "auto";
			else
				value = os__get_radio_channel_nocache(data);

			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
			return 0;
	}
	return 0;
}

/**************************************************************************
* SET & GET VALUE
***************************************************************************/
/*#Device.WiFi.SSID.{i}.SSIDAdvertisementEnabled!UCI:wireless/wifi-iface,@i-1/hidden*/
static int get_wlan_ssid_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "hidden", value);
	*value = ((*value)[0] == '1') ? "0" : "1";
	return 0;
}

static int set_wlan_ssid_advertisement_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "hidden", b ? "0" : "1");
			return 0;

	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WMMEnable!UCI:wireless/wifi-device,@i-1/wmm*/
static int get_wmm_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", value);
	dmuci_get_option_value_string("wireless", *value, "wmm", value);
	return 0;
}

static int set_wmm_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *device;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", &device);
			dmuci_set_value("wireless", device, "wmm", b ? "1" : "0");
			dmuci_set_value("wireless", device, "wmm_noack", b ? "1" : "");
			dmuci_set_value("wireless", device, "wmm_apsd", b ? "1" : "");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MaxAssociatedDevices!UCI:wireless/wifi-iface,@i-1/maxassoc*/
static int get_access_point_maxassoc(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "device", value);
	dmuci_get_option_value_string("wireless", *value, "maxassoc", value);
	return 0;
}

static int set_access_point_maxassoc(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *device;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", &device);
			dmuci_set_value("wireless", device, "maxassoc", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MACAddressControlEnabled!UCI:wireless/wifi-iface,@i-1/macfilter*/
static int get_access_point_control_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *macfilter;

	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "macfilter", &macfilter);
	if (macfilter[0] == 0 || strcmp(macfilter, "deny") == 0 || strcmp(macfilter, "disable") == 0)
		*value = "false";
	else
		*value = "true";
	return 0;
}

static int get_WiFiAccessPoint_WMMCapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.MaxAllowedAssociations!UCI:wireless/wifi-iface,@i-1/maxassoc*/
static int get_WiFiAccessPoint_MaxAllowedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", value);
	dmuci_get_option_value_string("wireless", *value, "maxassoc", value);
	return 0;
}

static int set_WiFiAccessPoint_MaxAllowedAssociations(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *device;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "device", &device);
			dmuci_set_value("wireless", device, "maxassoc", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.IsolationEnable!UCI:wireless/wifi-iface,@i-1/isolate*/
static int get_WiFiAccessPoint_IsolationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "isolate", value);
	if(!*value || *value[0] == 0)
		*value = "0";
	return 0;
}

static int set_WiFiAccessPoint_IsolationEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "isolate", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AllowedMACAddress!UCI:wireless/wifi-iface,@i-1/maclist*/
static int get_WiFiAccessPoint_AllowedMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val;
	dmuci_get_value_by_section_list(((struct wifi_acp_args *)data)->wifi_acp_sec, "maclist", &val);
	if (val)
		*value = dmuci_list_to_string(val, " ");
	return 0;
}

static int set_WiFiAccessPoint_AllowedMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	size_t length;
	int i;
	char **arr;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			arr = strsplit(value, " ", &length);
			for (i = 0; i < length; i++)
				dmuci_add_list_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "maclist", arr[i]);
			break;
	}
	return 0;
}

static int get_WiFiAccessPoint_UAPSDCapability(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_access_point_control_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "macfilter", b ? "allow" : "disable");
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.UAPSDEnable!UCI:wireless/wifi-iface,@i-1/wmm_apsd*/
static int get_WiFiAccessPoint_UAPSDEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wmm_apsd", value);
	if (!*value || *value[0] == 0)
		*value = "0";
	return 0;
}

static int set_WiFiAccessPoint_UAPSDEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wmm_apsd", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_access_point_security_supported_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise";
	return 0;
}

static void get_value_security_mode(char **value, char *encryption)
{
	if (strcmp(encryption, "none") == 0)
		*value = "None";
	else if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0)
		*value = "WEP-64";
	else if (strcmp(encryption, "psk") == 0)
		*value = "WPA-Personal";
	else if (strcmp(encryption, "wpa") == 0)
		*value = "WPA-Enterprise";
	else if (strcmp(encryption, "psk2") == 0)
		*value = "WPA2-Personal";
	else if (strcmp(encryption, "wpa2") == 0)
		*value = "WPA2-Enterprise";
	else if (strcmp(encryption, "mixed-psk") == 0)
		*value = "WPA-WPA2-Personal";
	else if (strcmp(encryption, "wpa-mixed") == 0 || strcmp(encryption, "mixed-wpa") == 0)
		*value = "WPA-WPA2-Enterprise";
	else
		*value = "unknown";
}

static int reset_wlan(struct uci_section *s)
{
	dmuci_delete_by_section(s, "wpa_group_rekey", NULL);
	dmuci_delete_by_section(s, "wps", NULL);
	dmuci_delete_by_section(s, "key", NULL);
	dmuci_delete_by_section(s, "key1", NULL);
	dmuci_delete_by_section(s, "key2", NULL);
	dmuci_delete_by_section(s, "key3", NULL);
	dmuci_delete_by_section(s, "key4", NULL);
	dmuci_delete_by_section(s, "auth_server", NULL);
	dmuci_delete_by_section(s, "auth_port", NULL);
	dmuci_delete_by_section(s, "auth_secret", NULL);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.ModeEnabled!UCI:wireless/wifi-iface,@i-1/encryption&UCI:wireless/wifi-iface,@i-1/encryption*/
static int get_access_point_security_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *encryption;

	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
	if (*encryption == '\0')
		*value = "None";
	else
		get_value_security_mode(value, encryption);
	return 0;
}

static int set_access_point_security_modes(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *option, *wpa_key;
	char *encryption, *mode;
	char strk64[4][11];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			get_value_security_mode(&mode, encryption);
			if (strcmp(value, mode) != 0) {
				if (strcmp(value, "None") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "none");
				}
				else if (strcmp(value, "WEP-64") == 0 || strcmp(value, "WEP-128") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "wep-open");
					wepkey64("iopsys", strk64);
					int i;
					for (i = 0; i < 4; i++) {
						dmasprintf(&option, "key%d", i + 1);
						dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, option, strk64[i]);
						dmfree(option);
					}
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", "1");
				}
				else if (strcmp(value, "WPA-Personal") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					wpa_key = os__get_default_wpa_key();
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "psk");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", wpa_key);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wpa_group_rekey", "3600");
				}
				else if (strcmp(value, "WPA-Enterprise") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "wpa");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_server", "");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_port", "1812");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_secret", "");
				}
				else if (strcmp(value, "WPA2-Personal") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					wpa_key = os__get_default_wpa_key();
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "psk2");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", wpa_key);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wpa_group_rekey", "3600");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", "1");
				}
				else if (strcmp(value, "WPA2-Enterprise") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "wpa2");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_server", "");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_port", "1812");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_secret", "");
				}
				else if (strcmp(value, "WPA-WPA2-Personal") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					wpa_key = os__get_default_wpa_key();
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "mixed-psk");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", wpa_key);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wpa_group_rekey", "3600");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", "1");
				}
				else if (strcmp(value, "WPA-WPA2-Enterprise") == 0) {
					reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", "wpa-mixed");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_server", "");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_port", "1812");
					dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_secret", "");
				}
			}
			return 0;
	}
	return 0;
}

static int set_access_point_security_wepkey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"5","5"},{"13","13"}}, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0 ) {
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", value);
			}
			return 0;
	}
	return 0;
}

static int set_access_point_security_shared_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"32"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 )
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "key", value);
			return 0;
	}
	return 0;
}

static int set_access_point_security_passphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, 8, 63, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "psk") == 0 || strcmp(encryption, "psk2") == 0 || strcmp(encryption, "mixed-psk") == 0 )
				set_access_point_security_shared_key(refparam, ctx, data, instance, value, action);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RekeyingInterval!UCI:wireless/wifi-iface,@i-1/wpa_group_rekey*/
static int get_access_point_security_rekey_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wpa_group_rekey", value);
	if (!*value || *value[0] == 0)
		*value = "0";
	return 0;
}

static int set_access_point_security_rekey_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wep-open") != 0 && strcmp(encryption, "wep-shared") != 0 && strcmp(encryption, "none") != 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wpa_group_rekey", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RadiusServerIPAddr!UCI:wireless/wifi-iface,@i-1/auth_server*/
static int get_access_point_security_radius_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_server", value);
	return 0;
}

static int set_access_point_security_radius_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_server", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.RadiusServerPort!UCI:wireless/wifi-iface,@i-1/auth_port*/
static int get_access_point_security_radius_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_port", value);
	return 0;
}

static int set_access_point_security_radius_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_port", value);
			return 0;
	}
	return 0;
}

static int set_access_point_security_radius_secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "encryption", &encryption);
			if (strcmp(encryption, "wpa") == 0 || strcmp(encryption, "wpa2") == 0 || strcmp(encryption, "mixed-wpa") == 0 || strcmp(encryption, "wpa-mixed") == 0)
				dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "auth_secret", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Security.MFPConfig!UCI:wireless/wifi-iface,@i-1/ieee80211w*/
static int get_WiFiAccessPointSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "ieee80211w", value);

	if(!*value || *value[0] == 0 || *value[0] == '0')
		*value = "Disabled";
	else if (*value[0] == '1')
		*value = "Optional";
	else if (*value[0] == '2')
		*value = "Required";
	return 0;
}

static int set_WiFiAccessPointSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char buf[2];

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, MFPConfig, 3, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcmp(value, "Disabled") == 0)
				buf[0] = '0';
			else if (strcmp(value, "Optional") == 0)
				buf[0] = '1';
			else if (strcmp(value, "Required") == 0)
				buf[0] = '2';
			buf[1] = 0;
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "ieee80211w", buf);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", value);
	if(*value[0] == '\0')
		*value= "0";
	return 0;
}

static int set_WiFiAccessPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiAccessPointWPS_ConfigMethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "PushButton,Label,PIN";
	return 0;
}

static int get_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pushbut = NULL, *label = NULL, *pin = NULL, *str1, *str2, *str3;

	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pushbutton", &pushbut);
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_label", &label);
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", &pin);

	if (pushbut == NULL || pushbut[0] == '\0' || strcmp(pushbut, "1") != 0)
		str1 = dmstrdup("");
	else
		str1 = dmstrdup("PushButton");

	if (label == NULL || label[0] == '\0' || strcmp(label, "1") != 0)
		str2 = dmstrdup("");
	else {
		if(pushbut == NULL || pushbut[0] == '\0' || strcmp(pushbut, "1") != 0)
			str2 = dmstrdup("Label");
		else
			str2 = dmstrdup(",Label");
	}

	if( pin == NULL || pin[0] == '\0')
		str3 = dmstrdup("");
	else {
		if((pushbut != NULL && pushbut[0] != '\0' && strcmp(pushbut, "1") == 0) || (label != NULL && label[0] != '\0' && strcmp(label, "1") == 0))
			str3 = dmstrdup(",PIN");
		else
			str3 = dmstrdup("PIN");
	}

	dmasprintf(value,"%s%s%s", str1, str2, str3);
	return 0;
}

static int set_WiFiAccessPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiAccessPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps", &wps_status);
	if (!wps_status || wps_status[0] == 0 || strcmp(wps_status, "0") == 0)
		*value = "Disabled";
	else
		*value = "Configured";
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.WPS.PIN!UCI:wireless/wifi-iface,@i-1/wps_pin*/
static int get_WiFiAccessPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps_pin", value);
	return 0;
}

static int set_WiFiAccessPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 8, NULL, 0, PIN, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "wps_pin", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Accounting.ServerIPAddr!UCI:wireless/wifi-iface,@i-1/acct_server*/
static int get_WiFiAccessPointAccounting_ServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_server", value);
	return 0;
}

static int set_WiFiAccessPointAccounting_ServerIPAddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_server", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Accounting.ServerPort!UCI:wireless/wifi-iface,@i-1/acct_port*/
static int get_WiFiAccessPointAccounting_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_port", value);
	return 0;
}

static int set_WiFiAccessPointAccounting_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_port", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Accounting.Secret!UCI:wireless/wifi-iface,@i-1/acct_secret*/
static int get_WiFiAccessPointAccounting_Secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_secret", value);
	return 0;
}

static int set_WiFiAccessPointAccounting_Secret(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_acp_args *)data)->wifi_acp_sec, "acct_secret", value);
			break;
	}
	return 0;
}

static int set_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SupportedFrequencyBands, 2, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_radio_args *)data)->wifi_radio_sec, "hwmode", (!strcmp(value, "5GHz") ? "11a" :"11g"));
			break;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataDownlinkRate!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rate_of_last_rx_pkt*/
static int get_access_point_associative_device_lastdatadownlinkrate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rate_of_last_rx_pkt");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.LastDataUplinkRate!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rate_of_last_tx_pkt*/
static int get_access_point_associative_device_lastdatauplinkrate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rate_of_last_tx_pkt");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.SignalStrength!UBUS:wifi.ap.@Name/stations//stations[i-1].rssi*/
static int get_access_point_associative_device_signalstrength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rssi");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Retransmissions!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_pkts_retries*/
static int get_WiFiAccessPointAssociatedDevice_Retransmissions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_pkts_retries");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.AssociationTime!UBUS:wifi.ap.@Name/stations//stations[i-1].in_network*/
static int get_WiFiAccessPointAssociatedDevice_AssociationTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char local_time[32] = {0};
	time_t t_time;

	*value = "0001-01-01T00:00:00Z";
	char *in_network = dmjson_get_value((json_object *)data, 1, "in_network");
	t_time = time(NULL) - atoi(in_network);
	if (localtime(&t_time) == NULL)
		return -1;

	if (strftime(local_time, sizeof(local_time), "%Y-%m-%dT%H:%M:%SZ", localtime(&t_time)) == 0)
		return -1;

	*value = dmstrdup(local_time);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.MACAddress!UBUS:wifi.ap.@Name/stations//stations[i-1].macaddr*/
static int get_access_point_associative_device_mac(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "macaddr");
	return 0;
}

static int get_access_point_associative_device_active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Noise!UBUS:wifi.ap.@Name/stations//stations[i-1].noise*/
static int get_WiFiAccessPointAssociatedDevice_Noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "noise");
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Enable!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_WiFiEndPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", value);
	if (((*value)[0] == '\0') || ((*value)[0] == '0'))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_WiFiEndPoint_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Status!UCI:wireless/wifi-iface,@i-1/disabled*/
static int get_WiFiEndPoint_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "disabled", value);
	if ((*value)[0] == '\0' || (*value)[0] == '0')
		*value = "Up";
	else
		*value = "Down";
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/endpointalias*/
static int get_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_enp_args *)data)->wifi_enp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_WiFiEndPoint_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_enp_args *)data)->wifi_enp_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "endpointalias", value);
			return 0;
	}
	return 0;
}

static int get_WiFiEndPoint_SSIDReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_enp_args *)data)->ifname, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static int get_WiFiEndPointProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int set_WiFiEndPointProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_WiFiEndPointProfile_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Active";
	return 0;
}

static int get_WiFiEndPointProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL, *dm = NULL;
	char *epinst = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name((struct uci_section*)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &epinst);
	get_dmmap_section_of_config_section_eq("dmmap_wireless", "ep_profile", "ep_key", epinst, &dm);
	dmuci_get_value_by_section_string(dm, "ep_profile_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_WiFiEndPointProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL, *dm = NULL;
	char *epinst = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name((struct uci_section*)data), &dmmap_section);
			dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &epinst);
			get_dmmap_section_of_config_section_eq("dmmap_wireless", "ep_profile", "ep_key", epinst, &dm);
			dmuci_set_value_by_section_bbfdm(dm, "ep_profile_alias", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.SSID!UCI:wireless/wifi-iface,@i-1/ssid*/
static int get_WiFiEndPointProfile_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section*)data, "ssid", value);
	return 0;
}

static int set_WiFiEndPointProfile_SSID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 32, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section*)data, "ssid", value);
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.Profile.{i}.Security.SSID!UCI:wireless/wifi-iface,@i-1/encryption&UCI:wireless/wifi-iface,@i-1/encryption*/
static int get_WiFiEndPointProfileSecurity_ModeEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *encryption;

	dmuci_get_value_by_section_string((struct uci_section *)data, "encryption", &encryption);
	if (*encryption == '\0')
		*value = "None";
	else
		get_value_security_mode(value, encryption);
	return 0;
}

static int set_WiFiEndPointProfileSecurity_ModeEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *option, *wpa_key;
	char *encryption, *mode;
	char strk64[4][11];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			get_value_security_mode(&mode, encryption);

			if (strcmp(value, mode) != 0) {
				if (strcmp(value, "None") == 0) {
					reset_wlan((struct uci_section*)data);
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "none");
				}
				else if (strcmp(value, "WEP-64") == 0 || strcmp(value, "WEP-128") == 0) {
					reset_wlan((struct uci_section*)data);
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "wep-open");
					wepkey64("iopsys", strk64);
					int i;
					for (i = 0; i < 4; i++) {
						dmasprintf(&option, "key%d", i + 1);
						dmuci_set_value_by_section((struct uci_section*)data, option, strk64[i]);
						dmfree(option);
					}
					dmuci_set_value_by_section((struct uci_section*)data, "key", "1");
				}
				else if (strcmp(value, "WPA-Personal") == 0) {
					reset_wlan((struct uci_section*)data);
					wpa_key = os__get_default_wpa_key();
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "psk");
					dmuci_set_value_by_section((struct uci_section*)data, "key", wpa_key);
					dmuci_set_value_by_section((struct uci_section*)data, "wpa_group_rekey", "3600");
				}
				else if (strcmp(value, "WPA-Enterprise") == 0) {
						reset_wlan(((struct wifi_acp_args *)data)->wifi_acp_sec);
						dmuci_set_value_by_section((struct uci_section*)data, "encryption", "wpa");
						dmuci_set_value_by_section((struct uci_section*)data, "auth_server", "");
						dmuci_set_value_by_section((struct uci_section*)data, "auth_port", "1812");
						dmuci_set_value_by_section((struct uci_section*)data, "auth_secret", "");
				}
				else if (strcmp(value, "WPA2-Personal") == 0) {
					reset_wlan((struct uci_section*)data);
					wpa_key = os__get_default_wpa_key();
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "psk2");
					dmuci_set_value_by_section((struct uci_section*)data, "key", wpa_key);
					dmuci_set_value_by_section((struct uci_section*)data, "wpa_group_rekey", "3600");
					dmuci_set_value_by_section((struct uci_section*)data, "wps", "1");
				}
				else if (strcmp(value, "WPA2-Enterprise") == 0) {
					reset_wlan((struct uci_section*)data);
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "wpa2");
					dmuci_set_value_by_section((struct uci_section*)data, "auth_server", "");
					dmuci_set_value_by_section((struct uci_section*)data, "auth_port", "1812");
					dmuci_set_value_by_section((struct uci_section*)data, "auth_secret", "");
				}
				else if (strcmp(value, "WPA-WPA2-Personal") == 0) {
					reset_wlan((struct uci_section*)data);
					wpa_key = os__get_default_wpa_key();
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "mixed-psk");
					dmuci_set_value_by_section((struct uci_section*)data, "key", wpa_key);
					dmuci_set_value_by_section((struct uci_section*)data, "wpa_group_rekey", "3600");
					dmuci_set_value_by_section((struct uci_section*)data, "wps", "1");
				}
				else if (strcmp(value, "WPA-WPA2-Enterprise") == 0) {
					reset_wlan((struct uci_section*)data);
					dmuci_set_value_by_section((struct uci_section*)data, "encryption", "wpa-mixed");
					dmuci_set_value_by_section((struct uci_section*)data, "auth_server", "");
					dmuci_set_value_by_section((struct uci_section*)data, "auth_port", "1812");
					dmuci_set_value_by_section((struct uci_section*)data, "auth_secret", "");
				}
			}
			return 0;
	}
	return 0;
}

static int set_WiFiEndPointProfileSecurity_WEPKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"5","5"},{"13","13"}}, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section*)data, "encryption", &encryption);
			if (strcmp(encryption, "wep-open") == 0 || strcmp(encryption, "wep-shared") == 0 ) {
				dmuci_set_value_by_section((struct uci_section*)data, "key", value);
			}
			return 0;
	}
	return 0;
}

static int set_WiFiEndPointProfileSecurity_PreSharedKey(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"32"}}, 1))
				return FAULT_9007;
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

static int set_WiFiEndPointProfileSecurity_KeyPassphrase(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *encryption;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, 8, 63, NULL, 0, NULL, 0))
				return FAULT_9007;
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
static int get_WiFiEndPointProfileSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section*)data, "ieee80211w", value);
	if(*value[0] == 0 || *value[0] == '0')
		*value = "Disabled";
	else if (strcmp(*value, "1") == 0)
		*value = "Optional";
	else if (strcmp(*value, "2") == 0)
		*value = "Required";
	return 0;
}

static int set_WiFiEndPointProfileSecurity_MFPConfig(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, MFPConfig, 3, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcmp(value, "Disabled") == 0)
				dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", "0");
			else if (strcmp(value, "Optional") == 0)
				dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", "1");
			else if (strcmp(value, "Required") == 0)
				dmuci_set_value_by_section((struct uci_section*)data, "ieee80211w", "2");
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.Enable!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiEndPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", value);
	if(*value[0] == '\0')
		*value = "0";
	return 0;
}

static int set_WiFiEndPointWPS_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", b ? "1" : "0");
			break;
	}
	return 0;
}

static int get_WiFiEndPointWPS_ConfigMethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "PushButton,Label,PIN";
	return 0;
}

static int get_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *pushbut = NULL, *label = NULL, *pin = NULL, *str1, *str2, *str3;

	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pushbutton", &pushbut);
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_label", &label);
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", &pin);

	if (pushbut == NULL || pushbut[0]=='\0' || strcmp(pushbut, "1")!=0)
		str1 = dmstrdup("");
	else
		str1 = dmstrdup("PushButton");

	if (label == NULL || label[0]=='\0' || strcmp(label, "1")!=0)
		str2 = dmstrdup("");
	else {
		if (pushbut == NULL || pushbut[0]=='\0' || strcmp(pushbut, "1")!=0)
			str2 = dmstrdup("Label");
		else
			str2 = dmstrdup(",Label");
	}

	if (pin == NULL || pin[0]=='\0')
		str3 = dmstrdup("");
	else {
		if ((pushbut != NULL && pushbut[0] != '\0' && strcmp(pushbut, "1") == 0) || (label != NULL && label[0] != '\0' && strcmp(label, "1") == 0))
			str3 = dmstrdup(",PIN");
		else
			str3 = dmstrdup("PIN");
	}

	dmasprintf(value,"%s%s%s", str1, str2, str3);
	return 0;
}

static int set_WiFiEndPointWPS_ConfigMethodsEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.Status!UCI:wireless/wifi-iface,@i-1/wps*/
static int get_WiFiEndPointWPS_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *wps_status;

	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps", &wps_status);
	if (strcmp(wps_status, "0") == 0 || wps_status[0] == '\0')
		*value = "Disabled";
	else
		*value = "Configured";
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.WPS.PIN!UCI:wireless/wifi-iface,@i-1/wps_pin*/
static int get_WiFiEndPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", value);
	return 0;
}

static int set_WiFiEndPointWPS_PIN(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"4","4"},{"8","8"}}, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "wps_pin", value);
			break;
	}
	return 0;
}

/**************************************************************************
* SET AND GET ALIAS
***************************************************************************/
/*#Device.WiFi.Radio.{i}.Alias!UCI:dmmap_wireless/wifi-device,@i-1/radioalias*/
static int get_radio_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-device", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "radioalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_radio_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-device", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "radioalias", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.SSID.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/ssidalias*/
static int get_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ssidalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_ssid_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "ssidalias", value);
			return 0;
	}
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.Alias!UCI:dmmap_wireless/wifi-iface,@i-1/accesspointalias*/
static int get_access_point_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_acp_args *)data)->wifi_acp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ap_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_access_point_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_acp_args *)data)->wifi_acp_sec), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "ap_alias", value);
			return 0;
	}
	return 0;
}
/*************************************************************
* GET & SET LOWER LAYER
**************************************************************/
static int get_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (data && ((struct wifi_ssid_args *)data)->linker[0] != '\0') {
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_ssid_args *)data)->linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

static int set_ssid_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker, *newvalue = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (value[strlen(value)-1] != '.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else
				adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmuci_set_value_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "device", linker);
				dmfree(linker);
			} else
				return FAULT_9005;
			return 0;
	}
	return 0;
}

static int get_ap_ssid_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), ((struct wifi_acp_args *)data)->ifname, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

/*************************************************************
* ADD DEL OBJ
**************************************************************/
static int add_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value, *v, *inst, ssid[32] = {0};
	struct uci_section *s = NULL, *dmmap_wifi = NULL;

	check_create_dmmap_package("dmmap_wireless");
	inst = get_last_instance_bbfdm("dmmap_wireless", "wifi-iface", "ssidinstance");
	snprintf(ssid, sizeof(ssid), "iopsys_%d", inst ? (atoi(inst)+1) : 1);
	dmuci_add_section("wireless", "wifi-iface", &s, &value);
	dmuci_set_value_by_section(s, "ssid", ssid);
	dmuci_set_value_by_section(s, "network", "lan");
	dmuci_set_value_by_section(s, "mode", "ap");
	dmuci_set_value_by_section(s, "disabled", "0");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi, &v);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_wifi, inst, "ssidinstance");
	return 0;
}

static int delete_wifi_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("wireless", "wifi-iface", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

static int add_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value, *v, *inst, ssid[32] = {0};
	struct uci_section *s = NULL, *dmmap_wifi = NULL;

	check_create_dmmap_package("dmmap_wireless");
	inst = get_last_instance_bbfdm("dmmap_wireless", "wifi-iface", "ap_instance");
	snprintf(ssid, sizeof(ssid), "iopsys_%d", inst ? (atoi(inst)+1) : 1);
	dmuci_add_section("wireless", "wifi-iface", &s, &value);
	dmuci_set_value_by_section(s, "ssid", ssid);
	dmuci_set_value_by_section(s, "network", "lan");
	dmuci_set_value_by_section(s, "mode", "ap");
	dmuci_set_value_by_section(s, "disabled", "0");

	dmuci_add_section_bbfdm("dmmap_wireless", "wifi-iface", &dmmap_wifi, &v);
	dmuci_set_value_by_section(dmmap_wifi, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_wifi, inst, "ap_instance");
	return 0;
}

static int delete_wifi_accesspoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
			dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct wifi_ssid_args *)data)->wifi_ssid_sec, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("wireless", "wifi-iface", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ss), &dmmap_section);
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

static int addObjWiFiEndPoint(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value, *v, *instancepara, *instancepara1, *instancepara2;
	struct uci_section *endpoint_sec = NULL, *dmmap_sec= NULL;

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

static int delObjWiFiEndPoint(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *dmmap_section = NULL;
	char *mode;

	switch (del_action) {
	case DEL_INST:
		get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(((struct wifi_ssid_args *)data)->wifi_ssid_sec), &dmmap_section);
		if (dmmap_section)
			dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "endpointinstance", "");
		dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "mode", "");
		break;
	case DEL_ALL:
		uci_foreach_sections("wireless", "wifi-iface", s) {
			dmuci_get_value_by_section_string(s, "mode", &mode);
			if (strcmp(mode, "sta") != 0 && strcmp(mode, "wet") != 0)
				continue;
			dmuci_set_value_by_section(s, "mode", "");
			get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(s), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(((struct wifi_enp_args *)data)->wifi_enp_sec, "endpointinstance", "");
		}
	}
	return 0;
}
/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.WiFi.Radio.{i}.!UCI:wireless/wifi-device/dmmap_wireless*/
static int browseWifiRadioInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *wnum_last = NULL;
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
static int browseWifiSsidInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *ssid_last = NULL, *ifname, *linker;
	struct wifi_ssid_args curr_wifi_ssid_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "device", &linker);
#ifdef GENERIC_OPENWRT
		ifname = get_device_from_wifi_iface(linker, section_name(p->config_section));
#else
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
#endif
		init_wifi_ssid(&curr_wifi_ssid_args, p->config_section, ifname, linker);
		wnum =  handle_update_instance(1, dmctx, &ssid_last, update_instance_alias, 3, p->dmmap_section, "ssidinstance", "ssidalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_ssid_args, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWifiAccessPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *ifname, *acpt_last = NULL, *mode = NULL;
	struct wifi_acp_args curr_wifi_acp_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("wireless", "wifi-iface", "dmmap_wireless", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "mode", &mode);
		if ((strlen(mode)>0 || mode[0] != '\0') && strcmp(mode, "ap") != 0)
			continue;
		dmuci_get_value_by_section_string(p->config_section, "ifname", &ifname);
		init_wifi_acp(&curr_wifi_acp_args, p->config_section, ifname);
		wnum =  handle_update_instance(1, dmctx, &acpt_last, update_instance_alias, 3, p->dmmap_section, "ap_instance", "ap_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_wifi_acp_args, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.WiFi.EndPoint.{i}.!UCI:wireless/wifi-iface/dmmap_wireless*/
static int browseWiFiEndPointInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *ifname, *acpt_last = NULL, *mode= NULL;
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

static int browseWiFiEndPointProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s= NULL;
	char *v, *instnbr = NULL, *ep_instance;
	struct wifi_enp_args *ep_args = (struct wifi_enp_args *)prev_data;
	struct uci_section *dmmap_section = NULL;

	check_create_dmmap_package("dmmap_wireless");

	get_dmmap_section_of_config_section("dmmap_wireless", "wifi-iface", section_name(ep_args->wifi_enp_sec), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "endpointinstance", &ep_instance);
	s = is_dmmap_section_exist_eq("dmmap_wireless", "ep_profile", "ep_key", ep_instance);
	if(!s)
		dmuci_add_section_bbfdm("dmmap_wireless", "ep_profile", &s, &v);
	DMUCI_SET_VALUE_BY_SECTION(bbfdm, s, "ep_key", ep_instance);
	handle_update_instance(1, dmctx, &instnbr, update_instance_alias, 3, s, "ep_profile_instance", "ep_profile_alias");

	DM_LINK_INST_OBJ(dmctx, parent_node, ep_args->wifi_enp_sec, "1");
	return 0;
}

int set_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *ss;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				uci_foreach_sections("wireless", "wifi-device", ss)
					os__wifi_start_scan(section_name(ss));

				dmubus_call_set("tr069", "inform", UBUS_ARGS{{"event", "8 DIAGNOSTICS COMPLETE", String}}, 1);
			}
			return 0;
	}
	return 0;
}

/* *** Device.WiFi. *** */
DMOBJ tWiFiObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Radio", &DMREAD, NULL, NULL, NULL, browseWifiRadioInst, NULL, NULL, NULL, tWiFiRadioObj, tWiFiRadioParams, get_linker_Wifi_Radio, BBFDM_BOTH},
{"SSID", &DMWRITE, add_wifi_ssid, delete_wifi_ssid, NULL, browseWifiSsidInst, NULL, NULL, NULL, tWiFiSSIDObj, tWiFiSSIDParams, get_linker_Wifi_Ssid, BBFDM_BOTH},
{"AccessPoint", &DMWRITE, add_wifi_accesspoint, delete_wifi_accesspoint, NULL, browseWifiAccessPointInst, NULL, NULL, NULL, tWiFiAccessPointObj, tWiFiAccessPointParams, NULL, BBFDM_BOTH},
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
{0}
};

/* *** Device.WiFi.Radio.{i}. *** */
DMOBJ tWiFiRadioObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
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
{"MaxBitRate", &DMREAD, DMT_UNINT, os__get_radio_max_bit_rate, NULL, NULL, NULL, BBFDM_BOTH},
{"OperatingFrequencyBand", &DMWRITE, DMT_STRING, os__get_radio_frequency, set_radio_frequency, NULL, NULL, BBFDM_BOTH},
{"SupportedFrequencyBands", &DMREAD, DMT_STRING, os__get_radio_supported_frequency_bands, NULL, NULL, NULL, BBFDM_BOTH},
{"SupportedStandards", &DMREAD, DMT_STRING, os__get_radio_supported_standard, NULL, NULL, NULL, BBFDM_BOTH},
{"OperatingStandards", &DMWRITE, DMT_STRING, os_get_radio_operating_standard, set_radio_operating_standard, NULL, NULL, BBFDM_BOTH},
{"ChannelsInUse", &DMREAD, DMT_STRING, os__get_radio_channel, NULL, NULL, NULL, BBFDM_BOTH},
{"Channel", &DMWRITE, DMT_UNINT, os__get_radio_channel, set_radio_channel, NULL, NULL, BBFDM_BOTH},
{"AutoChannelEnable", &DMWRITE, DMT_BOOL, get_radio_auto_channel_enable, set_radio_auto_channel_enable, NULL, NULL, BBFDM_BOTH},
{"PossibleChannels", &DMREAD, DMT_STRING, os__get_radio_possible_channels, NULL, NULL, NULL, BBFDM_BOTH},
{"AutoChannelSupported", &DMREAD, DMT_BOOL, get_WiFiRadio_AutoChannelSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"AutoChannelRefreshPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_AutoChannelRefreshPeriod, set_WiFiRadio_AutoChannelRefreshPeriod, NULL, NULL, BBFDM_BOTH},
{"MaxSupportedAssociations", &DMREAD, DMT_UNINT, get_WiFiRadio_MaxSupportedAssociations, NULL, NULL, NULL, BBFDM_BOTH},
{"FragmentationThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_FragmentationThreshold, set_WiFiRadio_FragmentationThreshold, NULL, NULL, BBFDM_BOTH},
{"RTSThreshold", &DMWRITE, DMT_UNINT, get_WiFiRadio_RTSThreshold, set_WiFiRadio_RTSThreshold, NULL, NULL, BBFDM_BOTH},
{"BeaconPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_BeaconPeriod, set_WiFiRadio_BeaconPeriod, NULL, NULL, BBFDM_BOTH},
{"DTIMPeriod", &DMWRITE, DMT_UNINT, get_WiFiRadio_DTIMPeriod, set_WiFiRadio_DTIMPeriod, NULL, NULL, BBFDM_BOTH},
{"SupportedOperatingChannelBandwidths", &DMREAD, DMT_STRING, os__get_WiFiRadio_SupportedOperatingChannelBandwidths, NULL, NULL, NULL, BBFDM_BOTH},
{"OperatingChannelBandwidth", &DMWRITE, DMT_STRING, get_WiFiRadio_OperatingChannelBandwidth, set_WiFiRadio_OperatingChannelBandwidth, NULL, NULL, BBFDM_BOTH},
{"CurrentOperatingChannelBandwidth", &DMREAD, DMT_STRING, os__get_WiFiRadio_CurrentOperatingChannelBandwidth, NULL, NULL, NULL, BBFDM_BOTH},
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
{"BytesSent", &DMREAD, DMT_UNLONG, os__get_WiFiRadioStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, os__get_WiFiRadioStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiRadioStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiRadioStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"FCSErrorCount", &DMREAD, DMT_UNINT, os__get_WiFiRadioStats_FCSErrorCount, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic. *** */
DMOBJ tWiFiNeighboringWiFiDiagnosticObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Result", &DMREAD, NULL, NULL, NULL, os__browseWifiNeighboringWiFiDiagnosticResultInst, NULL, NULL, NULL, NULL, tWiFiNeighboringWiFiDiagnosticResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tWiFiNeighboringWiFiDiagnosticParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, os__get_neighboring_wifi_diagnostics_diagnostics_state, set_neighboring_wifi_diagnostics_diagnostics_state, NULL, NULL, BBFDM_CWMP},
{"ResultNumberOfEntries", &DMREAD, DMT_UNINT, os__get_neighboring_wifi_diagnostics_result_number_entries, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}. *** */
DMLEAF tWiFiNeighboringWiFiDiagnosticResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"SSID", &DMREAD, DMT_STRING, os__get_neighboring_wifi_diagnostics_result_ssid, NULL, NULL, NULL, BBFDM_CWMP},
{"BSSID", &DMREAD, DMT_STRING, os__get_neighboring_wifi_diagnostics_result_bssid, NULL, NULL, NULL, BBFDM_CWMP},
{"Channel", &DMREAD, DMT_UNINT, os__get_neighboring_wifi_diagnostics_result_channel, NULL, NULL, NULL, BBFDM_CWMP},
{"SignalStrength", &DMREAD, DMT_INT, os__get_neighboring_wifi_diagnostics_result_signal_strength, NULL, NULL, NULL, BBFDM_CWMP},
{"OperatingFrequencyBand", &DMREAD, DMT_STRING, os__get_neighboring_wifi_diagnostics_result_operating_frequency_band, NULL, NULL, NULL, BBFDM_CWMP},
{"Noise", &DMREAD, DMT_INT, os__get_neighboring_wifi_diagnostics_result_noise, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.WiFi.SSID.{i}. *** */
DMOBJ tWiFiSSIDObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
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
{"BSSID", &DMREAD, DMT_STRING, os__get_wlan_bssid, NULL, NULL, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_WiFiSSID_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.SSID.{i}.Stats. *** */
DMLEAF tWiFiSSIDStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_RetransCount, NULL, NULL, NULL, BBFDM_BOTH},
{"FailedRetransCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_FailedRetransCount, NULL, NULL, NULL, BBFDM_BOTH},
{"RetryCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_RetryCount, NULL, NULL, NULL, BBFDM_BOTH},
{"MultipleRetryCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_MultipleRetryCount, NULL, NULL, NULL, BBFDM_BOTH},
{"ACKFailureCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_ACKFailureCount, NULL, NULL, NULL, BBFDM_BOTH},
{"AggregatedPacketCount", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_AggregatedPacketCount, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNLONG, os__get_WiFiSSIDStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, os__get_WiFiSSIDStats_UnknownProtoPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}. *** */
DMOBJ tWiFiAccessPointObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Security", &DMWRITE, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointSecurityParams, NULL, BBFDM_BOTH},
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, os__browse_wifi_associated_device, NULL, NULL, NULL, tWiFiAccessPointAssociatedDeviceObj, tWiFiAccessPointAssociatedDeviceParams, get_linker_associated_device, BBFDM_BOTH},
{"WPS", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointWPSParams, NULL, BBFDM_BOTH},
{"Accounting", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiAccessPointAccountingParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiAccessPointParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_access_point_alias, set_access_point_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL,  get_wifi_enable, set_wifi_enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, os_get_wifi_access_point_status, NULL, NULL, NULL, BBFDM_BOTH},
{"SSIDReference", &DMREAD, DMT_STRING, get_ap_ssid_ref, NULL, NULL, NULL, BBFDM_BOTH},
{"SSIDAdvertisementEnabled", &DMWRITE, DMT_BOOL, get_wlan_ssid_advertisement_enable, set_wlan_ssid_advertisement_enable, NULL, NULL, BBFDM_BOTH},
{"WMMEnable", &DMWRITE, DMT_BOOL, get_wmm_enabled, set_wmm_enabled, NULL, NULL, BBFDM_BOTH},
{"UAPSDEnable", &DMWRITE, DMT_BOOL, get_WiFiAccessPoint_UAPSDEnable, set_WiFiAccessPoint_UAPSDEnable, NULL, NULL, BBFDM_BOTH},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, os__get_access_point_total_associations, NULL, NULL, NULL, BBFDM_BOTH},
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
{"WEPKey", &DMWRITE, DMT_HEXBIN, get_empty, set_access_point_security_wepkey, NULL, NULL, BBFDM_BOTH},
{"PreSharedKey", &DMWRITE, DMT_HEXBIN, get_empty, set_access_point_security_shared_key, NULL, NULL, BBFDM_BOTH},
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
//{"Version", &DMREAD, DMT_STRING, get_WiFiAccessPointWPS_Version, NULL, NULL, NULL, BBFDM_BOTH},
{"PIN", &DMWRITE, DMT_STRING, get_WiFiAccessPointWPS_PIN, set_WiFiAccessPointWPS_PIN, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}. *** */
DMOBJ tWiFiAccessPointAssociatedDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
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
{"BytesSent", &DMREAD, DMT_UNLONG, os__get_access_point_associative_device_statistics_tx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNLONG, os__get_access_point_associative_device_statistics_rx_bytes, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNLONG, os__get_access_point_associative_device_statistics_tx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNLONG, os__get_access_point_associative_device_statistics_rx_packets, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_tx_errors, NULL, NULL, NULL, BBFDM_BOTH},
{"RetransCount", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_retrans_count, NULL, NULL, NULL, BBFDM_BOTH},
//{"FailedRetransCount", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_failed_retrans_count, NULL, NULL, NULL, BBFDM_BOTH},
//{"RetryCount", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_retry_count, NULL, NULL, NULL, BBFDM_BOTH},
//{"MultipleRetryCount", &DMREAD, DMT_UNINT, os__get_access_point_associative_device_statistics_multiple_retry_count, NULL, NULL, NULL, BBFDM_BOTH},
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

/* *** Device.WiFi.EndPoint.{i}. *** */
DMOBJ tWiFiEndPointObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
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
//{"LastDataDownlinkRate", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_LastDataDownlinkRate, NULL, NULL, NULL, BBFDM_BOTH},
//{"LastDataUplinkRate", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_LastDataUplinkRate, NULL, NULL, NULL, BBFDM_BOTH},
//{"SignalStrength", &DMREAD, DMT_INT, get_WiFiEndPointStats_SignalStrength, NULL, NULL, NULL, BBFDM_BOTH},
//{"Retransmissions", &DMREAD, DMT_UNINT, get_WiFiEndPointStats_Retransmissions, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Security. *** */
DMLEAF tWiFiEndPointSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"ModesSupported", &DMREAD, DMT_STRING, get_WiFiEndPointSecurity_ModesSupported, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.WiFi.EndPoint.{i}.Profile.{i}. *** */
DMOBJ tWiFiEndPointProfileObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Security", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tWiFiEndPointProfileSecurityParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tWiFiEndPointProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_WiFiEndPointProfile_Enable, set_WiFiEndPointProfile_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_WiFiEndPointProfile_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_Alias, set_WiFiEndPointProfile_Alias, NULL, NULL, BBFDM_BOTH},
{"SSID", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_SSID, set_WiFiEndPointProfile_SSID, NULL, NULL, BBFDM_BOTH},
//{"Location", &DMWRITE, DMT_STRING, get_WiFiEndPointProfile_Location, set_WiFiEndPointProfile_Location, NULL, NULL, BBFDM_BOTH},
//{"Priority", &DMWRITE, DMT_UNINT, get_WiFiEndPointProfile_Priority, set_WiFiEndPointProfile_Priority, NULL, NULL, BBFDM_BOTH},
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
//{"Version", &DMREAD, DMT_STRING, get_WiFiEndPointWPS_Version, NULL, NULL, NULL, BBFDM_BOTH},
{"PIN", &DMWRITE, DMT_UNINT, get_WiFiEndPointWPS_PIN, set_WiFiEndPointWPS_PIN, NULL, NULL, BBFDM_BOTH},
{0}
};
