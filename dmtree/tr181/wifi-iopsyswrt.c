#include "os.h"

/*#Device.WiFi.SSID.{i}.BSSID!UBUS:wifi.ap.@Name/status//bssid*/
int os__get_wlan_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_ssid_args *)data)->ifname);
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "bssid");
	return 0;
}

static int ssid_read_ubus(const struct wifi_ssid_args *args, const char *name, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.ap.%s", args->ifname);
	dmubus_call(object, "stats", UBUS_ARGS{}, 0, &res);
	if (!res) {
		*value = "0";
		return 0;
	}
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

static int radio_read_ubus(const struct wifi_radio_args *args, const char *name, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->wifi_radio_sec));
	dmubus_call(object, "stats", UBUS_ARGS{}, 0, &res);
	if (!res) {
		*value = "0";
		return 0;
	}
	*value = dmjson_get_value(res, 1, name);
	return 0;
}

/*#Device.WiFi.Radio.{i}.Stats.BytesSent!UBUS:wifi.radio.@Name/stats//tx_bytes*/
int os__get_WiFiRadioStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_bytes", value);
}

/*#Device.WiFi.Radio.{i}.Stats.BytesReceived!UBUS:wifi.radio.@Name/stats//rx_bytes*/
int os__get_WiFiRadioStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_bytes", value);
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsSent!UBUS:wifi.radio.@Name/stats//tx_packets*/
int os__get_WiFiRadioStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsReceived!UBUS:wifi.radio.@Name/stats//rx_packets*/
int os__get_WiFiRadioStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsSent!UBUS:wifi.radio.@Name/stats//tx_error_packets*/
int os__get_WiFiRadioStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_error_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsReceived!UBUS:wifi.radio.@Name/stats//rx_error_packets*/
int os__get_WiFiRadioStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_error_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent!UBUS:wifi.radio.@Name/stats//tx_dropped_packets*/
int os__get_WiFiRadioStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "tx_dropped_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived!UBUS:wifi.radio.@Name/stats//rx_dropped_packets*/
int os__get_WiFiRadioStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_dropped_packets", value);
}

/*#Device.WiFi.Radio.{i}.Stats.FCSErrorCount!UBUS:wifi.radio.@Name/stats//rx_fcs_error_packets*/
int os__get_WiFiRadioStats_FCSErrorCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return radio_read_ubus(data, "rx_fcs_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BytesSent!UBUS:wifi.ap.@Name/stats//tx_bytes*/
int os__get_WiFiSSIDStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_bytes", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BytesReceived!UBUS:wifi.ap.@Name/stats//rx_bytes*/
int os__get_WiFiSSIDStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_bytes", value);
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsSent!UBUS:wifi.ap.@Name/stats//tx_packets*/
int os__get_WiFiSSIDStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsReceived!UBUS:wifi.ap.@Name/stats//rx_packets*/
int os__get_WiFiSSIDStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsSent!UBUS:wifi.ap.@Name/stats//tx_error_packets*/
int os__get_WiFiSSIDStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsReceived!UBUS:wifi.ap.@Name/stats//rx_error_packets*/
int os__get_WiFiSSIDStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_error_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent!UBUS:wifi.ap.@Name/stats//tx_dropped_packets*/
int os__get_WiFiSSIDStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_dropped_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_dropped_packets*/
int os__get_WiFiSSIDStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_dropped_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnicastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_unicast_packets*/
int os__get_WiFiSSIDStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_unicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnicastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_unicast_packets*/
int os__get_WiFiSSIDStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_unicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MulticastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_multicast_packets*/
int os__get_WiFiSSIDStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_multicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MulticastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_multicast_packets*/
int os__get_WiFiSSIDStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_multicast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BroadcastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_broadcast_packets*/
int os__get_WiFiSSIDStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_broadcast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.BroadcastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_broadcast_packets*/
int os__get_WiFiSSIDStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_broadcast_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.RetransCount!UBUS:wifi.ap.@Name/stats//tx_retrans_packets*/
int os__get_WiFiSSIDStats_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retrans_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.FailedRetransCount!UBUS:wifi.ap.@Name/stats//tx_retrans_fail_packets*/
int os__get_WiFiSSIDStats_FailedRetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retrans_fail_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.RetryCount!UBUS:wifi.ap.@Name/stats//tx_retry_packets*/
int os__get_WiFiSSIDStats_RetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_retry_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.MultipleRetryCount!UBUS:wifi.ap.@Name/stats//tx_multi_retry_packets*/
int os__get_WiFiSSIDStats_MultipleRetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "tx_multi_retry_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.ACKFailureCount!UBUS:wifi.ap.@Name/stats//ack_fail_packets*/
int os__get_WiFiSSIDStats_ACKFailureCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "ack_fail_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.AggregatedPacketCount!UBUS:wifi.ap.@Name/stats//aggregate_packets*/
int os__get_WiFiSSIDStats_AggregatedPacketCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "aggregate_packets", value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnknownProtoPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_unknown_packets*/
int os__get_WiFiSSIDStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return ssid_read_ubus(data, "rx_unknown_packets", value);
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_total_bytes*/
int os__get_access_point_associative_device_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_total_bytes");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.BytesReceived!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rx_data_bytes*/
int os__get_access_point_associative_device_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_data_bytes");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_total_pkts*/
int os__get_access_point_associative_device_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_total_pkts");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.PacketsReceived!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.rx_data_pkts*/
int os__get_access_point_associative_device_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "rx_data_pkts");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.ErrorsSent!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_failures*/
int os__get_access_point_associative_device_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_failures");
	return 0;
}

/*#Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.Stats.RetransCount!UBUS:wifi.ap.@Name/stations//stations[i-1].stats.tx_pkts_retries*/
int os__get_access_point_associative_device_statistics_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 2, "stats", "tx_pkts_retries");
	return 0;
}


/*#Device.WiFi.AccessPoint.{i}.Status!UBUS:wifi.ap.@Name/status//status*/
int os_get_wifi_access_point_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char object[32], *status = NULL, *iface;

	dmuci_get_value_by_section_string(((struct wifi_ssid_args *)data)->wifi_ssid_sec, "device", &iface);
	snprintf(object, sizeof(object), "wifi.ap.%s", iface);
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, status = "");
	status = dmjson_get_value(res, 1, "status");

	if (strcmp(status, "running") == 0 || strcmp(status, "up") == 0)
		*value = "Enabled";
	else
		*value = "Disabled";
	return 0;
}

/*#Device.WiFi.Radio.{i}.MaxBitRate!UBUS:wifi.radio.@Name/status//maxrate*/
int os__get_radio_max_bit_rate (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "maxrate");
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/status//band*/
int os__get_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "band");
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedFrequencyBands!UBUS:wifi.radio.@Name/status//supp_bands*/
int os__get_radio_supported_frequency_bands(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value_array_all(res, DELIMITOR, 1, "supp_bands");
	return 0;
}

/*#Device.WiFi.Radio.{i}.ChannelsInUse!UCI:wireless/wifi-device,@i-1/channel*/
int os__get_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmuci_get_value_by_section_string(((struct wifi_radio_args *)data)->wifi_radio_sec, "channel", value);
	if (strcmp(*value, "auto") == 0 || (*value)[0] == '\0') {
		char object[32];
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
		dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
		DM_ASSERT(res, *value = "");
		*value = dmjson_get_value(res, 1, "channel");
	}
	return 0;
}

char * os__get_radio_channel_nocache(const struct wifi_radio_args *args)
{
	char object[32];
	char *value = "";
	json_object *res;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	if (res)
		value = dmjson_get_value(res, 1, "channel");

	return value;
}

char * os__get_radio_frequency_nocache(const struct wifi_radio_args *args)
{
	char object[32];
	json_object *res;
	char *freq = "";

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(args->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	if (res)
		freq = dmjson_get_value(res, 1, "frequency");

	return freq;
}

int os__get_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss;
	json_object *res = NULL, *neighboring_wifi_obj = NULL;
	char object[32];

	uci_foreach_sections("wireless", "wifi-device", ss) {
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(ss));
		dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);
		DM_ASSERT(res, *value = "None");
		neighboring_wifi_obj = dmjson_select_obj_in_array_idx(res, 0, 1, "accesspoints");
		if (neighboring_wifi_obj) {
			*value = "Complete";
			break;
		} else
			*value = "None";
	}
	return 0;
}

int os__get_neighboring_wifi_diagnostics_result_number_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss;
	json_object *res = NULL, *accesspoints = NULL;
	size_t entries = 0, result = 0;
	char object[32];
	*value = "0";

	uci_foreach_sections("wireless", "wifi-device", ss) {
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(ss));
		dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);
		if (res) {
			json_object_object_get_ex(res, "accesspoints", &accesspoints);
			if (accesspoints)
				entries = json_object_array_length(accesspoints);
		}
		result = result + entries;
		entries = 0;
	}
	dmasprintf(value, "%d", result); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

void os__wifi_start_scan(const char *radio)
{
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", radio);
	dmubus_call_set(object, "scan", UBUS_ARGS{}, 0);
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SSID!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].ssid*/
int os__get_neighboring_wifi_diagnostics_result_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "ssid");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.BSSID!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].bssid*/
int os__get_neighboring_wifi_diagnostics_result_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "bssid");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Channel!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].channel*/
int os__get_neighboring_wifi_diagnostics_result_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "channel");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.SignalStrength!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].rssi*/
int os__get_neighboring_wifi_diagnostics_result_signal_strength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "rssi");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].band*/
int os__get_neighboring_wifi_diagnostics_result_operating_frequency_band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "band");
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.Noise!UBUS:wifi.radio.@Name/scanresults//accesspoints[@i-1].noise*/
int os__get_neighboring_wifi_diagnostics_result_noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "noise");
	return 0;
}

/*#Device.WiFi.Radio.{i}.PossibleChannels!UBUS:wifi.radio.@Name/status//supp_channels[0].channels*/
int os__get_radio_possible_channels(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *supp_channels = NULL;
	char object[32];

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	supp_channels = dmjson_select_obj_in_array_idx(res, 0, 1, "supp_channels");
	if (supp_channels)
		*value = dmjson_get_value_array_all(supp_channels, DELIMITOR, 1, "channels");
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedOperatingChannelBandwidths!UBUS:wifi.radio.@Name/status//supp_channels[0].bandwidth*/
int os__get_WiFiRadio_SupportedOperatingChannelBandwidths(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *supp_channels = NULL;
	char object[32], *bandwidth = NULL;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	supp_channels = dmjson_select_obj_in_array_idx(res, 0, 1, "supp_channels");
	if (supp_channels)
		bandwidth = dmjson_get_value(supp_channels, 1, "bandwidth");
	if (bandwidth)
		dmasprintf(value, "%sMHz", bandwidth);
	return 0;
}

/*#Device.WiFi.Radio.{i}.CurrentOperatingChannelBandwidth!UBUS:wifi.radio.@Name/status//bandwidth*/
int os__get_WiFiRadio_CurrentOperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char object[32], *bandwidth = NULL;

	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	bandwidth = dmjson_get_value(res, 1, "bandwidth");
	if (bandwidth)
		dmasprintf(value, "%sMHz", bandwidth);
	return 0;
}

/*#Device.WiFi.NeighboringWiFiDiagnostic.Result.{i}.!UBUS:wifi.radio.@Name/scanresults//accesspoints*/
int os__browseWifiNeighboringWiFiDiagnosticResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *ss;
	json_object *res = NULL, *accesspoints = NULL, *arrobj = NULL;
	char object[32], *idx, *idx_last = NULL;
	int id = 0, i = 0;

	uci_foreach_sections("wireless", "wifi-device", ss) {
		snprintf(object, sizeof(object), "wifi.radio.%s", section_name(ss));
		dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);
		if (res) {
			dmjson_foreach_obj_in_array(res, arrobj, accesspoints, i, 1, "accesspoints") {
				idx = handle_update_instance(3, dmctx, &idx_last, update_instance_without_section, 1, ++id);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)accesspoints, idx) == DM_STOP)
					return 0;
			}
		}
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedStandards!UBUS:wifi/status//radio[i-1].standard*/
int os__get_radio_supported_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *radios = NULL, *arrobj = NULL;
	char *name;
	int i = 0;

	dmubus_call("wifi", "status", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, arrobj, radios, i, 1, "radios") {
		name = dmjson_get_value(radios, 1, "name");
		if (strcmp(name, section_name(((struct wifi_radio_args *)data)->wifi_radio_sec)) == 0) {
			*value = dmjson_get_value(radios, 1, "standard");
			return 0;
		}
	}
	return 0;
}

/*#Device.WiFi.Radio.{i}.OperatingStandards!UBUS:wifi.radio.@Name/status//standard*/
int os_get_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	char object[32], *standard = NULL;
	char  **standards = NULL, *str_append= NULL;
	int i;
	size_t length;

	*value = "";
	snprintf(object, sizeof(object), "wifi.radio.%s", section_name(((struct wifi_radio_args *)data)->wifi_radio_sec));
	dmubus_call(object, "status", UBUS_ARGS{}, 0, &res);

	DM_ASSERT(res, standard = "");
	standard = dmjson_get_value(res, 1, "standard");
	standards = strsplit(standard, "/", &length);

	for (i=0; i<length;i++) {
		if (strstr(standards[i], "802.11") == standards[i])
			str_append = dmstrdup(strstr(standards[i], "802.11") + strlen("802.11"));
		else
			str_append = dmstrdup(standards[i]);
		if (strlen(*value) == 0){
			dmasprintf(value, "%s", str_append);
			continue;
		}
		dmasprintf(value, "%s,%s", *value, str_append);
		FREE(str_append);
	}

	return 0;
}

int os__get_access_point_total_associations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *assoclist = NULL, *arrobj = NULL;
	char object[32];
	int i = 0, entries = 0;

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_acp_args *)data)->ifname);
	dmubus_call(object, "assoclist", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, assoclist, i, 1, "assoclist") {
			entries++;
		}
	}
	dmasprintf(value, "%d", entries);
	return 0;
}

int os__browse_wifi_associated_device(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *stations = NULL, *arrobj = NULL;
	char object[32], *idx, *idx_last = NULL;
	int id = 0, i = 0;

	snprintf(object, sizeof(object), "wifi.ap.%s", ((struct wifi_acp_args *)prev_data)->ifname);
	dmubus_call(object, "stations", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, stations, i, 1, "stations") {
			idx = handle_update_instance(3, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)stations, idx) == DM_STOP)
				return 0;
		}
	}
	return 0;
}

char * os__get_default_wpa_key()
{
	char *wpakey;
	db_get_value_string("hw", "board", "wpa_key", &wpakey);
	return wpakey;
}
