#include "os.h"

static int not_implemented(char **value)
{
	*value = "";
	return 0;
}

/*#Device.WiFi.SSID.{i}.BSSID!UBUS:wifi.ap.@Name/status//bssid*/
int os__get_wlan_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.BytesSent!UBUS:wifi.radio.@Name/stats//tx_bytes*/
int os__get_WiFiRadioStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.BytesReceived!UBUS:wifi.radio.@Name/stats//rx_bytes*/
int os__get_WiFiRadioStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsSent!UBUS:wifi.radio.@Name/stats//tx_packets*/
int os__get_WiFiRadioStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.PacketsReceived!UBUS:wifi.radio.@Name/stats//rx_packets*/
int os__get_WiFiRadioStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsSent!UBUS:wifi.radio.@Name/stats//tx_error_packets*/
int os__get_WiFiRadioStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.ErrorsReceived!UBUS:wifi.radio.@Name/stats//rx_error_packets*/
int os__get_WiFiRadioStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsSent!UBUS:wifi.radio.@Name/stats//tx_dropped_packets*/
int os__get_WiFiRadioStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.DiscardPacketsReceived!UBUS:wifi.radio.@Name/stats//rx_dropped_packets*/
int os__get_WiFiRadioStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.Stats.FCSErrorCount!UBUS:wifi.radio.@Name/stats//rx_fcs_error_packets*/
int os__get_WiFiRadioStats_FCSErrorCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.BytesSent!UBUS:wifi.ap.@Name/stats//tx_bytes*/
int os__get_WiFiSSIDStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.BytesReceived!UBUS:wifi.ap.@Name/stats//rx_bytes*/
int os__get_WiFiSSIDStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsSent!UBUS:wifi.ap.@Name/stats//tx_packets*/
int os__get_WiFiSSIDStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.PacketsReceived!UBUS:wifi.ap.@Name/stats//rx_packets*/
int os__get_WiFiSSIDStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsSent!UBUS:wifi.ap.@Name/stats//tx_error_packets*/
int os__get_WiFiSSIDStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.ErrorsReceived!UBUS:wifi.ap.@Name/stats//rx_error_packets*/
int os__get_WiFiSSIDStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsSent!UBUS:wifi.ap.@Name/stats//tx_dropped_packets*/
int os__get_WiFiSSIDStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.DiscardPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_dropped_packets*/
int os__get_WiFiSSIDStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnicastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_unicast_packets*/
int os__get_WiFiSSIDStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnicastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_unicast_packets*/
int os__get_WiFiSSIDStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.MulticastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_multicast_packets*/
int os__get_WiFiSSIDStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.MulticastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_multicast_packets*/
int os__get_WiFiSSIDStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.BroadcastPacketsSent!UBUS:wifi.ap.@Name/stats//tx_broadcast_packets*/
int os__get_WiFiSSIDStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.BroadcastPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_broadcast_packets*/
int os__get_WiFiSSIDStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.RetransCount!UBUS:wifi.ap.@Name/stats//tx_retrans_packets*/
int os__get_WiFiSSIDStats_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.FailedRetransCount!UBUS:wifi.ap.@Name/stats//tx_retrans_fail_packets*/
int os__get_WiFiSSIDStats_FailedRetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.RetryCount!UBUS:wifi.ap.@Name/stats//tx_retry_packets*/
int os__get_WiFiSSIDStats_RetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.MultipleRetryCount!UBUS:wifi.ap.@Name/stats//tx_multi_retry_packets*/
int os__get_WiFiSSIDStats_MultipleRetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.ACKFailureCount!UBUS:wifi.ap.@Name/stats//ack_fail_packets*/
int os__get_WiFiSSIDStats_ACKFailureCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.AggregatedPacketCount!UBUS:wifi.ap.@Name/stats//aggregate_packets*/
int os__get_WiFiSSIDStats_AggregatedPacketCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.SSID.{i}.Stats.UnknownProtoPacketsReceived!UBUS:wifi.ap.@Name/stats//rx_unknown_packets*/
int os__get_WiFiSSIDStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.BytesSent!UBUS:wifix/stations/vif,@Name/stats.tx_total_bytes*/
int os__get_access_point_associative_device_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.BytesReceived!UBUS:wifix/stations/vif,@Name/stats.rx_data_bytes*/
int os__get_access_point_associative_device_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.PacketsSent!UBUS:wifix/stations/vif,@Name/stats.tx_total_pkts*/
int os__get_access_point_associative_device_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.PacketsReceived!UBUS:wifix/stations/vif,@Name/stats.rx_data_pkts*/
int os__get_access_point_associative_device_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.ErrorsSent!UBUS:wifix/stations/vif,@Name/stats.tx_failures*/
int os__get_access_point_associative_device_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.RetransCount!UBUS:wifix/stations/vif,@Name/stats.tx_pkts_retries*/
int os__get_access_point_associative_device_statistics_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.FailedRetransCount!UBUS:wifix/stations/vif,@Name/stats.tx_pkts_retry_exhausted*/
int os__get_access_point_associative_device_statistics_failed_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.RetryCount!UBUS:wifix/stations/vif,@Name/stats.tx_pkts_retries*/
int os__get_access_point_associative_device_statistics_retry_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.AccessPoint.{i}.Stats.MultipleRetryCount!UBUS:wifix/stations/vif,@Name/stats.tx_data_pkts_retried*/
int os__get_access_point_associative_device_statistics_multiple_retry_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.MaxBitRate!UBUS:wifi.radio.@Name/status//maxrate*/
int os__get_radio_max_bit_rate (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.OperatingFrequencyBand!UBUS:wifi.radio.@Name/status//band*/
int os__get_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.ChannelsInUse!UCI:wireless/wifi-device,@i-1/channel*/
int os__get_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

char * os__get_radio_channel_nocache(const struct wifi_radio_args *args)
{
	return "";
}

char * os__get_radio_frequency_nocache(const struct wifi_radio_args *args)
{
	return "";
}

int os__get_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_neighboring_wifi_diagnostics_result_number_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_neighboring_wifi_diagnostics_result_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_neighboring_wifi_diagnostics_result_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_neighboring_wifi_diagnostics_result_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_neighboring_wifi_diagnostics_result_signal_strength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_neighboring_wifi_diagnostics_result_operating_frequency_band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_neighboring_wifi_diagnostics_result_noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.PossibleChannels!UBUS:wifi.radio.@Name/status//supp_channels[0].channels*/
int os__get_radio_possible_channels(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.SupportedOperatingChannelBandwidths!UBUS:wifi.radio.@Name/status//supp_channels[0].bandwidth*/
int os__get_WiFiRadio_SupportedOperatingChannelBandwidths(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

/*#Device.WiFi.Radio.{i}.CurrentOperatingChannelBandwidth!UBUS:wifi.radio.@Name/status//bandwidth*/
int os__get_WiFiRadio_CurrentOperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

void os__wifi_start_scan(const char *radio)
{
}

int os__browseWifiNeighboringWiFiDiagnosticResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

/*#Device.WiFi.Radio.{i}.SupportedStandards!UBUS:wifi/status//radio[i-1].standard*/
int os__get_radio_supported_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_access_point_total_associations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__browse_wifi_associated_device(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

