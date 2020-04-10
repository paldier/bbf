#ifndef __BBF_TR181_OPERATING_SYTEM_H
#define __BBF_TR181_OPERATING_SYTEM_H

#include <libbbf_api/dmbbf.h>

/* IOPSYS-WRT and OpenWrt
 */
char * os__get_deviceid_manufacturer();
char * os__get_deviceid_productclass();
char * os__get_deviceid_serialnumber();
char * os__get_softwareversion();
char * os__get_deviceid_manufactureroui();

int os__get_device_hardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_device_routermodel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_base_mac_addr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int os__get_memory_status_total(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_memory_status_free(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int os__get_process_cpu_usage(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_process_number_of_entries(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_process_pid(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_process_command(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_process_size(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_process_priority(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_process_cpu_time(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_process_state(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__browseProcessEntriesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);


int os__browsehostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int os__get_host_nbr_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_associateddevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_layer3interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_phy_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_address_source(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_leasetime_remaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_host_dhcp_client(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

#include "wifi.h"

int os__get_wlan_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadioStats_FCSErrorCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_FailedRetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_RetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_MultipleRetryCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_ACKFailureCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_AggregatedPacketCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiSSIDStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_failed_retrans_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_retry_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_associative_device_statistics_multiple_retry_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_radio_max_bit_rate (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_radio_frequency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_radio_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_neighboring_wifi_diagnostics_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_neighboring_wifi_diagnostics_result_ssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_neighboring_wifi_diagnostics_result_bssid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_neighboring_wifi_diagnostics_result_number_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_neighboring_wifi_diagnostics_result_noise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_neighboring_wifi_diagnostics_result_operating_frequency_band(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_neighboring_wifi_diagnostics_result_signal_strength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_neighboring_wifi_diagnostics_result_channel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_radio_possible_channels(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__browseWifiNeighboringWiFiDiagnosticResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int os__get_WiFiRadio_CurrentOperatingChannelBandwidth(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_WiFiRadio_SupportedOperatingChannelBandwidths(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_radio_supported_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__get_access_point_total_associations(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os__browse_wifi_associated_device(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
char * os__get_radio_frequency_nocache(const struct wifi_radio_args *args);
char * os__get_radio_channel_nocache(const struct wifi_radio_args *args);
void os__wifi_start_scan(const char *radio);
int os_get_wifi_access_point_status (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int os_get_radio_operating_standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
char * os__get_default_wpa_key();

#endif
