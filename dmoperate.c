/*
 * dmoperate.c: Operate handler for uspd
 *
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * Author: Vivek Dutta <vivek.dutta@iopsys.eu>
 * Author: Yashvardhan <y.yashvardhan@iopsys.eu>
 * Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmoperate.h"

#define GLOB_EXPR "[=><]+"

char *DMT_TYPE[] = {
[DMT_STRING] = "xsd:string",
[DMT_UNINT] = "xsd:unsignedInt",
[DMT_INT] = "xsd:int",
[DMT_UNLONG] = "xsd:unsignedLong",
[DMT_LONG] = "xsd:long",
[DMT_BOOL] = "xsd:boolean",
[DMT_TIME] = "xsd:dateTime",
[DMT_HEXBIN] = "xsd:hexBinary",
};

static uint8_t wifi_neighbor_count = 0;
struct op_cmd *dynamic_operate = NULL;

bool is_str_eq(const char *s1, const char *s2)
{
	if(0==strcmp(s1, s2))
		return true;

	return false;
}

static void bbf_init(struct dmctx *dm_ctx, char *path)
{
	char *uci_amd = NULL, *uci_instance = NULL;
	int amd = AMD_2, instance = INSTANCE_MODE_ALIAS;

	if(match(path, "[[]+")) {
		if(!match(path, GLOB_EXPR)) {
			amd = AMD_5;
		}
	} else {
		dmuci_get_option_value_string("cwmp", "cpe", "amd_version", &uci_amd);
		if(uci_amd) {
			amd = atoi(uci_amd);
			dmfree(uci_amd);
		}
		dmuci_get_option_value_string("cwmp", "cpe", "instance_mode", &uci_instance);
		if(uci_instance) {
			if(!is_str_eq(uci_instance, "InstanceAlias"))
				instance = INSTANCE_MODE_NUMBER;
			dmfree(uci_instance);
		}
	}
	dm_ctx_init_sub(dm_ctx, DM_CWMP, amd, instance);
}

static void bbf_cleanup(struct dmctx *dm_ctx)
{
	dm_ctx_clean_sub(dm_ctx);
}

static bool bbf_get(int operation, char *path, struct dmctx *dm_ctx)
{
	int fault = 0;

	switch(operation) {
		case CMD_GET_NAME:
			fault = dm_entry_param_method(dm_ctx, CMD_GET_NAME, path, "true", NULL);
			break;
		case CMD_GET_VALUE:
			fault = dm_entry_param_method(dm_ctx, CMD_GET_VALUE, path, NULL, NULL);
			break;
		default:
			return false;
	}

	if (dm_ctx->list_fault_param.next != &dm_ctx->list_fault_param) {
		return false;
	}
	if (fault) {
		return false;
	}
	return true;
}

static bool bbf_set_value(char *path, char *value)
{
	int fault = 0, res;
	struct dmctx dm_ctx = {0};
	struct dmctx *p_dmctx = &dm_ctx;

	bbf_init(&dm_ctx, path);

	fault = dm_entry_param_method(&dm_ctx, CMD_SET_VALUE, path, value, NULL);

	if(!fault) {
		fault = dm_entry_apply(&dm_ctx, CMD_SET_VALUE, "", NULL);
	}

	if (p_dmctx->list_fault_param.next != &p_dmctx->list_fault_param) {
		res = FAIL;
	}

	if (fault)
		res = FAIL;
	else
		res = SUCCESS;

	bbf_cleanup(&dm_ctx);
	return res;
}

static char *bbf_get_value_by_id(char *id)
{
	struct dmctx dm_ctx = {0};
	struct dm_parameter *n;
	char *value = NULL;

	bbf_init(&dm_ctx, id);
	if(bbf_get(CMD_GET_VALUE, id, &dm_ctx)) {
			list_for_each_entry(n, &dm_ctx.list_parameter, list) {
				value = dmstrdup(n->data);
				break;
			}
	}
	bbf_cleanup(&dm_ctx);
	return value;
}

static char *get_param_val_from_op_cmd(char *op_cmd, const char *param)
{
	char *val = NULL;
	char node[256] = {'\0'};

	// Trim action from operation command
	// For eg: trim Reset from Device.IP.Interface.*.Reset
	char *ret = strrchr(op_cmd, '.');
	strncpy(node, op_cmd, ret - op_cmd +1);

	// Append param name to the trimmed path
	strcat(node, param);

	// Get parameter value
	val = bbf_get_value_by_id(node);
	return val;
}

// Operate function definitions
static opr_ret_t reboot_device(struct dmctx *dmctx, char *path, char *input)
{
	if(0 == dmubus_call_set(SYSTEM_UBUS_PATH, "reboot", UBUS_ARGS{}, 0))
		return SUCCESS;
	else
		return FAIL;
}

static opr_ret_t factory_reset(struct dmctx *dmctx, char *path, char *input)
{
	if(0 == dmcmd_no_wait("/sbin/defaultreset", 0))
		return SUCCESS;
	else
		return FAIL;
}

static opr_ret_t network_interface_reset(struct dmctx *dmctx, char *path, char *input)
{
	char cmd[NAME_MAX] = NETWORK_INTERFACE_UBUS_PATH;
	bool status = false;

	snprintf(cmd + strlen(cmd), NAME_MAX - strlen(cmd), "%s", ".");
	char *zone = NULL;
	zone = get_param_val_from_op_cmd(path, "Name");
	if(zone) {
		strcat(cmd, zone);
		dmfree(zone);
	} else {
		return FAIL;
	}
	if(0 == dmubus_call_set(cmd, "down", UBUS_ARGS{}, 0))
		status = true;

	if(0 == dmubus_call_set(cmd, "up", UBUS_ARGS{}, 0))
		status &= true;

	if(status)
		return SUCCESS;
	else
		return FAIL;
}

static opr_ret_t wireless_reset(struct dmctx *dmctx, char *path, char *input)
{
	if(0 == dmcmd_no_wait("/sbin/wifi", 2, "reload", "&"))
		return SUCCESS;
	else
		return FAIL;
}

struct wifi_security_params reset_params[] = {
	{"", "ModeEnabled", ""},
	{"", "PreSharedKey", ""},
	{"", "KeyPassphrase", ""}
};

static opr_ret_t ap_security_reset(struct dmctx *dmctx, char *path, char *input)
{
	char *wpakey = NULL;
	char node[255] = {'\0'};
	int i, len = 0;

	char *ret = strrchr(path, '.');
	strncpy(node, path, ret - path +1);

	len = ARRAY_SIZE(reset_params);

	for (i = 0; i < len; i++) {
		strncpy(reset_params[i].node, node, 255);
		strcat(reset_params[i].node, reset_params[i].param);
	}
	const char *mode_enabled = "WPA2-Personal";

	// Default mode - WPA2-Personal
	strncpy(reset_params[0].value, mode_enabled, 255);

	// Get Default wpakey
	db_get_value_string("hw", "board", "wpa_key", &wpakey);

	// PreSharedKey and KeyPassphrase are kept same
	strncpy(reset_params[1].value, wpakey, 255);
	strncpy(reset_params[2].value, wpakey, 255);

	for (i = 0; i < len; i++) {
		bbf_set_value(reset_params[i].node, reset_params[i].value);
	}
	return SUCCESS;
}

static opr_ret_t dhcp_client_renew(struct dmctx *dmctx, char *path, char *input)
{
	if(SUCCESS == bbf_set_value(path, "true"))
		return SUCCESS;
	else
		return FAIL;
}

static opr_ret_t vendor_conf_backup(struct dmctx *dmctx, char *path, char *input)
{
	struct file_server fserver = {0};
	json_object *json_res = NULL;
	char *vcf_name = NULL;

	vcf_name = get_param_val_from_op_cmd(path, "Name");
	if (!vcf_name)
		return FAIL;

	json_res = json_tokener_parse((const char *)input);
	fserver.url = dmjson_get_value(json_res, 1, "URL");
	if(fserver.url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	fserver.user = dmjson_get_value(json_res, 1, "Username");
	fserver.pass = dmjson_get_value(json_res, 1, "Password");

	dmcmd("/bin/sh", 7, ICWMP_SCRIPT, "upload", fserver.url, VCF_FILE_TYPE, fserver.user, fserver.pass, vcf_name);
	dmfree(vcf_name);

	return SUCCESS;
}

static opr_ret_t vendor_conf_restore(struct dmctx *dmctx, char *path, char *input)
{
	struct file_server fserver = {0};
	json_object *json_res = NULL;
	char *file_size = NULL;

	json_res = json_tokener_parse((const char *)input);
	fserver.url = dmjson_get_value(json_res, 1, "URL");
	if(fserver.url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	fserver.user = dmjson_get_value(json_res, 1, "Username");
	fserver.pass = dmjson_get_value(json_res, 1, "Password");
	file_size = dmjson_get_value(json_res, 1, "FileSize");

	dmcmd("/bin/sh", 7, ICWMP_SCRIPT, "download", fserver.url, file_size, VCF_FILE_TYPE, fserver.user, fserver.pass);

	if (0 == dmcmd_no_wait("/bin/sh", 4, ICWMP_SCRIPT, "apply", "download", VCF_FILE_TYPE))
		return SUCCESS;
	else
		return FAIL;
}

static void fill_wireless_scan_results(struct dmctx *dmctx, char *radio)
{
	json_object *res = NULL, *obj = NULL;
	struct neighboring_wiFi_diagnostic neighboring = {0};
	char object[32], *ssid, *bssid, *channel, *frequency, *signal_stregth, *noise;

	snprintf(object, sizeof(object), "wifi.radio.%s", radio);
	dmubus_call_set(object, "scan", UBUS_ARGS{}, 0);
	sleep(2); // Wait for results to get populated in scanresults
	dmubus_call(object, "scanresults", UBUS_ARGS{}, 0, &res);

	if (!res)
		return;

	if (!json_object_object_get_ex(res,"accesspoints", &obj))
		return;

	uint8_t len = json_object_array_length(obj);
	for (uint8_t j = 0; j < len; j++ ) {
		wifi_neighbor_count++;
		json_object *array_obj = json_object_array_get_idx(obj, j);
		neighboring.ssid = dmjson_get_value(array_obj, 1, "ssid");
		neighboring.bssid = dmjson_get_value(array_obj, 1, "bssid");
		neighboring.channel = dmjson_get_value(array_obj, 1, "channel");
		neighboring.frequency = dmjson_get_value(array_obj, 1, "frequency");
		neighboring.signal_strength = dmjson_get_value(array_obj, 1, "rssi");
		neighboring.noise = dmjson_get_value(array_obj, 1, "snr");

		dmasprintf(&ssid, "Result.%d.SSID", wifi_neighbor_count);
		dmasprintf(&bssid, "Result.%d.BSSID", wifi_neighbor_count);
		dmasprintf(&channel, "Result.%d.Channel", wifi_neighbor_count);
		dmasprintf(&frequency, "Result.%d.OperatingFrequencyBand", wifi_neighbor_count);
		dmasprintf(&signal_stregth, "Result.%d.SignalStrength", wifi_neighbor_count);
		dmasprintf(&noise, "Result.%d.Noise", wifi_neighbor_count);

		add_list_paramameter(dmctx, ssid, neighboring.ssid, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, bssid, neighboring.bssid, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, channel, neighboring.channel, DMT_TYPE[DMT_UNINT], NULL, 0);
		add_list_paramameter(dmctx, frequency, neighboring.frequency, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, signal_stregth, neighboring.signal_strength, DMT_TYPE[DMT_INT], NULL, 0);
		add_list_paramameter(dmctx, noise, neighboring.noise, DMT_TYPE[DMT_INT], NULL, 0);
	}
}

static opr_ret_t fetch_neighboring_wifi_diagnostic(struct dmctx *dmctx, char *path, char *input)
{
	json_object *res = NULL, *radios = NULL, *arrobj = NULL;
	int j = 0;

	dmubus_call("wifi", "status", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, radios, j, 1, "radios") {
			fill_wireless_scan_results(dmctx, dmjson_get_value(radios, 1, "name"));
		}
	}
	wifi_neighbor_count = 0;
	return SUCCESS;
}

static opr_ret_t ip_diagnostics_ipping(struct dmctx *dmctx, char *path, char *input)
{
	json_object *json_res = NULL;
	struct ipping_diagnostics ipping = {0};

	json_res = json_tokener_parse((const char *)input);
	ipping.host = dmjson_get_value(json_res, 1, "Host");
	if(ipping.host[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	ipping.interface = dmjson_get_value(json_res, 1, "Interface");
	ipping.proto = dmjson_get_value(json_res, 1, "ProtocolVersion");
	ipping.nbofrepetition = dmjson_get_value(json_res, 1, "NumberOfRepetitions");
	ipping.timeout = dmjson_get_value(json_res, 1, "Timeout");
	ipping.datablocksize = dmjson_get_value(json_res, 1, "DataBlockSize");
	ipping.dscp = dmjson_get_value(json_res, 1, "DSCP");

	set_param_diagnostics("ippingdiagnostic", "Host", ipping.host);
	set_param_diagnostics("ippingdiagnostic", "interface", ipping.interface);
	set_param_diagnostics("ippingdiagnostic", "ProtocolVersion", ipping.proto);
	set_param_diagnostics("ippingdiagnostic", "NumberOfRepetitions", ipping.nbofrepetition);
	set_param_diagnostics("ippingdiagnostic", "Timeout", ipping.timeout);
	set_param_diagnostics("ippingdiagnostic", "DataBlockSize", ipping.datablocksize);
	set_param_diagnostics("ippingdiagnostic", "DSCP", ipping.dscp);

	//Free uci_varstate_ctx
	end_uci_varstate_ctx();

	dmcmd("/bin/sh", 3, IPPING_PATH, "run", "usp");

	//Allocate uci_varstate_ctx
	init_uci_varstate_ctx();

	ipping.success_count = get_param_diagnostics("ippingdiagnostic", "SuccessCount");
	ipping.failure_count = get_param_diagnostics("ippingdiagnostic", "FailureCount");
	ipping.average_response_time = get_param_diagnostics("ippingdiagnostic", "AverageResponseTime");
	ipping.minimum_response_time = get_param_diagnostics("ippingdiagnostic", "MinimumResponseTime");
	ipping.maximum_response_time = get_param_diagnostics("ippingdiagnostic", "MaximumResponseTime");
	ipping.average_response_time_detailed = get_param_diagnostics("ippingdiagnostic", "AverageResponseTimeDetailed");
	ipping.minimum_response_time_detailed = get_param_diagnostics("ippingdiagnostic", "MinimumResponseTimeDetailed");
	ipping.maximum_response_time_detailed = get_param_diagnostics("ippingdiagnostic", "MaximumResponseTimeDetailed");

	char *param_success_count = dmstrdup("SuccessCount");
	char *param_failure_count = dmstrdup("FailureCount");
	char *param_average_response_time = dmstrdup("AverageResponseTime");
	char *param_minimum_response_time = dmstrdup("MinimumResponseTime");
	char *param_maximum_response_time = dmstrdup("MaximumResponseTime");
	char *param_average_response_time_detailed = dmstrdup("AverageResponseTimeDetailed");
	char *param_minimum_response_time_detailed = dmstrdup("MinimumResponseTimeDetailed");
	char *param_maximum_response_time_detailed = dmstrdup("MaximumResponseTimeDetailed");

	add_list_paramameter(dmctx, param_success_count, ipping.success_count, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_failure_count, ipping.failure_count, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_average_response_time, ipping.average_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_minimum_response_time, ipping.minimum_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_maximum_response_time, ipping.maximum_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_average_response_time_detailed, ipping.average_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_minimum_response_time_detailed, ipping.minimum_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_maximum_response_time_detailed, ipping.maximum_response_time_detailed, DMT_TYPE[DMT_UNINT], NULL, 0);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_traceroute(struct dmctx *dmctx, char *path, char *input)
{
	json_object *json_res = NULL;
	struct traceroute_diagnostics traceroute = {0};
	struct uci_section *s = NULL;
	char *host, *host_address, *errorcode, *rttimes;
	int i = 1;

	json_res = json_tokener_parse((const char *)input);
	traceroute.host = dmjson_get_value(json_res, 1, "Host");
	if(traceroute.host[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	traceroute.interface = dmjson_get_value(json_res, 1, "Interface");
	traceroute.proto = dmjson_get_value(json_res, 1, "ProtocolVersion");
	traceroute.nboftries = dmjson_get_value(json_res, 1, "NumberOfTries");
	traceroute.timeout = dmjson_get_value(json_res, 1, "Timeout");
	traceroute.datablocksize = dmjson_get_value(json_res, 1, "DataBlockSize");
	traceroute.dscp = dmjson_get_value(json_res, 1, "DSCP");
	traceroute.maxhops = dmjson_get_value(json_res, 1, "MaxHopCount");

	set_param_diagnostics("traceroutediagnostic", "Host", traceroute.host);
	set_param_diagnostics("traceroutediagnostic", "interface", traceroute.interface);
	set_param_diagnostics("traceroutediagnostic", "ProtocolVersion", traceroute.proto);
	set_param_diagnostics("traceroutediagnostic", "NumberOfTries", traceroute.nboftries);
	set_param_diagnostics("traceroutediagnostic", "Timeout", traceroute.timeout);
	set_param_diagnostics("traceroutediagnostic", "DataBlockSize", traceroute.datablocksize);
	set_param_diagnostics("traceroutediagnostic", "DSCP", traceroute.dscp);
	set_param_diagnostics("traceroutediagnostic", "MaxHops", traceroute.maxhops);

	//Free uci_varstate_ctx
	end_uci_varstate_ctx();

	dmcmd("/bin/sh", 3, TRACEROUTE_PATH, "run", "usp");

	//Allocate uci_varstate_ctx
	init_uci_varstate_ctx();

	traceroute.response_time = get_param_diagnostics("traceroutediagnostic", "ResponseTime");
	char *param_response_time = dmstrdup("ResponseTime");
	add_list_paramameter(dmctx, param_response_time, traceroute.response_time, DMT_TYPE[DMT_UNINT], NULL, 0);

	uci_foreach_sections_state("cwmp", "RouteHops", s)
	{
		dmasprintf(&host, "RouteHops.%d.Host", i);
		dmasprintf(&host_address, "RouteHops.%d.HostAddress", i);
		dmasprintf(&errorcode, "RouteHops.%d.ErrorCode", i);
		dmasprintf(&rttimes, "RouteHops.%d.RTTimes", i);

		dmuci_get_value_by_section_string(s, "host", &traceroute.host_name);
		dmuci_get_value_by_section_string(s, "ip", &traceroute.host_address);
		dmuci_get_value_by_section_string(s, "time", &traceroute.rttimes);

		add_list_paramameter(dmctx, host, traceroute.host_name, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, host_address, traceroute.host_address, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, errorcode, "0", DMT_TYPE[DMT_UNINT], NULL, 0);
		add_list_paramameter(dmctx, rttimes, traceroute.rttimes, DMT_TYPE[DMT_STRING], NULL, 0);
		i++;
	}

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_download(struct dmctx *dmctx, char *path, char *input)
{
	json_object *json_res = NULL;
	struct download_diagnostics download = {0};

	json_res = json_tokener_parse((const char *)input);
	download.download_url = dmjson_get_value(json_res, 1, "DownloadURL");
	if(download.download_url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	download.interface = dmjson_get_value(json_res, 1, "Interface");
	download.dscp = dmjson_get_value(json_res, 1, "DSCP");
	download.ethernet_priority = dmjson_get_value(json_res, 1, "EthernetPriority");
	download.proto = dmjson_get_value(json_res, 1, "ProtocolVersion");
	download.num_of_connections = dmjson_get_value(json_res, 1, "NumberOfConnections");
	download.enable_per_connection_results = dmjson_get_value(json_res, 1, "EnablePerConnectionResults");

	set_param_diagnostics("downloaddiagnostic", "url", download.download_url);
	set_param_diagnostics("downloaddiagnostic", "device", download.interface);
	set_param_diagnostics("downloaddiagnostic", "DSCP", download.dscp);
	set_param_diagnostics("downloaddiagnostic", "ethernetpriority", download.ethernet_priority);
	set_param_diagnostics("downloaddiagnostic", "ProtocolVersion", download.proto);
	set_param_diagnostics("downloaddiagnostic", "NumberOfConnections", download.num_of_connections);
	set_param_diagnostics("downloaddiagnostic", "EnablePerConnection", download.enable_per_connection_results);

	if(start_upload_download_diagnostic(DOWNLOAD_DIAGNOSTIC) == -1)
		return FAIL;

	download.romtime = get_param_diagnostics("downloaddiagnostic", "ROMtime");
	download.bomtime = get_param_diagnostics("downloaddiagnostic", "BOMtime");
	download.eomtime = get_param_diagnostics("downloaddiagnostic", "EOMtime");
	download.test_bytes_received = get_param_diagnostics("downloaddiagnostic", "TestBytesReceived");
	download.total_bytes_received = get_param_diagnostics("downloaddiagnostic", "TotalBytesReceived");
	download.total_bytes_sent = get_param_diagnostics("downloaddiagnostic", "TotalBytesSent");
	download.test_bytes_received_under_full_loading = get_param_diagnostics("downloaddiagnostic", "TestBytesReceived");
	download.total_bytes_received_under_full_loading = get_param_diagnostics("downloaddiagnostic", "TotalBytesReceived");
	download.total_bytes_sent_under_full_loading = get_param_diagnostics("downloaddiagnostic", "TotalBytesSent");
	download.period_of_full_loading = get_param_diagnostics("downloaddiagnostic", "PeriodOfFullLoading");
	download.tcp_open_request_time = get_param_diagnostics("downloaddiagnostic", "TCPOpenRequestTimes");
	download.tcp_open_response_time = get_param_diagnostics("downloaddiagnostic", "TCPOpenResponseTime");

	char *param_rom_time = dmstrdup("ROMTime");
	char *param_bom_time = dmstrdup("BOMTime");
	char *param_eom_time = dmstrdup("EOMTime");
	char *param_test_bytes_received = dmstrdup("TestBytesReceived");
	char *param_total_bytes_received = dmstrdup("TotalBytesReceived");
	char *param_total_bytes_sent = dmstrdup("TotalBytesSent");
	char *param_test_bytes_received_under_full_loading = dmstrdup("TestBytesReceivedUnderFullLoading");
	char *param_total_bytes_received_under_full_loading = dmstrdup("TotalBytesReceivedUnderFullLoading");
	char *param_total_bytes_sent_under_full_loading = dmstrdup("TotalBytesSentUnderFullLoading");
	char *param_period_of_full_loading = dmstrdup("PeriodOfFullLoading");
	char *param_tcp_open_request_time = dmstrdup("TCPOpenRequestTime");
	char *param_tcp_open_response_time = dmstrdup("TCPOpenResponseTime");

	add_list_paramameter(dmctx, param_rom_time, download.romtime, DMT_TYPE[DMT_TIME], NULL, 0);
	add_list_paramameter(dmctx, param_bom_time, download.bomtime, DMT_TYPE[DMT_TIME], NULL, 0);
	add_list_paramameter(dmctx, param_eom_time, download.eomtime, DMT_TYPE[DMT_TIME], NULL, 0);
	add_list_paramameter(dmctx, param_test_bytes_received, download.test_bytes_received, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_total_bytes_received, download.total_bytes_received, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_total_bytes_sent, download.total_bytes_sent, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_test_bytes_received_under_full_loading, download.test_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_total_bytes_received_under_full_loading, download.total_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_total_bytes_sent_under_full_loading, download.total_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_period_of_full_loading, download.period_of_full_loading, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_tcp_open_request_time, download.tcp_open_request_time, DMT_TYPE[DMT_TIME], NULL, 0);
	add_list_paramameter(dmctx, param_tcp_open_response_time, download.tcp_open_response_time, DMT_TYPE[DMT_TIME], NULL, 0);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_upload(struct dmctx *dmctx, char *path, char *input)
{
	json_object *json_res = NULL;
	struct upload_diagnostics upload = {0};

	json_res = json_tokener_parse((const char *)input);
	upload.upload_url = dmjson_get_value(json_res, 1, "UploadURL");
	if(upload.upload_url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	upload.test_file_length = dmjson_get_value(json_res, 1, "TestFileLength");
	if(upload.test_file_length[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	upload.interface = dmjson_get_value(json_res, 1, "Interface");
	upload.dscp = dmjson_get_value(json_res, 1, "DSCP");
	upload.ethernet_priority = dmjson_get_value(json_res, 1, "EthernetPriority");
	upload.proto = dmjson_get_value(json_res, 1, "ProtocolVersion");
	upload.num_of_connections = dmjson_get_value(json_res, 1, "NumberOfConnections");
	upload.enable_per_connection_results = dmjson_get_value(json_res, 1, "EnablePerConnectionResults");

	set_param_diagnostics("uploaddiagnostic", "url", upload.upload_url);
	set_param_diagnostics("uploaddiagnostic", "TestFileLength", upload.test_file_length);
	set_param_diagnostics("uploaddiagnostic", "device", upload.interface);
	set_param_diagnostics("uploaddiagnostic", "DSCP", upload.dscp);
	set_param_diagnostics("uploaddiagnostic", "ethernetpriority", upload.ethernet_priority);
	set_param_diagnostics("uploaddiagnostic", "ProtocolVersion", upload.proto);
	set_param_diagnostics("uploaddiagnostic", "NumberOfConnections", upload.num_of_connections);
	set_param_diagnostics("uploaddiagnostic", "EnablePerConnection", upload.enable_per_connection_results);

	if(start_upload_download_diagnostic(UPLOAD_DIAGNOSTIC) == -1)
		return FAIL;

	upload.romtime = get_param_diagnostics("uploaddiagnostic", "ROMtime");
	upload.bomtime = get_param_diagnostics("uploaddiagnostic", "BOMtime");
	upload.eomtime = get_param_diagnostics("uploaddiagnostic", "EOMtime");
	upload.test_bytes_sent = get_param_diagnostics("uploaddiagnostic", "TestBytesSent");
	upload.total_bytes_received = get_param_diagnostics("uploaddiagnostic", "TotalBytesReceived");
	upload.total_bytes_sent = get_param_diagnostics("uploaddiagnostic", "TotalBytesSent");
	upload.test_bytes_sent_under_full_loading = get_param_diagnostics("uploaddiagnostic", "TestBytesSent");
	upload.total_bytes_received_under_full_loading = get_param_diagnostics("uploaddiagnostic", "TotalBytesReceived");
	upload.total_bytes_sent_under_full_loading = get_param_diagnostics("uploaddiagnostic", "TotalBytesSent");
	upload.period_of_full_loading = get_param_diagnostics("uploaddiagnostic", "PeriodOfFullLoading");
	upload.tcp_open_request_time = get_param_diagnostics("uploaddiagnostic", "TCPOpenRequestTimes");
	upload.tcp_open_response_time = get_param_diagnostics("uploaddiagnostic", "TCPOpenResponseTime");

	char *param_rom_time = dmstrdup("ROMTime");
	char *param_bom_time = dmstrdup("BOMTime");
	char *param_eom_time = dmstrdup("EOMTime");
	char *param_test_bytes_sent = dmstrdup("TestBytesSent");
	char *param_total_bytes_received = dmstrdup("TotalBytesReceived");
	char *param_total_bytes_sent = dmstrdup("TotalBytesSent");
	char *param_test_bytes_sent_under_full_loading = dmstrdup("TestBytesSentUnderFullLoading");
	char *param_total_bytes_received_under_full_loading = dmstrdup("TotalBytesReceivedUnderFullLoading");
	char *param_total_bytes_sent_under_full_loading = dmstrdup("TotalBytesSentUnderFullLoading");
	char *param_period_of_full_loading = dmstrdup("PeriodOfFullLoading");
	char *param_tcp_open_request_time = dmstrdup("TCPOpenRequestTime");
	char *param_tcp_open_response_time = dmstrdup("TCPOpenResponseTime");

	add_list_paramameter(dmctx, param_rom_time, upload.romtime, DMT_TYPE[DMT_TIME], NULL, 0);
	add_list_paramameter(dmctx, param_bom_time, upload.bomtime, DMT_TYPE[DMT_TIME], NULL, 0);
	add_list_paramameter(dmctx, param_eom_time, upload.eomtime, DMT_TYPE[DMT_TIME], NULL, 0);
	add_list_paramameter(dmctx, param_test_bytes_sent, upload.test_bytes_sent, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_total_bytes_received, upload.total_bytes_received, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_total_bytes_sent, upload.total_bytes_sent, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_test_bytes_sent_under_full_loading, upload.test_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_total_bytes_received_under_full_loading, upload.total_bytes_received_under_full_loading, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_total_bytes_sent_under_full_loading, upload.total_bytes_sent_under_full_loading, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_period_of_full_loading, upload.period_of_full_loading, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_tcp_open_request_time, upload.tcp_open_request_time, DMT_TYPE[DMT_TIME], NULL, 0);
	add_list_paramameter(dmctx, param_tcp_open_response_time, upload.tcp_open_response_time, DMT_TYPE[DMT_TIME], NULL, 0);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_udpecho(struct dmctx *dmctx, char *path, char *input)
{
	json_object *json_res = NULL;
	struct udpecho_diagnostics udpecho = {0};

	json_res = json_tokener_parse((const char *)input);
	udpecho.host = dmjson_get_value(json_res, 1, "Host");
	if(udpecho.host[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	udpecho.port = dmjson_get_value(json_res, 1, "Port");
	if(udpecho.port[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	udpecho.interface = dmjson_get_value(json_res, 1, "Interface");
	udpecho.proto = dmjson_get_value(json_res, 1, "ProtocolVersion");
	udpecho.nbofrepetition = dmjson_get_value(json_res, 1, "NumberOfRepetitions");
	udpecho.timeout = dmjson_get_value(json_res, 1, "Timeout");
	udpecho.datablocksize = dmjson_get_value(json_res, 1, "DataBlockSize");
	udpecho.dscp = dmjson_get_value(json_res, 1, "DSCP");
	udpecho.inter_transmission_time = dmjson_get_value(json_res, 1, "InterTransmissionTime");

	set_param_diagnostics("udpechodiagnostic", "Host", udpecho.host);
	set_param_diagnostics("udpechodiagnostic", "port", udpecho.port);
	set_param_diagnostics("udpechodiagnostic", "interface", udpecho.interface);
	set_param_diagnostics("udpechodiagnostic", "ProtocolVersion", udpecho.proto);
	set_param_diagnostics("udpechodiagnostic", "NumberOfRepetitions", udpecho.nbofrepetition);
	set_param_diagnostics("udpechodiagnostic", "Timeout", udpecho.timeout);
	set_param_diagnostics("udpechodiagnostic", "DataBlockSize", udpecho.datablocksize);
	set_param_diagnostics("udpechodiagnostic", "DSCP", udpecho.dscp);
	set_param_diagnostics("udpechodiagnostic", "InterTransmissionTime", udpecho.inter_transmission_time);

	//Free uci_varstate_ctx
	end_uci_varstate_ctx();

	dmcmd("/bin/sh", 3, UDPECHO_PATH, "run", "usp");

	//Allocate uci_varstate_ctx
	init_uci_varstate_ctx();

	udpecho.success_count = get_param_diagnostics("udpechodiagnostic", "SuccessCount");
	udpecho.failure_count = get_param_diagnostics("udpechodiagnostic", "FailureCount");
	udpecho.average_response_time = get_param_diagnostics("udpechodiagnostic", "AverageResponseTime");
	udpecho.minimum_response_time = get_param_diagnostics("udpechodiagnostic", "MinimumResponseTime");
	udpecho.maximum_response_time = get_param_diagnostics("udpechodiagnostic", "MaximumResponseTime");

	char *param_success_count = dmstrdup("SuccessCount");
	char *param_failure_count = dmstrdup("FailureCount");
	char *param_average_response_time = dmstrdup("AverageResponseTime");
	char *param_minimum_response_time = dmstrdup("MinimumResponseTime");
	char *param_maximum_response_time = dmstrdup("MaximumResponseTime");

	add_list_paramameter(dmctx, param_success_count, udpecho.success_count, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_failure_count, udpecho.failure_count, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_average_response_time, udpecho.average_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_minimum_response_time, udpecho.minimum_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_maximum_response_time, udpecho.maximum_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_serverselection(struct dmctx *dmctx, char *path, char *input)
{

	json_object *json_res = NULL;
	struct serverselection_diagnostics serverselection = {0};

	json_res = json_tokener_parse((const char *)input);
	serverselection.hostlist = dmjson_get_value(json_res, 1, "HostList");
	if(serverselection.hostlist[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	serverselection.port = dmjson_get_value(json_res, 1, "Port");
	serverselection.proto = dmjson_get_value(json_res, 1, "Protocol");
	if (strcmp(serverselection.proto, "ICMP")) {
		if(serverselection.port[0] == '\0')
			return UBUS_INVALID_ARGUMENTS;
	}
	serverselection.protocol_version = dmjson_get_value(json_res, 1, "ProtocolVersion");
	serverselection.interface = dmjson_get_value(json_res, 1, "Interface");
	serverselection.nbofrepetition = dmjson_get_value(json_res, 1, "NumberOfRepetitions");
	serverselection.timeout = dmjson_get_value(json_res, 1, "Timeout");

	set_param_diagnostics("serverselectiondiagnostic", "HostList", serverselection.hostlist);
	set_param_diagnostics("serverselectiondiagnostic", "interface", serverselection.interface);
	set_param_diagnostics("serverselectiondiagnostic", "ProtocolVersion", serverselection.protocol_version);
	set_param_diagnostics("serverselectiondiagnostic", "NumberOfRepetitions", serverselection.nbofrepetition);
	set_param_diagnostics("serverselectiondiagnostic", "port", serverselection.port);
	set_param_diagnostics("serverselectiondiagnostic", "Protocol", serverselection.proto);
	set_param_diagnostics("serverselectiondiagnostic", "Timeout", serverselection.timeout);

	//Free uci_varstate_ctx
	end_uci_varstate_ctx();

	dmcmd("/bin/sh", 3, SERVERSELECTION_PATH, "run", "usp");

	//Allocate uci_varstate_ctx
	init_uci_varstate_ctx();

	serverselection.fasthost = get_param_diagnostics("serverselectiondiagnostic", "FastestHost");
	serverselection.average_response_time = get_param_diagnostics("serverselectiondiagnostic", "AverageResponseTime");
	serverselection.minimum_response_time = get_param_diagnostics("serverselectiondiagnostic", "MinimumResponseTime");
	serverselection.maximum_response_time = get_param_diagnostics("serverselectiondiagnostic", "MaximumResponseTime");

	char *param_fastest_host = dmstrdup("FastestHost");
	char *param_average_response_time = dmstrdup("AverageResponseTime");
	char *param_minimum_response_time = dmstrdup("MinimumResponseTime");
	char *param_maximum_response_time = dmstrdup("MaximumResponseTime");

	add_list_paramameter(dmctx, param_fastest_host, serverselection.fasthost, DMT_TYPE[DMT_STRING], NULL, 0);
	add_list_paramameter(dmctx, param_average_response_time, serverselection.average_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_minimum_response_time, serverselection.minimum_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);
	add_list_paramameter(dmctx, param_maximum_response_time, serverselection.maximum_response_time, DMT_TYPE[DMT_UNINT], NULL, 0);

	return SUCCESS;
}

static opr_ret_t ip_diagnostics_nslookup(struct dmctx *dmctx, char *path, char *input)
{
	json_object *json_res = NULL;
	struct nslookup_diagnostics nslookup = {0};
	struct uci_section *s = NULL;
	char *status, *answertype, *hostname, *ipaddress, *dnsserverip, *responsetime;
	int i = 1;

	json_res = json_tokener_parse((const char *)input);
	nslookup.hostname = dmjson_get_value(json_res, 1, "HostName");
	if(nslookup.hostname[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	nslookup.interface = dmjson_get_value(json_res, 1, "Interface");
	nslookup.dnsserver = dmjson_get_value(json_res, 1, "DNSServer");
	nslookup.timeout = dmjson_get_value(json_res, 1, "Timeout");
	nslookup.nbofrepetition = dmjson_get_value(json_res, 1, "NumberOfRepetitions");

	set_param_diagnostics("nslookupdiagnostic", "HostName", nslookup.hostname);
	set_param_diagnostics("nslookupdiagnostic", "interface", nslookup.interface);
	set_param_diagnostics("nslookupdiagnostic", "DNSServer", nslookup.dnsserver);
	set_param_diagnostics("nslookupdiagnostic", "Timeout", nslookup.timeout);
	set_param_diagnostics("nslookupdiagnostic", "NumberOfRepetitions", nslookup.nbofrepetition);

	//Free uci_varstate_ctx
	end_uci_varstate_ctx();

	dmcmd("/bin/sh", 3, NSLOOKUP_PATH, "run", "usp");

	//Allocate uci_varstate_ctx
	init_uci_varstate_ctx();

	nslookup.success_count = get_param_diagnostics("nslookupdiagnostic", "SuccessCount");
	char *param_success_count = dmstrdup("SuccessCount");
	add_list_paramameter(dmctx, param_success_count, nslookup.success_count, DMT_TYPE[DMT_UNINT], NULL, 0);

	uci_foreach_sections_state("cwmp", "NSLookupResult", s)
	{
		dmasprintf(&status, "Result.%d.Status", i);
		dmasprintf(&answertype, "Result.%d.AnswerType", i);
		dmasprintf(&hostname, "Result.%d.HostNameReturned", i);
		dmasprintf(&ipaddress, "Result.%d.IPAddresses", i);
		dmasprintf(&dnsserverip, "Result.%d.DNSServerIP", i);
		dmasprintf(&responsetime, "Result.%d.ResponseTime", i);

		dmuci_get_value_by_section_string(s, "Status", &nslookup.status);
		dmuci_get_value_by_section_string(s, "AnswerType", &nslookup.answer_type);
		dmuci_get_value_by_section_string(s, "HostNameReturned", &nslookup.hostname_returned);
		dmuci_get_value_by_section_string(s, "IPAddresses", &nslookup.ip_addresses);
		dmuci_get_value_by_section_string(s, "DNSServerIP", &nslookup.dns_server_ip);
		dmuci_get_value_by_section_string(s, "ResponseTime", &nslookup.response_time);

		add_list_paramameter(dmctx, status, nslookup.status, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, answertype, nslookup.answer_type, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, hostname, nslookup.hostname_returned, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, ipaddress, nslookup.ip_addresses, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, dnsserverip, nslookup.dns_server_ip, DMT_TYPE[DMT_STRING], NULL, 0);
		add_list_paramameter(dmctx, responsetime, nslookup.response_time, DMT_TYPE[DMT_UNINT], NULL, 0);
		i++;
	}

	return SUCCESS;
}

static opr_ret_t swmodules_exec_env_reset(struct dmctx *dmctx, char *path, char *input)
{
	char *exec_env = get_param_val_from_op_cmd(path, "Name");
	if (exec_env) {
		if (strcmp(exec_env, "OpenWRT_Linux") == 0) {
			if (0 == dmcmd_no_wait("/sbin/defaultreset", 0))
				return SUCCESS;
			else
				return FAIL;
		}
	} else
		return FAIL;

	return SUCCESS;
}

static opr_ret_t swmodules_install_du(struct dmctx *dmctx, char *path, char *input)
{
	json_object *json_res = NULL, *res = NULL;
	struct deployment_unit_install du_install = {0};

	json_res = json_tokener_parse((const char *)input);
	du_install.url = dmjson_get_value(json_res, 1, "URL");
	if (du_install.url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	du_install.uuid = dmjson_get_value(json_res, 1, "UUID");
	du_install.username = dmjson_get_value(json_res, 1, "Username");
	du_install.password = dmjson_get_value(json_res, 1, "Password");
	du_install.environment = dmjson_get_value(json_res, 1, "ExecutionEnvRef");
	if (du_install.environment[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;

	char *exec_env = get_param_val_from_op_cmd(du_install.environment, "Name");
	if (!exec_env)
		return FAIL;

	dmubus_call("swmodules", "du_install",
			UBUS_ARGS{{"url", du_install.url},
					  {"uuid", du_install.uuid},
					  {"username", du_install.username},
					  {"password", du_install.password},
					  {"environment", exec_env}},
			5,
			&res);

	if (!res)
		return FAIL;

	char *status = dmjson_get_value(res, 1, "status");

	return (strcmp(status, "true") == 0) ? SUCCESS : FAIL;
}

static opr_ret_t swmodules_update_du(struct dmctx *dmctx, char *path, char *input)
{
	json_object *json_res = NULL, *res = NULL;
	struct deployment_unit_update du_update = {0};

	json_res = json_tokener_parse((const char *)input);
	du_update.url = dmjson_get_value(json_res, 1, "URL");
	if (du_update.url[0] == '\0')
		return UBUS_INVALID_ARGUMENTS;
	du_update.username = dmjson_get_value(json_res, 1, "Username");
	du_update.password = dmjson_get_value(json_res, 1, "Password");

	char *du_uuid = get_param_val_from_op_cmd(path, "UUID");
	if (!du_uuid)
		return FAIL;

	dmubus_call("swmodules", "du_update",
			UBUS_ARGS{{"uuid", du_uuid},
					  {"url", du_update.url},
					  {"username", du_update.username},
					  {"password", du_update.password}},
			4,
			&res);

	if (!res)
		return FAIL;

	char *status = dmjson_get_value(res, 1, "status");

	return (strcmp(status, "true") == 0) ? SUCCESS : FAIL;
}

static opr_ret_t swmodules_uninstall_du(struct dmctx *dmctx, char *path, char *input)
{
	json_object *res = NULL;

	char *du_name = get_param_val_from_op_cmd(path, "Name");
	if (!du_name)
		return FAIL;

	char *exec_env = get_param_val_from_op_cmd(path, "ExecutionEnvRef");
	if (!exec_env)
		return FAIL;

	char *env = get_param_val_from_op_cmd(exec_env, "Name");
	if (!env)
		return FAIL;

	dmubus_call("swmodules", "du_uninstall",
			UBUS_ARGS{{"name", du_name},
					  {"environment", env}},
			2,
			&res);

	if (!res)
		return FAIL;

	char *status = dmjson_get_value(res, 1, "status");

	return (strcmp(status, "true") == 0) ? SUCCESS : FAIL;

}

static int get_index_of_available_dynamic_operate(struct op_cmd *operate)
{
	int idx = 0;
	for (; (operate && operate->name); operate++) {
		idx++;
	}
	return idx;
}

int add_dynamic_operate(char *path, operation operate, char *type)
{
	if (dynamic_operate == NULL) {
		dynamic_operate = calloc(2, sizeof(struct op_cmd));
		dynamic_operate[0].name = path;
		dynamic_operate[0].opt = operate;
		dynamic_operate[0].type = type;
	} else {
		int idx = get_index_of_available_dynamic_operate(dynamic_operate);
		struct op_cmd *new_dynamic_operate = realloc(dynamic_operate, (idx + 2) * sizeof(struct op_cmd));
		if (new_dynamic_operate == NULL)
			FREE(dynamic_operate);
		else
			dynamic_operate = new_dynamic_operate;
		memset(dynamic_operate + (idx + 1), 0, sizeof(struct op_cmd));
		dynamic_operate[idx].name = path;
		dynamic_operate[idx].opt = operate;
		dynamic_operate[idx].type = type;
	}
	return 0;
}

static struct op_cmd operate_helper[] = {
	{"Device.Reboot", reboot_device, "sync"},
	{"Device.FactoryReset", factory_reset, "sync"},
	{"Device.IP.Interface.*.Reset", network_interface_reset, "sync"},
	{"Device.PPP.Interface.*.Reset", network_interface_reset, "sync"},
	{"Device.WiFi.Reset", wireless_reset, "sync"},
	{"Device.WiFi.AccessPoint.*.Security.Reset", ap_security_reset, "sync"},
	{"Device.DHCPv4.Client.*.Renew", dhcp_client_renew, "sync"},
	{"Device.DHCPv6.Client.*.Renew", dhcp_client_renew, "sync"},
	{"Device.DeviceInfo.VendorConfigFile.*.Backup", vendor_conf_backup, "async"},
	{"Device.DeviceInfo.VendorConfigFile.*.Restore", vendor_conf_restore, "async"},
	{"Device.WiFi.NeighboringWiFiDiagnostic", fetch_neighboring_wifi_diagnostic, "async"},
	//{"Device.DeviceInfo.VendorLogFile.*.Upload", blob_parser},
	{"Device.IP.Diagnostics.IPPing", ip_diagnostics_ipping, "async"},
	{"Device.IP.Diagnostics.TraceRoute", ip_diagnostics_traceroute, "async"},
	{"Device.IP.Diagnostics.DownloadDiagnostics", ip_diagnostics_download, "async"},
	{"Device.IP.Diagnostics.UploadDiagnostics", ip_diagnostics_upload, "async"},
	{"Device.IP.Diagnostics.UDPEchoDiagnostics", ip_diagnostics_udpecho, "async"},
	{"Device.IP.Diagnostics.ServerSelectionDiagnostics", ip_diagnostics_serverselection, "async"},
	{"Device.DNS.Diagnostics.NSLookupDiagnostics", ip_diagnostics_nslookup, "async"},
	{"Device.SoftwareModules.ExecEnv.*.Reset", swmodules_exec_env_reset, "sync"},
	{"Device.SoftwareModules.InstallDU", swmodules_install_du, "async"},
	{"Device.SoftwareModules.DeploymentUnit.*.Update", swmodules_update_du, "async"},
	{"Device.SoftwareModules.DeploymentUnit.*.Uninstall", swmodules_uninstall_du, "async"}
};

void operate_list_cmds(struct dmctx *dmctx)
{
	char *param, *type;
	uint8_t len = 0, i;
	struct op_cmd *save_pointer = NULL;
	if (dynamic_operate) save_pointer = dynamic_operate;

	len = ARRAY_SIZE(operate_helper);
	for(i = 0; i < len; i++) {
		param = dmstrdup(operate_helper[i].name);
		type = operate_helper[i].type;
		add_list_paramameter(dmctx, param, NULL, type, NULL, 0);
	}

	for (; (dynamic_operate && dynamic_operate->name); dynamic_operate++) {
		param = dmstrdup(dynamic_operate->name);
		type = dynamic_operate->type;
		add_list_paramameter(dmctx, param, NULL, type, NULL, 0);
	}
	if (save_pointer) dynamic_operate = save_pointer;
}
opr_ret_t operate_on_node(struct dmctx *dmctx, char *path, char *input)
{
	uint8_t len = 0, i;
	struct op_cmd *save_pointer = NULL;
	if (dynamic_operate) save_pointer = dynamic_operate;

	len = ARRAY_SIZE(operate_helper);
	for(i = 0; i < len; i++) {
		if (match(path, operate_helper[i].name))
			return(operate_helper[i].opt(dmctx, path, input));
	}

	for (; (dynamic_operate && dynamic_operate->name); dynamic_operate++) {
		if (match(path, dynamic_operate->name)) {
			opr_ret_t res = dynamic_operate->opt(dmctx, path, input);
			if (save_pointer) dynamic_operate = save_pointer;
			return res;
		}
	}
	if (save_pointer) dynamic_operate = save_pointer;

	return CMD_NOT_FOUND;
}
