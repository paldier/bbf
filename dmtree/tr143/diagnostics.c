/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "diagnostics.h"

static int get_diag_enable_true(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*
 * *** Device.IP.Diagnostics.IPPing. ***
 */

static inline char *ipping_get(char *option, char *def)
{
	char *tmp;
	dmuci_get_varstate_string("cwmp", "@ippingdiagnostic[0]", option, &tmp);
	if(tmp && tmp[0] == '\0')
		return dmstrdup(def);
	else
		return tmp;
}

static int get_ip_ping_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("DiagnosticState", "None");
	return 0;
}

static int set_ip_ping_diagnostics_state(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				IPPING_STOP
				curr_section = dmuci_walk_state_section("cwmp", "ippingdiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
				if (!curr_section)
					dmuci_add_state_section("cwmp", "ippingdiagnostic", &curr_section, &tmp);
				dmuci_set_varstate_value("cwmp", "@ippingdiagnostic[0]", "DiagnosticState", value);
				cwmp_set_end_session(END_SESSION_IPPING_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_ip_ping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@ippingdiagnostic[0]", "interface", value);
	return 0;
}

static int set_ip_ping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			curr_section = dmuci_walk_state_section("cwmp", "ippingdiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "ippingdiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@ippingdiagnostic[0]", "interface", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_protocolversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("ProtocolVersion", "Any");
	return 0;
}

static int set_ip_ping_protocolversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			curr_section = dmuci_walk_state_section("cwmp", "ippingdiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "ippingdiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@ippingdiagnostic[0]", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@ippingdiagnostic[0]", "Host", value);
	return 0;
}

static int set_ip_ping_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			curr_section = dmuci_walk_state_section("cwmp", "ippingdiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "ippingdiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@ippingdiagnostic[0]", "Host", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_repetition_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("NumberOfRepetitions", "3");
	return 0;
}

static int set_ip_ping_repetition_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			curr_section = dmuci_walk_state_section("cwmp", "ippingdiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "ippingdiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@ippingdiagnostic[0]", "NumberOfRepetitions", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("Timeout", "1000");
	return 0;
}

static int set_ip_ping_timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			curr_section = dmuci_walk_state_section("cwmp", "ippingdiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "ippingdiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@ippingdiagnostic[0]", "Timeout", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_block_size(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("DataBlockSize", "64");

	return 0;
}

static int set_ip_ping_block_size(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			IPPING_STOP
			curr_section = dmuci_walk_state_section("cwmp", "ippingdiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "ippingdiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@ippingdiagnostic[0]", "DataBlockSize", value);
	}
	return 0;
}

static int get_ip_ping_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("DSCP", "0");
	return 0;
}

static int set_ip_ping_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "ippingdiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "ippingdiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@ippingdiagnostic[0]", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_ip_ping_success_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("SuccessCount", "0");
	return 0;
}

static int get_ip_ping_failure_count(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("FailureCount", "0");
	return 0;
}

static int get_ip_ping_average_response_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("AverageResponseTime", "0");
	return 0;
}

static int get_ip_ping_min_response_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("MinimumResponseTime", "0");
	return 0;
}

static int get_ip_ping_max_response_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("MaximumResponseTime", "0");
	return 0;
}

static int get_ip_ping_AverageResponseTimeDetailed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("AverageResponseTimeDetailed", "0");
	return 0;
}

static int get_ip_ping_MinimumResponseTimeDetailed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("MinimumResponseTimeDetailed", "0");
	return 0;
}

static int get_ip_ping_MaximumResponseTimeDetailed(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = ipping_get("MaximumResponseTimeDetailed", "0");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.TraceRoute. ***
 */

static inline char *traceroute_get(char *option, char *def)
{
	char *tmp;
	dmuci_get_varstate_string("cwmp", "@traceroutediagnostic[0]", option, &tmp);
	if(tmp && tmp[0] == '\0')
		return dmstrdup(def);
	else
		return tmp;
}

static int get_IPDiagnosticsTraceRoute_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				TRACEROUTE_STOP
				curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
				if (!curr_section)
					dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
				dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "DiagnosticState", value);
				cwmp_set_end_session(END_SESSION_TRACEROUTE_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@traceroutediagnostic[0]", "interface", value);
	return 0;
}

static int set_IPDiagnosticsTraceRoute_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "interface", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@traceroutediagnostic[0]", "Host", value);
	return 0;
}

static int set_IPDiagnosticsTraceRoute_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "Host", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_NumberOfTries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("NumberOfTries", "3");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_NumberOfTries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","3"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "NumberOfTries", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("Timeout", "5000");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "Timeout", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_DataBlockSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("DataBlockSize", "38");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_DataBlockSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "DataBlockSize", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("DSCP", "0");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_MaxHopCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("MaxHops", "30");
	return 0;
}

static int set_IPDiagnosticsTraceRoute_MaxHopCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","64"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			TRACEROUTE_STOP
			curr_section = dmuci_walk_state_section("cwmp", "traceroutediagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "traceroutediagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@traceroutediagnostic[0]", "MaxHops", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsTraceRoute_ResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("ResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsTraceRoute_RouteHopsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = traceroute_get("NumberOfHops", "0");
	return 0;
}

static int get_IPDiagnosticsTraceRouteRouteHops_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "host", value);
	return 0;
}

static int get_IPDiagnosticsTraceRouteRouteHops_HostAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ip", value);
	return 0;
}

static int get_IPDiagnosticsTraceRouteRouteHops_ErrorCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int get_IPDiagnosticsTraceRouteRouteHops_RTTimes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "time", value);
	return 0;
}

/*
 * *** Device.IP.Diagnostics.DownloadDiagnostics. ***
 */

static inline char *download_get(char *option, char *def)
{
	char *tmp;
	dmuci_get_varstate_string("cwmp", "@downloaddiagnostic[0]", option, &tmp);
	if(tmp && tmp[0] == '\0')
		return dmstrdup(def);
	else
		return tmp;
}

static int get_IPDiagnosticsDownloadDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				DOWNLOAD_DIAGNOSTIC_STOP
				curr_section = dmuci_walk_state_section("cwmp", "downloaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
				if (!curr_section)
					dmuci_add_state_section("cwmp", "downloaddiagnostic", &curr_section, &tmp);
				dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "DiagnosticState", value);
				cwmp_set_end_session(END_SESSION_DOWNLOAD_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;
	dmuci_get_varstate_string("cwmp", "@downloaddiagnostic[0]", "interface", &linker);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL, *tmp, *device = NULL;
	struct uci_section *curr_section = NULL;
	json_object *res;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", linker, String}}, 1, &res);
				if (!res) return 0;
				device = dmjson_get_value(res, 1, "device");
				if (device) {
					DOWNLOAD_DIAGNOSTIC_STOP
					curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "downloaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
					if (!curr_section)
						dmuci_add_state_section("cwmp", "downloaddiagnostic", &curr_section, &tmp);
					dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "interface", linker);
					dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "device", device);
				}
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_DownloadURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@downloaddiagnostic[0]", "url", value);
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_DownloadURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "downloaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "downloaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "url", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_DownloadTransports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,FTP";
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_DownloadDiagnosticMaxConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("DSCP", "0");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "downloaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "downloaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_EthernetPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("ethernetpriority", "");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_EthernetPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "downloaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "downloaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "ethernetpriority", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "downloaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "downloaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_NumberOfConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("NumberOfConnections", "1");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_NumberOfConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "downloaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "downloaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "NumberOfConnections", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("ROMtime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("BOMtime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("EOMtime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TestBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TestBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TotalBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TestBytesReceivedUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TestBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceivedUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TotalBytesSentUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_PeriodOfFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("PeriodOfFullLoading", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TCPOpenRequestTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TCPOpenRequestTime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TCPOpenResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_PerConnectionResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp;
	bool b;
	dmuci_get_varstate_string("cwmp", "@downloaddiagnostic[0]", "EnablePerConnection", &tmp);
	string_to_bool(tmp, &b);
	*value = (b) ? "1" : "0";
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("EnablePerConnection", "0");
	return 0;
}

static int set_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			DOWNLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "downloaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "downloaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@downloaddiagnostic[0]", "EnablePerConnection", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("ROMtime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("BOMtime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("EOMtime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TestBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TestBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "TotalBytesReceived", value);
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "TotalBytesSent", value);
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenRequestTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TCPOpenRequestTime", "0");
	return 0;
}

static int get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = download_get("TCPOpenResponseTime", "0");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.UploadDiagnostics. ***
 */

static inline char *upload_get(char *option, char *def)
{
	char *tmp;
	dmuci_get_varstate_string("cwmp", "@uploaddiagnostic[0]", option, &tmp);
	if(tmp && tmp[0] == '\0')
		return dmstrdup(def);
	else
		return tmp;
}

static int get_IPDiagnosticsUploadDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				UPLOAD_DIAGNOSTIC_STOP
				curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
				if (!curr_section)
					dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
				dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "DiagnosticState", value);
				cwmp_set_end_session(END_SESSION_UPLOAD_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;
	dmuci_get_varstate_string("cwmp", "@uploaddiagnostic[0]", "interface", &linker);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL, *tmp, *device = NULL;
	struct uci_section *curr_section = NULL;
	json_object *res;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", linker, String}}, 1, &res);
				if (!res) return 0;
				device = dmjson_get_value(res, 1, "device");
				if (device) {
					UPLOAD_DIAGNOSTIC_STOP
					curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
					if (!curr_section)
						dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
					dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "interface", linker);
					dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "device", device);
				}
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_UploadURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@uploaddiagnostic[0]", "url", value);
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_UploadURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "url", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_UploadTransports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,FTP";
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("DSCP", "0");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_EthernetPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("ethernetpriority", "0");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_EthernetPriority(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","7"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "ethernetpriority", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TestFileLength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TestFileLength", "0");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_TestFileLength(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "TestFileLength", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_NumberOfConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("NumberOfConnections", "1");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_NumberOfConnections(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "NumberOfConnections", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("ROMtime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("BOMtime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("EOMtime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TestBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TestBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TotalBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TotalBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TestBytesSentUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TestBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TotalBytesReceivedUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TotalBytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TotalBytesSentUnderFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TotalBytesSent", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_PeriodOfFullLoading(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("PeriodOfFullLoading", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TCPOpenRequestTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TCPOpenRequestTime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TCPOpenResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_PerConnectionResultNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp;
	bool b;
	dmuci_get_varstate_string("cwmp", "@uploaddiagnostic[0]", "EnablePerConnection", &tmp);
	string_to_bool(tmp, &b);
	*value = (b) ? "1" : "0";
	return 0;
}

static int get_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("EnablePerConnection", "0");
	return 0;
}

static int set_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UPLOAD_DIAGNOSTIC_STOP
			curr_section = (struct uci_section *)dmuci_walk_state_section("cwmp", "uploaddiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "uploaddiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@uploaddiagnostic[0]", "EnablePerConnection", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_ROMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("ROMtime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_BOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("BOMtime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_EOMTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("EOMtime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TestBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "TestBytesSent", value);
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "TotalBytesReceived", value);
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "TotalBytesSent", value);
	return 0;

}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenRequestTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TCPOpenRequestTime", "0");
	return 0;
}

static int get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = upload_get("TCPOpenResponseTime", "0");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.UDPEchoConfig. ***
 */

static int get_IPDiagnosticsUDPEchoConfig_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_udpechoserver", "udpechoserver", "enable", value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoConfig_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char file[32] = "/var/state/cwmp_udpechoserver";

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b) {
				if( access( file, F_OK ) != -1 )
					dmcmd("/bin/rm", 1, file);
				dmuci_set_value("cwmp_udpechoserver", "udpechoserver", "enable", "1");
			} else
				dmuci_set_value("cwmp_udpechoserver", "udpechoserver", "enable", "0");
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_udpechoserver", "udpechoserver", "interface", value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoConfig_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_udpechoserver", "udpechoserver", "interface", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_SourceIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_udpechoserver", "udpechoserver", "address", value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoConfig_SourceIPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_udpechoserver", "udpechoserver", "address", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_UDPPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_udpechoserver", "udpechoserver", "server_port", value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoConfig_UDPPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_udpechoserver", "udpechoserver", "server_port", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_EchoPlusEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_udpechoserver", "udpechoserver", "plus", value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoConfig_EchoPlusEnabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("cwmp_udpechoserver", "udpechoserver", "plus", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_EchoPlusSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static inline char *udpechoconfig_get(char *option, char *def)
{
	char *tmp;
	dmuci_get_varstate_string("cwmp_udpechoserver", "udpechoserver", option, &tmp);
	if(tmp && tmp[0] == '\0')
		return dmstrdup(def);
	else
		return tmp;
}

static int get_IPDiagnosticsUDPEchoConfig_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechoconfig_get("PacketsReceived", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_PacketsResponded(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechoconfig_get("PacketsResponded", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechoconfig_get("BytesReceived", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_BytesResponded(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechoconfig_get("BytesResponded", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_TimeFirstPacketReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechoconfig_get("TimeFirstPacketReceived", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoConfig_TimeLastPacketReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechoconfig_get("TimeLastPacketReceived", "0");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.UDPEchoDiagnostics. ***
 */

static inline char *udpechodiagnostics_get(char *option, char *def)
{
	char *tmp;
	dmuci_get_varstate_string("cwmp", "@udpechodiagnostic[0]", option, &tmp);
	if(tmp && tmp[0] == '\0')
		return dmstrdup(def);
	else
		return tmp;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				UDPECHO_STOP;
				curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
				if (!curr_section)
					dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
				dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "DiagnosticState", value);
				cwmp_set_end_session(END_SESSION_UDPECHO_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@udpechodiagnostic[0]", "Interface", value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "Interface", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@udpechodiagnostic[0]", "Host", value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "Host", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@udpechodiagnostic[0]", "port", value);
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "port", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("NumberOfRepetitions", "1");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "NumberOfRepetitions", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("Timeout", "5000");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "Timeout", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("DataBlockSize", "24");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "DataBlockSize", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("DSCP", "0");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_DSCP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","63"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "DSCP", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("InterTransmissionTime", "1000");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "InterTransmissionTime", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			UDPECHO_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "udpechodiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "udpechodiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@udpechodiagnostic[0]", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_SuccessCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("SuccessCount", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_FailureCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("FailureCount", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_AverageResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("AverageResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_MinimumResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("MinimumResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsUDPEchoDiagnostics_MaximumResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = udpechodiagnostics_get("MaximumResponseTime", "0");
	return 0;
}

/*
 * *** Device.IP.Diagnostics.ServerSelectionDiagnostics. ***
 */

static inline char *serverselection_get(char *option, char *def)
{
	char *tmp;
	dmuci_get_varstate_string("cwmp", "@serverselectiondiagnostic[0]", option, &tmp);
	if(tmp && tmp[0] == '\0')
		return dmstrdup(def);
	else
		return tmp;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("DiagnosticState", "None");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DiagnosticsState, 5, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				SERVERSELECTION_STOP
				curr_section = dmuci_walk_state_section("cwmp", "serverselectiondiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
				if (!curr_section)
					dmuci_add_state_section("cwmp", "serverselectiondiagnostic", &curr_section, &tmp);
				dmuci_set_varstate_value("cwmp", "@serverselectiondiagnostic[0]", "DiagnosticState", value);
				cwmp_set_end_session(END_SESSION_SERVERSELECTION_DIAGNOSTIC);
			}
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@serverselectiondiagnostic[0]", "interface", value);
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			curr_section = dmuci_walk_state_section("cwmp", "serverselectiondiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "serverselectiondiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@serverselectiondiagnostic[0]", "interface", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("ProtocolVersion", "Any");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ProtocolVersion, 3, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			curr_section = dmuci_walk_state_section("cwmp", "serverselectiondiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "serverselectiondiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@serverselectiondiagnostic[0]", "ProtocolVersion", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("Protocol", "ICMP");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ServerSelectionProtocol, 2, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			curr_section = dmuci_walk_state_section("cwmp", "serverselectiondiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "serverselectiondiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@serverselectiondiagnostic[0]", "Protocol", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("port", "1");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP;
			curr_section = dmuci_walk_state_section("cwmp", "serverselectiondiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "serverselectiondiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@serverselectiondiagnostic[0]", "port", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_HostList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp", "@serverselectiondiagnostic[0]", "HostList", value);
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_HostList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 10, -1, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			curr_section = dmuci_walk_state_section("cwmp", "serverselectiondiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "serverselectiondiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@serverselectiondiagnostic[0]", "HostList", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("NumberOfRepetitions", "3");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			curr_section = dmuci_walk_state_section("cwmp", "serverselectiondiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "serverselectiondiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@serverselectiondiagnostic[0]", "NumberOfRepetitions", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("Timeout", "1000");
	return 0;
}

static int set_IPDiagnosticsServerSelectionDiagnostics_Timeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			SERVERSELECTION_STOP
			curr_section = dmuci_walk_state_section("cwmp", "serverselectiondiagnostic", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
			if (!curr_section)
				dmuci_add_state_section("cwmp", "serverselectiondiagnostic", &curr_section, &tmp);
			dmuci_set_varstate_value("cwmp", "@serverselectiondiagnostic[0]", "Timeout", value);
			return 0;
	}
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_FastestHost(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("FastestHost", "");
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_MinimumResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("MinimumResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_AverageResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("AverageResponseTime", "0");
	return 0;
}

static int get_IPDiagnosticsServerSelectionDiagnostics_MaximumResponseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = serverselection_get("MaximumResponseTime", "0");
	return 0;
}

static int browseIPDiagnosticsTraceRouteRouteHopsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *instance, *idx_last = NULL;

	uci_foreach_sections_state("cwmp", "RouteHops", s) {
		instance = handle_update_instance(2, dmctx, &idx_last, update_instance_alias, 3, (void *)s, "routehop_instance", "routehop_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, instance) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIPDiagnosticsDownloadDiagnosticsPerConnectionResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *instance, *idx_last = NULL;

	uci_foreach_sections_state("cwmp", "DownloadPerConnection", s) {
		instance = handle_update_instance(2, dmctx, &idx_last, update_instance_alias, 3, (void *)s, "perconnection_instance", "perconnection_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, instance) == DM_STOP)
			break;
	}
	return 0;
}

static int browseIPDiagnosticsUploadDiagnosticsPerConnectionResultInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL;
	char *instance, *idx_last = NULL;

	uci_foreach_sections_state("cwmp", "UploadPerConnection", s) {
		instance = handle_update_instance(2, dmctx, &idx_last, update_instance_alias, 3, (void *)s, "perconnection_instance", "perconnection_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, instance) == DM_STOP)
			break;
	}
	return 0;
}

/* *** Device.IP.Diagnostics. *** */
DMOBJ tIPDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"IPPing", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsIPPingParams, NULL, BBFDM_CWMP},
{"TraceRoute", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsTraceRouteObj, tIPDiagnosticsTraceRouteParams, NULL, BBFDM_CWMP},
{"DownloadDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsDownloadDiagnosticsObj, tIPDiagnosticsDownloadDiagnosticsParams, NULL, BBFDM_CWMP},
{"UploadDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsUploadDiagnosticsObj, tIPDiagnosticsUploadDiagnosticsParams, NULL, BBFDM_CWMP},
{"UDPEchoConfig", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsUDPEchoConfigParams, NULL, BBFDM_BOTH},
{"UDPEchoDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsUDPEchoDiagnosticsParams, NULL, BBFDM_CWMP},
{"ServerSelectionDiagnostics", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tIPDiagnosticsServerSelectionDiagnosticsParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IPv4PingSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6PingSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4TraceRouteSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6TraceRouteSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4DownloadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6DownloadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4UploadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6UploadDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4UDPEchoDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6UDPEchoDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv4ServerSelectionDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6ServerSelectionDiagnosticsSupported", &DMREAD, DMT_BOOL, get_diag_enable_true, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Diagnostics.IPPing. *** */
DMLEAF tIPDiagnosticsIPPingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_ip_ping_diagnostics_state, set_ip_ping_diagnostics_state, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_ip_ping_interface, set_ip_ping_interface, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_ip_ping_protocolversion, set_ip_ping_protocolversion, NULL, NULL, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_ip_ping_host, set_ip_ping_host, NULL, NULL, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_ip_ping_repetition_number, set_ip_ping_repetition_number, NULL, NULL, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_ip_ping_timeout, set_ip_ping_timeout, NULL, NULL, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_ip_ping_block_size, set_ip_ping_block_size, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_ip_ping_DSCP, set_ip_ping_DSCP, NULL, NULL, BBFDM_CWMP},
{"SuccessCount", &DMREAD, DMT_UNINT, get_ip_ping_success_count, NULL, NULL, NULL, BBFDM_CWMP},
{"FailureCount", &DMREAD, DMT_UNINT, get_ip_ping_failure_count, NULL, NULL, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_average_response_time, NULL, NULL, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_min_response_time, NULL, NULL, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_ip_ping_max_response_time, NULL, NULL, NULL, BBFDM_CWMP},
{"AverageResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_AverageResponseTimeDetailed, NULL, NULL, NULL, BBFDM_CWMP},
{"MinimumResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_MinimumResponseTimeDetailed, NULL, NULL, NULL, BBFDM_CWMP},
{"MaximumResponseTimeDetailed", &DMREAD, DMT_UNINT, get_ip_ping_MaximumResponseTimeDetailed, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.TraceRoute. *** */
DMOBJ tIPDiagnosticsTraceRouteObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"RouteHops", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsTraceRouteRouteHopsInst, NULL, NULL, NULL, NULL, tIPDiagnosticsTraceRouteRouteHopsParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsTraceRouteParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_DiagnosticsState, set_IPDiagnosticsTraceRoute_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_Interface, set_IPDiagnosticsTraceRoute_Interface, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_ProtocolVersion, set_IPDiagnosticsTraceRoute_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_IPDiagnosticsTraceRoute_Host, set_IPDiagnosticsTraceRoute_Host, NULL, NULL, BBFDM_CWMP},
{"NumberOfTries", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_NumberOfTries, set_IPDiagnosticsTraceRoute_NumberOfTries, NULL, NULL, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_Timeout, set_IPDiagnosticsTraceRoute_Timeout, NULL, NULL, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_DataBlockSize, set_IPDiagnosticsTraceRoute_DataBlockSize, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_DSCP, set_IPDiagnosticsTraceRoute_DSCP, NULL, NULL, BBFDM_CWMP},
{"MaxHopCount", &DMWRITE, DMT_UNINT, get_IPDiagnosticsTraceRoute_MaxHopCount, set_IPDiagnosticsTraceRoute_MaxHopCount, NULL, NULL, BBFDM_CWMP},
{"ResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRoute_ResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"RouteHopsNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRoute_RouteHopsNumberOfEntries, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.TraceRoute.RouteHops.{i}. *** */
DMLEAF tIPDiagnosticsTraceRouteRouteHopsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Host", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_Host, NULL, NULL, NULL, BBFDM_CWMP},
{"HostAddress", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_HostAddress, NULL, NULL, NULL, BBFDM_CWMP},
{"ErrorCode", &DMREAD, DMT_UNINT, get_IPDiagnosticsTraceRouteRouteHops_ErrorCode, NULL, NULL, NULL, BBFDM_CWMP},
{"RTTimes", &DMREAD, DMT_STRING, get_IPDiagnosticsTraceRouteRouteHops_RTTimes, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.DownloadDiagnostics. *** */
DMOBJ tIPDiagnosticsDownloadDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"PerConnectionResult", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsDownloadDiagnosticsPerConnectionResultInst, NULL, NULL, NULL, NULL, tIPDiagnosticsDownloadDiagnosticsPerConnectionResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsDownloadDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DiagnosticsState, set_IPDiagnosticsDownloadDiagnostics_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_Interface, set_IPDiagnosticsDownloadDiagnostics_Interface, NULL, NULL, BBFDM_CWMP},
{"DownloadURL", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DownloadURL, set_IPDiagnosticsDownloadDiagnostics_DownloadURL, NULL, NULL, BBFDM_CWMP},
{"DownloadTransports", &DMREAD, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_DownloadTransports, NULL, NULL, NULL, BBFDM_CWMP},
{"DownloadDiagnosticMaxConnections", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_DownloadDiagnosticMaxConnections, NULL, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_DSCP, set_IPDiagnosticsDownloadDiagnostics_DSCP, NULL, NULL, BBFDM_CWMP},
{"EthernetPriority", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_EthernetPriority, set_IPDiagnosticsDownloadDiagnostics_EthernetPriority, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsDownloadDiagnostics_ProtocolVersion, set_IPDiagnosticsDownloadDiagnostics_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"NumberOfConnections", &DMWRITE, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_NumberOfConnections, set_IPDiagnosticsDownloadDiagnostics_NumberOfConnections, NULL, NULL, BBFDM_CWMP},
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_ROMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_BOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_EOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TestBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TestBytesReceivedUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesReceivedUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_TotalBytesSentUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"PeriodOfFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_PeriodOfFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_TCPOpenRequestTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnostics_TCPOpenResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"PerConnectionResultNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnostics_PerConnectionResultNumberOfEntries, NULL, NULL, NULL, BBFDM_CWMP},
{"EnablePerConnectionResults", &DMWRITE, DMT_BOOL, get_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults, set_IPDiagnosticsDownloadDiagnostics_EnablePerConnectionResults, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.DownloadDiagnostics.PerConnectionResult.{i}. *** */
DMLEAF tIPDiagnosticsDownloadDiagnosticsPerConnectionResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_ROMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_BOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_EOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TestBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TotalBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenRequestTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsDownloadDiagnosticsPerConnectionResult_TCPOpenResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UploadDiagnostics. *** */
DMOBJ tIPDiagnosticsUploadDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"PerConnectionResult", &DMREAD, NULL, NULL, NULL, browseIPDiagnosticsUploadDiagnosticsPerConnectionResultInst, NULL, NULL, NULL, NULL, tIPDiagnosticsUploadDiagnosticsPerConnectionResultParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tIPDiagnosticsUploadDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_DiagnosticsState, set_IPDiagnosticsUploadDiagnostics_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_Interface, set_IPDiagnosticsUploadDiagnostics_Interface, NULL, NULL, BBFDM_CWMP},
{"UploadURL", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_UploadURL, set_IPDiagnosticsUploadDiagnostics_UploadURL, NULL, NULL, BBFDM_CWMP},
{"UploadTransports", &DMREAD, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_UploadTransports, NULL, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_DSCP, set_IPDiagnosticsUploadDiagnostics_DSCP, NULL, NULL, BBFDM_CWMP},
{"EthernetPriority", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_EthernetPriority, set_IPDiagnosticsUploadDiagnostics_EthernetPriority, NULL, NULL, BBFDM_CWMP},
{"TestFileLength", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestFileLength, set_IPDiagnosticsUploadDiagnostics_TestFileLength, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsUploadDiagnostics_ProtocolVersion, set_IPDiagnosticsUploadDiagnostics_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"NumberOfConnections", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_NumberOfConnections, set_IPDiagnosticsUploadDiagnostics_NumberOfConnections, NULL, NULL, BBFDM_CWMP},
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_ROMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_BOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_EOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TestBytesSentUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceivedUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesReceivedUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSentUnderFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_TotalBytesSentUnderFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"PeriodOfFullLoading", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_PeriodOfFullLoading, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_TCPOpenRequestTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnostics_TCPOpenResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"PerConnectionResultNumberOfEntries", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnostics_PerConnectionResultNumberOfEntries, NULL, NULL, NULL, BBFDM_CWMP},
{"EnablePerConnectionResults", &DMWRITE, DMT_BOOL, get_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults, set_IPDiagnosticsUploadDiagnostics_EnablePerConnectionResults, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UploadDiagnostics.PerConnectionResult.{i}. *** */
DMLEAF tIPDiagnosticsUploadDiagnosticsPerConnectionResultParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ROMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_ROMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"BOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_BOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"EOMTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_EOMTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TestBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TestBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesReceived, NULL, NULL, NULL, BBFDM_CWMP},
{"TotalBytesSent", &DMREAD, DMT_UNINT, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TotalBytesSent, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenRequestTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenRequestTime, NULL, NULL, NULL, BBFDM_CWMP},
{"TCPOpenResponseTime", &DMREAD, DMT_TIME, get_IPDiagnosticsUploadDiagnosticsPerConnectionResult_TCPOpenResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.UDPEchoConfig. *** */
DMLEAF tIPDiagnosticsUDPEchoConfigParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_IPDiagnosticsUDPEchoConfig_Enable, set_IPDiagnosticsUDPEchoConfig_Enable, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoConfig_Interface, set_IPDiagnosticsUDPEchoConfig_Interface, NULL, NULL, BBFDM_BOTH},
{"SourceIPAddress", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoConfig_SourceIPAddress, set_IPDiagnosticsUDPEchoConfig_SourceIPAddress, NULL, NULL, BBFDM_BOTH},
{"UDPPort", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoConfig_UDPPort, set_IPDiagnosticsUDPEchoConfig_UDPPort, NULL, NULL, BBFDM_BOTH},
{"EchoPlusEnabled", &DMWRITE, DMT_BOOL, get_IPDiagnosticsUDPEchoConfig_EchoPlusEnabled, set_IPDiagnosticsUDPEchoConfig_EchoPlusEnabled, NULL, NULL, BBFDM_BOTH},
{"EchoPlusSupported", &DMREAD, DMT_BOOL, get_IPDiagnosticsUDPEchoConfig_EchoPlusSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoConfig_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsResponded", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoConfig_PacketsResponded, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoConfig_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesResponded", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoConfig_BytesResponded, NULL, NULL, NULL, BBFDM_BOTH},
{"TimeFirstPacketReceived", &DMREAD, DMT_TIME, get_IPDiagnosticsUDPEchoConfig_TimeFirstPacketReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"TimeLastPacketReceived", &DMREAD, DMT_TIME, get_IPDiagnosticsUDPEchoConfig_TimeLastPacketReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Diagnostics.UDPEchoDiagnostics. *** */
DMLEAF tIPDiagnosticsUDPEchoDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState, set_IPDiagnosticsUDPEchoDiagnostics_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_Interface, set_IPDiagnosticsUDPEchoDiagnostics_Interface, NULL, NULL, BBFDM_CWMP},
{"Host", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_Host, set_IPDiagnosticsUDPEchoDiagnostics_Host, NULL, NULL, BBFDM_CWMP},
{"Port", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_Port, set_IPDiagnosticsUDPEchoDiagnostics_Port, NULL, NULL, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions, set_IPDiagnosticsUDPEchoDiagnostics_NumberOfRepetitions, NULL, NULL, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_Timeout, set_IPDiagnosticsUDPEchoDiagnostics_Timeout, NULL, NULL, BBFDM_CWMP},
{"DataBlockSize", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize, set_IPDiagnosticsUDPEchoDiagnostics_DataBlockSize, NULL, NULL, BBFDM_CWMP},
{"DSCP", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_DSCP, set_IPDiagnosticsUDPEchoDiagnostics_DSCP, NULL, NULL, BBFDM_CWMP},
{"InterTransmissionTime", &DMWRITE, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime, set_IPDiagnosticsUDPEchoDiagnostics_InterTransmissionTime, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion, set_IPDiagnosticsUDPEchoDiagnostics_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"SuccessCount", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_SuccessCount, NULL, NULL, NULL, BBFDM_CWMP},
{"FailureCount", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_FailureCount, NULL, NULL, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_AverageResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_MinimumResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsUDPEchoDiagnostics_MaximumResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};

/* *** Device.IP.Diagnostics.ServerSelectionDiagnostics. *** */
DMLEAF tIPDiagnosticsServerSelectionDiagnosticsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState, set_IPDiagnosticsServerSelectionDiagnostics_DiagnosticsState, NULL, NULL, BBFDM_CWMP},
{"Interface", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_Interface, set_IPDiagnosticsServerSelectionDiagnostics_Interface, NULL, NULL, BBFDM_CWMP},
{"ProtocolVersion", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion, set_IPDiagnosticsServerSelectionDiagnostics_ProtocolVersion, NULL, NULL, BBFDM_CWMP},
{"Protocol", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_Protocol, set_IPDiagnosticsServerSelectionDiagnostics_Protocol, NULL, NULL, BBFDM_CWMP},
{"Port", &DMWRITE, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_Port, set_IPDiagnosticsServerSelectionDiagnostics_Port, NULL, NULL, BBFDM_CWMP},
{"HostList", &DMWRITE, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_HostList, set_IPDiagnosticsServerSelectionDiagnostics_HostList, NULL, NULL, BBFDM_CWMP},
{"NumberOfRepetitions", &DMWRITE, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions, set_IPDiagnosticsServerSelectionDiagnostics_NumberOfRepetitions, NULL, NULL, BBFDM_CWMP},
{"Timeout", &DMWRITE, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_Timeout, set_IPDiagnosticsServerSelectionDiagnostics_Timeout, NULL, NULL, BBFDM_CWMP},
{"FastestHost", &DMREAD, DMT_STRING, get_IPDiagnosticsServerSelectionDiagnostics_FastestHost, NULL, NULL, NULL, BBFDM_CWMP},
{"MinimumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_MinimumResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"AverageResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_AverageResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{"MaximumResponseTime", &DMREAD, DMT_UNINT, get_IPDiagnosticsServerSelectionDiagnostics_MaximumResponseTime, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};
