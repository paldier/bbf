/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */ 

#include "x_iopsys_eu_mcpd.h"

static int get_mcp_dscp_mark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "dscp_mark", value); 
	return 0;
}

static int set_mcp_dscp_mark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "dscp_mark", value);
			return 0;
	}
	return 0;
}

static int get_igmp_proxy_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *p;
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_proxy_interfaces", value);
	*value = dmstrdup(*value);  // MEM WILL BE FREED IN DMMEMCLEAN
	p = *value;
	while (*p++) {
		if (*p == ' ') *p = ',';
	}
	return 0;
}

static int set_igmp_proxy_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *p;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (value[0] == '\0')
				return 0;
			value = dmstrdup(value);
			p = value;
			while (*p++) {
				if (*p == ',') *p = ' ';
			}
			compress_spaces(value);
			dmuci_set_value("mcpd", "mcpd", "igmp_proxy_interfaces", value);
			dmfree(value);
			return 0;
	}
	return 0;
}

static int get_igmp_default_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_default_version", value);
	return 0;
} 

static int set_igmp_default_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_default_version", value);
			return 0;
	}
	return 0;
}

static int get_igmp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_query_interval", value); 
	return 0;
} 

static int set_igmp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_query_interval", value);
			return 0;
	}
	return 0;
}

static int get_igmp_query_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_query_response_interval", value);
	return 0;
} 

static int set_igmp_query_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_query_response_interval", value);
			return 0;
	}
	return 0;
}

static int get_igmp_last_member_queryinterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_last_member_query_interval", value);
	return 0;
} 

static int set_igmp_last_member_queryinterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_last_member_query_interval", value);
			return 0;
	}
	return 0;
}

static int get_igmp_robustness_value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_robustness_value", value);
	return 0;
} 

static int set_igmp_robustness_value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_robustness_value", value);
			return 0;
	}
	return 0;
}

static int get_igmp_multicast_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_lan_to_lan_multicast", value);
	if ((*value)[0] == '\0') {
		*value = "0";
	}
	return 0;
}

static int set_igmp_multicast_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("mcpd", "mcpd", "igmp_lan_to_lan_multicast", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_igmp_fastleave_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_fast_leave", value);
	if ((*value)[0] == '\0') {
		*value = "0";
	}
	return 0;
}

static int set_igmp_fastleave_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("mcpd", "mcpd", "igmp_fast_leave", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_igmp_joinimmediate_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_join_immediate", value);
	if ((*value)[0] == '\0') {
		*value = "0";
	}
	return 0;
}

static int set_igmp_joinimmediate_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("mcpd", "mcpd", "igmp_join_immediate", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_igmp_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_proxy_enable", value);
	if ((*value)[0] == '\0') {
		*value = "0";
	}
	return 0;
}

static int set_igmp_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("mcpd", "mcpd", "igmp_proxy_enable", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_igmp_maxgroup(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_max_groups", value); 
	return 0;
} 

static int set_igmp_maxgroup(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_max_groups", value);
			return 0;
	}
	return 0;
}

static int get_igmp_maxsources(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_max_sources", value);
	return 0;
} 

static int set_igmp_maxsources(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_max_sources", value);
			return 0;
	}
	return 0;
}

static int get_igmp_maxmembers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_max_members", value);
	return 0;
}

static int set_igmp_maxmembers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_max_members", value);
			return 0;
	}
	return 0;
}

static int get_igmp_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_snooping_enable", value);
	return 0;
}

static int set_igmp_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_snooping_enable", value);
			return 0;
	}
	return 0;
}

static int get_igmp_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *p;

	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_snooping_interfaces", value);
	*value = dmstrdup(*value);  // MEM WILL BE FREED IN DMMEMCLEAN
	p = *value;
	while (*p++) {
		if (*p == ' ') *p = ',';
	}

	return 0;
}

static int set_igmp_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *p;
	
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (value[0] == '\0')
				return 0;
			value = dmstrdup(value);
			p = value;
			while (*p++) {
				if (*p == ',') *p = ' ';
			}
			compress_spaces(value);
			dmuci_set_value("mcpd", "mcpd", "igmp_snooping_interfaces", value);
			dmfree(value);
			return 0;
	}
	return 0;
}

static int get_mld_proxy_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *p;
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_proxy_interfaces", value);
	*value = dmstrdup(*value);  // MEM WILL BE FREED IN DMMEMCLEAN
	p = *value;
	while (*p++) {
		if (*p == ' ') *p = ',';
	}
	return 0;
}

static int set_mld_proxy_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *p;

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (value[0] == '\0')
				return 0;
			value = dmstrdup(value);
			p = value;
			while (*p++) {
				if (*p == ',') *p = ' ';
			}
			compress_spaces(value);
			dmuci_set_value("mcpd", "mcpd", "mld_proxy_interfaces", value);
			dmfree(value);
			return 0;
	}
	return 0;
}

static int get_mld_default_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_default_version", value);
	return 0;
} 

static int set_mld_default_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_default_version", value);
			return 0;
	}
	return 0;
}

static int get_mld_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_query_interval", value); 
	return 0;
} 

static int set_mld_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_query_interval", value);
			return 0;
	}
	return 0;
}

static int get_mld_query_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_query_response_interval", value);
	return 0;
} 

static int set_mld_query_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_query_response_interval", value);
			return 0;
	}
	return 0;
}

static int get_mld_last_member_queryinterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_last_member_query_interval", value);
	return 0;
} 

static int set_mld_last_member_queryinterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_last_member_query_interval", value);
			return 0;
	}
	return 0;
}

static int get_mld_robustness_value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_robustness_value", value);
	return 0;
} 

static int set_mld_robustness_value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_robustness_value", value);
			return 0;
	}
	return 0;
}

static int get_mld_multicast_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_lan_to_lan_multicast", value);
	if ((*value)[0] == '\0') {
		*value = "0";
	}
	return 0;
}

static int set_mld_multicast_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("mcpd", "mcpd", "mld_lan_to_lan_multicast", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_mld_fastleave_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_fast_leave", value);
	if ((*value)[0] == '\0') {
		*value = "0";
	}
	return 0;
}

static int set_mld_fastleave_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("mcpd", "mcpd", "mld_fast_leave", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_mld_joinimmediate_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_join_immediate", value);
	if ((*value)[0] == '\0') {
		*value = "0";
	}
	return 0;
}

static int set_mld_joinimmediate_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("mcpd", "mcpd", "mld_join_immediate", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_mld_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_proxy_enable", value);
	if ((*value)[0] == '\0') {
		*value = "0";
	}
	return 0;
}

static int set_mld_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("mcpd", "mcpd", "mld_proxy_enable", b ? "1" : "");
			return 0;
	}
	return 0;
}

static int get_mld_maxgroup(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_max_groups", value); 
	return 0;
} 

static int set_mld_maxgroup(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_max_groups", value);
			return 0;
	}
	return 0;
}

static int get_mld_maxsources(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_max_sources", value);
	return 0;
} 

static int set_mld_maxsources(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_max_sources", value);
			return 0;
	}
	return 0;
}

static int get_mld_maxmembers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_max_members", value);
	return 0;
}

static int set_mld_maxmembers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_max_members", value);
			return 0;
	}
	return 0;
}

static int get_mld_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "mld_snooping_enable", value);
	return 0;
}

static int set_mld_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "mld_snooping_enable", value);
			return 0;
	}
	return 0;
}

static int get_mld_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *p;

	dmuci_get_option_value_string("mcpd", "mcpd", "mld_snooping_interfaces", value);
	*value = dmstrdup(*value);  // MEM WILL BE FREED IN DMMEMCLEAN
	p = *value;
	while (*p++) {
		if (*p == ' ') *p = ',';
	}

	return 0;
}

static int set_mld_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *p;
	
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (value[0] == '\0')
				return 0;
			value = dmstrdup(value);
			p = value;
			while (*p++) {
				if (*p == ',') *p = ' ';
			}
			compress_spaces(value);
			dmuci_set_value("mcpd", "mcpd", "mld_snooping_interfaces", value);
			dmfree(value);
			return 0;
	}
	return 0;
}

DMLEAF X_IOPSYS_EU_MCPDParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DSCPMark", &DMWRITE, DMT_STRING, get_mcp_dscp_mark, set_mcp_dscp_mark, NULL, NULL, BBFDM_BOTH},
{"IGMPProxyInterface", &DMWRITE, DMT_STRING, get_igmp_proxy_interface, set_igmp_proxy_interface, NULL, NULL, BBFDM_BOTH},
{"IGMPDefaultVersion", &DMWRITE, DMT_STRING, get_igmp_default_version, set_igmp_default_version, NULL, NULL, BBFDM_BOTH},
{"IGMPQueryInterval", &DMWRITE, DMT_UNINT, get_igmp_query_interval, set_igmp_query_interval, NULL, NULL, BBFDM_BOTH},
{"IGMPQueryResponseInterval", &DMWRITE, DMT_UNINT, get_igmp_query_response_interval, set_igmp_query_response_interval, NULL, NULL, BBFDM_BOTH},
{"IGMPLastMemberQueryInterval", &DMWRITE, DMT_UNINT, get_igmp_last_member_queryinterval, set_igmp_last_member_queryinterval, NULL, NULL, BBFDM_BOTH},
{"IGMPRobustnessValue", &DMWRITE, DMT_INT, get_igmp_robustness_value, set_igmp_robustness_value, NULL, NULL, BBFDM_BOTH},
{"IGMPLANToLANMulticastEnable", &DMWRITE, DMT_BOOL, get_igmp_multicast_enable, set_igmp_multicast_enable, NULL, NULL, BBFDM_BOTH},
{"IGMPMaxGroup", &DMWRITE, DMT_UNINT, get_igmp_maxgroup, set_igmp_maxgroup, NULL, NULL, BBFDM_BOTH},
{"IGMPMaxSources", &DMWRITE, DMT_UNINT, get_igmp_maxsources, set_igmp_maxsources, NULL, NULL, BBFDM_BOTH},
{"IGMPMaxMembers", &DMWRITE, DMT_UNINT, get_igmp_maxmembers, set_igmp_maxmembers, NULL, NULL, BBFDM_BOTH},
{"IGMPFastLeaveEnable", &DMWRITE, DMT_BOOL, get_igmp_fastleave_enable, set_igmp_fastleave_enable, NULL, NULL, BBFDM_BOTH},
{"IGMPJoinImmediateEnable", &DMWRITE, DMT_BOOL, get_igmp_joinimmediate_enable, set_igmp_joinimmediate_enable, NULL, NULL, BBFDM_BOTH},
{"IGMPProxyEnable", &DMWRITE, DMT_BOOL, get_igmp_proxy_enable, set_igmp_proxy_enable, NULL, NULL, BBFDM_BOTH},
{"IGMPSnoopingMode", &DMWRITE, DMT_STRING, get_igmp_snooping_mode, set_igmp_snooping_mode, NULL, NULL, BBFDM_BOTH},
{"IGMPSnoopingInterfaces", &DMWRITE, DMT_STRING, get_igmp_snooping_interface, set_igmp_snooping_interface, NULL, NULL, BBFDM_BOTH},
{"MLDProxyInterface", &DMWRITE, DMT_STRING, get_mld_proxy_interface, set_mld_proxy_interface, NULL, NULL, BBFDM_BOTH},
{"MLDDefaultVersion", &DMWRITE, DMT_STRING, get_mld_default_version, set_mld_default_version, NULL, NULL, BBFDM_BOTH},
{"MLDQueryInterval", &DMWRITE, DMT_UNINT, get_mld_query_interval, set_mld_query_interval, NULL, NULL, BBFDM_BOTH},
{"MLDQueryResponseInterval", &DMWRITE, DMT_UNINT, get_mld_query_response_interval, set_mld_query_response_interval, NULL, NULL, BBFDM_BOTH},
{"MLDLastMemberQueryInterval", &DMWRITE, DMT_UNINT, get_mld_last_member_queryinterval, set_mld_last_member_queryinterval, NULL, NULL, BBFDM_BOTH},
{"MLDRobustnessValue", &DMWRITE, DMT_INT, get_mld_robustness_value, set_mld_robustness_value, NULL, NULL, BBFDM_BOTH},
{"MLDLANToLANMulticastEnable", &DMWRITE, DMT_BOOL, get_mld_multicast_enable, set_mld_multicast_enable, NULL, NULL, BBFDM_BOTH},
{"MLDMaxGroup", &DMWRITE, DMT_UNINT, get_mld_maxgroup, set_mld_maxgroup, NULL, NULL, BBFDM_BOTH},
{"MLDMaxSources", &DMWRITE, DMT_UNINT, get_mld_maxsources, set_mld_maxsources, NULL, NULL, BBFDM_BOTH},
{"MLDMaxMembers", &DMWRITE, DMT_UNINT, get_mld_maxmembers, set_mld_maxmembers, NULL, NULL, BBFDM_BOTH},
{"MLDFastLeaveEnable", &DMWRITE, DMT_BOOL, get_mld_fastleave_enable, set_mld_fastleave_enable, NULL, NULL, BBFDM_BOTH},
{"MLDJoinImmediateEnable", &DMWRITE, DMT_BOOL, get_mld_joinimmediate_enable, set_mld_joinimmediate_enable, NULL, NULL, BBFDM_BOTH},
{"MLDProxyEnable", &DMWRITE, DMT_BOOL, get_mld_proxy_enable, set_mld_proxy_enable, NULL, NULL, BBFDM_BOTH},
{"MLDSnoopingMode", &DMWRITE, DMT_STRING, get_mld_snooping_mode, set_mld_snooping_mode, NULL, NULL, BBFDM_BOTH},
{"MLDSnoopingInterfaces", &DMWRITE, DMT_STRING, get_mld_snooping_interface, set_mld_snooping_interface, NULL, NULL, BBFDM_BOTH},
{0}
};
