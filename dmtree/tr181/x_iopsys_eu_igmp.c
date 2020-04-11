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

#include "x_iopsys_eu_igmp.h"

static int get_igmp_dscp_mark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("mcpd", "mcpd", "igmp_dscp_mark", value); 
	return 0;
}

static int set_igmp_dscp_mark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("mcpd", "mcpd", "igmp_dscp_mark", value);
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

DMLEAF tSe_IgmpParam[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DifferentiateService", &DMWRITE, DMT_STRING, get_igmp_dscp_mark, set_igmp_dscp_mark, NULL, NULL, BBFDM_BOTH},
{"ProxyInterface", &DMWRITE, DMT_STRING, get_igmp_proxy_interface, set_igmp_proxy_interface, NULL, NULL, BBFDM_BOTH},
{"DefaultVersion", &DMWRITE, DMT_STRING, get_igmp_default_version, set_igmp_default_version, NULL, NULL, BBFDM_BOTH},
{"QueryInterval", &DMWRITE, DMT_UNINT, get_igmp_query_interval, set_igmp_query_interval, NULL, NULL, BBFDM_BOTH},
{"QueryResponseInterval", &DMWRITE, DMT_UNINT, get_igmp_query_response_interval, set_igmp_query_response_interval, NULL, NULL, BBFDM_BOTH},
{"LastMemberQueryInterval", &DMWRITE, DMT_UNINT, get_igmp_last_member_queryinterval, set_igmp_last_member_queryinterval, NULL, NULL, BBFDM_BOTH},
{"RobustnessValue", &DMWRITE, DMT_INT, get_igmp_robustness_value, set_igmp_robustness_value, NULL, NULL, BBFDM_BOTH},
{"LANToLANMulticastEnable", &DMWRITE, DMT_BOOL, get_igmp_multicast_enable, set_igmp_multicast_enable, NULL, NULL, BBFDM_BOTH},
{"MaxGroup", &DMWRITE, DMT_UNINT, get_igmp_maxgroup, set_igmp_maxgroup, NULL, NULL, BBFDM_BOTH},
{"MaxSources", &DMWRITE, DMT_UNINT, get_igmp_maxsources, set_igmp_maxsources, NULL, NULL, BBFDM_BOTH},
{"MaxMembers", &DMWRITE, DMT_UNINT, get_igmp_maxmembers, set_igmp_maxmembers, NULL, NULL, BBFDM_BOTH},
{"FastLeaveEnable", &DMWRITE, DMT_BOOL, get_igmp_fastleave_enable, set_igmp_fastleave_enable, NULL, NULL, BBFDM_BOTH},
{"JoinImmediateEnable", &DMWRITE, DMT_BOOL, get_igmp_joinimmediate_enable, set_igmp_joinimmediate_enable, NULL, NULL, BBFDM_BOTH},
{"ProxyEnable", &DMWRITE, DMT_BOOL, get_igmp_proxy_enable, set_igmp_proxy_enable, NULL, NULL, BBFDM_BOTH},
{"SnoopingMode", &DMWRITE, DMT_STRING, get_igmp_snooping_mode, set_igmp_snooping_mode, NULL, NULL, BBFDM_BOTH},
{"SnoopingInterfaces", &DMWRITE, DMT_STRING, get_igmp_snooping_interface, set_igmp_snooping_interface, NULL, NULL, BBFDM_BOTH},
{0}
};
