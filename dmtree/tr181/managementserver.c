/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "managementserver.h"

/*#Device.ManagementServer.URL!UCI:cwmp/acs,acs/url*/
static int get_management_server_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dhcp = NULL, *url = NULL, *provisioning_value = NULL;

	dmuci_get_option_value_string("cwmp", "acs", "dhcp_discovery", &dhcp);
	dmuci_get_option_value_string("cwmp", "acs", "url", &url);
	dmuci_get_varstate_string("cwmp", "acs", "dhcp_url", &provisioning_value);

	if ( ((dhcp && strcmp(dhcp, "enable") == 0 ) || ((url == NULL) || (url[0] == '\0'))) && ((provisioning_value != NULL) && (provisioning_value[0] != '\0')) )
		*value = provisioning_value;
	else if ((url != NULL) && (url[0] != '\0'))
		*value = url;
	else
		*value = dmstrdup("http://192.168.1.1:8080/openacs/acs");
	return 0;
}

static int set_management_server_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "dhcp_discovery", "disable");
			dmuci_set_value("cwmp", "acs", "url", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			break;
	}
	return 0;
}

/*#Device.ManagementServer.Username!UCI:cwmp/acs,acs/userid*/
static int get_management_server_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "userid", value);
	return 0;	
}

static int set_management_server_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "userid", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.Password!UCI:cwmp/acs,acs/passwd*/
static int set_management_server_passwd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "passwd", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.ParameterKey!UCI:cwmp/acs,acs/ParameterKey*/
static int get_management_server_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "ParameterKey", value);
	return 0;	
}

/*#Device.ManagementServer.PeriodicInformEnable!UCI:cwmp/acs,acs/periodic_inform_enable*/
static int get_management_server_periodic_inform_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "periodic_inform_enable", value);
	return 0;	
}

static int set_management_server_periodic_inform_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:			
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("cwmp", "acs", "periodic_inform_enable", b ? "1" : "0");
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.PeriodicInformInterval!UCI:cwmp/acs,acs/periodic_inform_interval*/
static int get_management_server_periodic_inform_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "periodic_inform_interval", value);
	return 0;
}

static int set_management_server_periodic_inform_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "periodic_inform_interval", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.PeriodicInformTime!UCI:cwmp/acs,acs/periodic_inform_time*/
static int get_management_server_periodic_inform_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	time_t time_value;
	
	dmuci_get_option_value_string("cwmp", "acs", "periodic_inform_time", value);
	if ((*value)[0] != '0' && (*value)[0] != '\0') {
		time_value = atoi(*value);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%SZ", localtime(&time_value));
		*value = dmstrdup(s_now); // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		*value = "0001-01-01T00:00:00Z";
	}		
	return 0;	
}

static int set_management_server_periodic_inform_time(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct tm tm;
	char buf[16];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			strptime(value, "%Y-%m-%dT%H:%M:%SZ", &tm);
			snprintf(buf, sizeof(buf), "%ld", mktime(&tm));
			dmuci_set_value("cwmp", "acs", "periodic_inform_time", buf);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;	
}

/*#Device.ManagementServer.ConnectionRequestURL!UCI:cwmp/cpe,cpe/port*/
static int get_management_server_connection_request_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ip, *port, *iface;

	dmuci_get_option_value_string("cwmp", "cpe", "default_wan_interface", &iface);
	network_get_ipaddr(&ip, iface);	
	dmuci_get_option_value_string("cwmp", "cpe", "port", &port);
	if (ip[0] != '\0' && port[0] != '\0') {
		char buf[64];
		snprintf(buf, sizeof(buf), "http://%s:%s/", ip, port);
		*value = dmstrdup(buf); //  MEM WILL BE FREED IN DMMEMCLEAN
	}
	return 0;
}

/*#Device.ManagementServer.ConnectionRequestUsername!UCI:cwmp/cpe,cpe/userid*/
static int get_management_server_connection_request_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "userid", value);
	return 0;
}

static int set_management_server_connection_request_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "userid", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.ConnectionRequestPassword!UCI:cwmp/cpe,cpe/passwd*/
static int set_management_server_connection_request_passwd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "passwd", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_lwn_protocol_supported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "UDP";
	return 0;
}

/*#Device.ManagementServer.LightweightNotificationProtocolsUsed!UCI:cwmp/lwn,lwn/enable*/
static int get_lwn_protocol_used(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	char *tmp;
	
	dmuci_get_option_value_string("cwmp", "lwn", "enable", &tmp);
	string_to_bool(tmp, &b);
	*value = b ? "UDP" : "";
	return 0;
}

static int set_lwn_protocol_used(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, -1, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcmp(value,"UDP") == 0)
				dmuci_set_value("cwmp", "lwn", "enable", "1");
			else
				dmuci_set_value("cwmp", "lwn", "enable", "0");
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.UDPLightweightNotificationHost!UCI:cwmp/lwn,lwn/hostname*/
static int get_lwn_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{	
	dmuci_get_option_value_string("cwmp", "lwn", "hostname", value);
	return 0;
}

static int set_lwn_host(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "lwn", "hostname", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.UDPLightweightNotificationPort!UCI:cwmp/lwn,lwn/port*/
static int get_lwn_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "lwn", "port", value);
	return 0;
}

static int set_lwn_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "lwn", "port", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

static int get_management_server_http_compression_supportted(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "GZIP,Deflate";
	return 0;
}

/*#Device.ManagementServer.HTTPCompression!UCI:cwmp/acs,acs/compression*/
static int get_management_server_http_compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "compression", value);
	return 0;
}

static int set_management_server_http_compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if (strcasecmp(value, "gzip") == 0 || strcasecmp(value, "deflate") == 0 || strncasecmp(value, "disable", 7) == 0) {
				dmuci_set_value("cwmp", "acs", "compression", value);
				cwmp_set_end_session(END_SESSION_RELOAD);
			}
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.CWMPRetryMinimumWaitInterval!UCI:cwmp/acs,acs/retry_min_wait_interval*/
static int get_management_server_retry_min_wait_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "retry_min_wait_interval", value);
	return 0;
}

static int set_management_server_retry_min_wait_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "retry_min_wait_interval", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.CWMPRetryIntervalMultiplier!UCI:cwmp/acs,acs/retry_interval_multiplier*/
static int get_management_server_retry_interval_multiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "acs", "retry_interval_multiplier", value);
	return 0;
}

static int set_management_server_retry_interval_multiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1000","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "acs", "retry_interval_multiplier", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.AliasBasedAddressing!UCI:cwmp/cpe,cpe/amd_version*/
static int get_alias_based_addressing(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "amd_version", value);
	if ((*value)[0] == '\0'|| atoi(*value) <= AMD_4)
		*value = "false";
	else
		*value = "true";
	return 0;
}

/*#Device.ManagementServer.InstanceMode!UCI:cwmp/cpe,cpe/instance_mode*/
static int get_instance_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "instance_mode", value);
	return 0;
}

static int set_instance_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, InstanceMode, 2, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "instance_mode", value);
			cwmp_set_end_session(END_SESSION_RELOAD);
			return 0;
	}
	return 0;
}

/*
 * STUN parameters
 */
/*#Device.ManagementServer.UDPConnectionRequestAddress!UCI:cwmp_stun/stun,stun/crudp_address*/
static int get_upd_cr_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_varstate_string("cwmp_stun", "stun", "crudp_address", value);
	return 0;
}

static int get_stun_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*icwmp_stund";
	if (check_file(path))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_stun_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if(b) {
				DMCMD("/etc/rc.common", 2, "/etc/init.d/icwmp_stund", "enable");
				DMCMD("/etc/rc.common", 2, "/etc/init.d/icwmp_stund", "start");
			}
			else {
				DMCMD("/etc/rc.common", 2, "/etc/init.d/icwmp_stund", "disable");
				DMCMD("/etc/rc.common", 2, "/etc/init.d/icwmp_stund", "stop");
			}
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.STUNServerAddress!UCI:cwmp_stun/stun,stun/server_address*/
static int get_stun_server_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_stun", "stun", "server_address", value);
	return 0;
}

static int set_stun_server_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_stun", "stun", "server_address", value);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.STUNServerPort!UCI:cwmp_stun/stun,stun/server_port*/
static int get_stun_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_stun", "stun", "server_port", value);
	return 0;
}

static int set_stun_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_stun", "stun", "server_port", value);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.STUNUsername!UCI:cwmp_stun/stun,stun/username*/
static int get_stun_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_stun", "stun", "username", value);
	return 0;
}

static int set_stun_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_stun", "stun", "username", value);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.STUNPassword!UCI:cwmp_stun/stun,stun/password*/
static int get_stun_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_stun_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_stun", "stun", "password", value);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.STUNMaximumKeepAlivePeriod!UCI:cwmp_stun/stun,stun/max_keepalive*/
static int get_stun_maximum_keepalive_period(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_stun", "stun", "max_keepalive", value);
	return 0;
}

static int set_stun_maximum_keepalive_period(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_stun", "stun", "max_keepalive", value);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.STUNMinimumKeepAlivePeriod!UCI:cwmp_stun/stun,stun/min_keepalive*/
static int get_stun_minimum_keepalive_period(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_stun", "stun", "min_keepalive", value);
	return 0;
}

static int set_stun_minimum_keepalive_period(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_stun", "stun", "min_keepalive", value);
			return 0;
	}
	return 0;
}

/*#Device.ManagementServer.NATDetected!UCI:cwmp_stun/stun,stun/nat_detected*/
static int get_nat_detected(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*icwmp_stund";
	char *v;

	if (check_file(path)) { //stun is enabled
		dmuci_get_varstate_string("cwmp_stun", "stun", "nat_detected", &v);
		*value = (*v == '1') ? "true" : "false";
	} else
		*value = "false";
	return 0;
}

/*
 * XMPP parameters
 */
/*#Device.ManagementServer.ConnReqAllowedJabberIDs!UCI:cwmp_xmpp/cwmp,xmpp/allowed_jid*/
static int get_management_server_conn_rep_allowed_jabber_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_xmpp", "xmpp", "allowed_jid", value);
	return 0;
}

static int set_management_server_conn_rep_allowed_jabber_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 32, -1, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp_xmpp", "xmpp", "allowed_jid", value);
			return 0;
	}
	return 0;
}

static int get_management_server_conn_req_jabber_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	char *username, *domain, *resource, *tmpPtr = NULL, *strResponse = NULL;

	uci_foreach_sections("cwmp_xmpp", "xmpp_connection", s) {
		dmuci_get_value_by_section_string(s, "username", &username);
		dmuci_get_value_by_section_string(s, "domain", &domain);
		dmuci_get_value_by_section_string(s, "resource", &resource);
		if(*username != '\0' || *domain != '\0' || *resource != '\0') {
			if(!strResponse)
				dmasprintf(&strResponse, "%s@%s/%s", username, domain, resource);
			else {
				tmpPtr = dmstrdup(strResponse);
				dmfree(strResponse);
				dmasprintf(&strResponse, "%s,%s@%s/%s", tmpPtr, username, domain, resource);
				dmfree(tmpPtr);
			}
		}
	}
	*value = strResponse ? strResponse : "";
	return 0;
}

static int get_management_server_conn_req_xmpp_connection(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *id;

	dmuci_get_option_value_string("cwmp_xmpp", "xmpp", "id", &id);
	if (strlen(id)) dmasprintf(value, "Device.XMPP.Connection.%s", id);
	return 0;
}

static int set_management_server_conn_req_xmpp_connection(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *str, *connection_instance;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			if ((str = strstr(value, "Device.XMPP.Connection."))) {
				value = dmstrdup(str + sizeof("Device.XMPP.Connection.") - 1); //MEM WILL BE FREED IN DMMEMCLEAN
			}
			uci_foreach_sections("cwmp_xmpp", "xmpp_connection", s) {
				dmuci_get_value_by_section_string(s, "connection_instance", &connection_instance);
				if(strcmp(value, connection_instance) == 0) {
					dmuci_set_value("cwmp_xmpp", "xmpp", "id", value);
					break;
				}
			}
			return 0;
	}
	return 0;
}

static int get_management_server_supported_conn_req_methods(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,XMPP,STUN";
	return 0;
}

/*** ManagementServer. ***/
DMLEAF tManagementServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"URL", &DMWRITE, DMT_STRING, get_management_server_url, set_management_server_url, NULL, NULL, BBFDM_CWMP},
{"Username", &DMWRITE, DMT_STRING, get_management_server_username, set_management_server_username, NULL, NULL, BBFDM_CWMP},
{"Password", &DMWRITE, DMT_STRING, get_empty, set_management_server_passwd, NULL, NULL, BBFDM_CWMP},
{"ParameterKey", &DMREAD, DMT_STRING, get_management_server_key, NULL, &DMFINFRM, &DMNONE, BBFDM_CWMP},
{"PeriodicInformEnable", &DMWRITE, DMT_BOOL, get_management_server_periodic_inform_enable, set_management_server_periodic_inform_enable,  NULL, NULL, BBFDM_CWMP},
{"PeriodicInformInterval", &DMWRITE, DMT_UNINT, get_management_server_periodic_inform_interval, set_management_server_periodic_inform_interval, NULL, NULL, BBFDM_CWMP},
{"PeriodicInformTime", &DMWRITE, DMT_TIME, get_management_server_periodic_inform_time, set_management_server_periodic_inform_time, NULL, NULL, BBFDM_CWMP},
{"ConnectionRequestURL", &DMREAD, DMT_STRING, get_management_server_connection_request_url, NULL, &DMFINFRM, &DMACTIVE, BBFDM_CWMP},
{"ConnectionRequestUsername", &DMWRITE, DMT_STRING, get_management_server_connection_request_username, set_management_server_connection_request_username, NULL, NULL, BBFDM_CWMP},
{"ConnectionRequestPassword", &DMWRITE, DMT_STRING, get_empty, set_management_server_connection_request_passwd,  NULL, NULL, BBFDM_CWMP},
{"HTTPCompressionSupported", &DMREAD, DMT_STRING, get_management_server_http_compression_supportted, NULL, NULL, NULL, BBFDM_CWMP},
{"HTTPCompression", &DMWRITE, DMT_STRING, get_management_server_http_compression, set_management_server_http_compression, NULL, NULL, BBFDM_CWMP},
{"LightweightNotificationProtocolsSupported", &DMREAD, DMT_STRING, get_lwn_protocol_supported, NULL, NULL, NULL, BBFDM_CWMP},
{"LightweightNotificationProtocolsUsed", &DMWRITE, DMT_STRING, get_lwn_protocol_used, set_lwn_protocol_used, NULL, NULL, BBFDM_CWMP},
{"UDPLightweightNotificationHost", &DMWRITE, DMT_STRING, get_lwn_host, set_lwn_host, NULL, NULL, BBFDM_CWMP},
{"UDPLightweightNotificationPort", &DMWRITE, DMT_UNINT, get_lwn_port, set_lwn_port, NULL, NULL, BBFDM_CWMP},
{"CWMPRetryMinimumWaitInterval", &DMWRITE, DMT_UNINT, get_management_server_retry_min_wait_interval, set_management_server_retry_min_wait_interval, NULL, NULL, BBFDM_CWMP},
{"CWMPRetryIntervalMultiplier", &DMWRITE, DMT_UNINT, get_management_server_retry_interval_multiplier, set_management_server_retry_interval_multiplier, NULL, NULL, BBFDM_CWMP},
{"AliasBasedAddressing", &DMREAD, DMT_BOOL, get_alias_based_addressing, NULL, &DMFINFRM, NULL, BBFDM_CWMP},
{"InstanceMode", &DMWRITE, DMT_STRING, get_instance_mode, set_instance_mode, NULL, NULL, BBFDM_CWMP},
{"ConnReqAllowedJabberIDs", &DMWRITE, DMT_STRING, get_management_server_conn_rep_allowed_jabber_id, set_management_server_conn_rep_allowed_jabber_id, NULL, NULL, BBFDM_CWMP},
{"ConnReqJabberID", &DMREAD, DMT_STRING, get_management_server_conn_req_jabber_id, NULL, &DMFINFRM, &DMACTIVE, BBFDM_CWMP},
{"ConnReqXMPPConnection", &DMWRITE, DMT_STRING, get_management_server_conn_req_xmpp_connection, set_management_server_conn_req_xmpp_connection, &DMFINFRM, NULL, BBFDM_CWMP},
{"SupportedConnReqMethods", &DMREAD, DMT_STRING, get_management_server_supported_conn_req_methods, NULL, NULL, NULL, BBFDM_CWMP},
{"UDPConnectionRequestAddress", &DMREAD, DMT_STRING, get_upd_cr_address, NULL, NULL, &DMACTIVE, BBFDM_CWMP},
{"STUNEnable", &DMWRITE, DMT_BOOL, get_stun_enable, set_stun_enable, NULL, NULL, BBFDM_CWMP},
{"STUNServerAddress", &DMWRITE, DMT_STRING, get_stun_server_address, set_stun_server_address, NULL, NULL, BBFDM_CWMP},
{"STUNServerPort", &DMWRITE, DMT_UNINT, get_stun_server_port, set_stun_server_port, NULL, NULL, BBFDM_CWMP},
{"STUNUsername", &DMWRITE, DMT_STRING, get_stun_username, set_stun_username, NULL, NULL, BBFDM_CWMP},
{"STUNPassword", &DMWRITE, DMT_STRING, get_stun_password, set_stun_password, NULL, NULL, BBFDM_CWMP},
{"STUNMaximumKeepAlivePeriod", &DMWRITE, DMT_INT, get_stun_maximum_keepalive_period, set_stun_maximum_keepalive_period, NULL, NULL, BBFDM_CWMP},
{"STUNMinimumKeepAlivePeriod", &DMWRITE, DMT_UNINT, get_stun_minimum_keepalive_period, set_stun_minimum_keepalive_period, NULL, NULL, BBFDM_CWMP},
{"NATDetected", &DMREAD, DMT_BOOL, get_nat_detected, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};
