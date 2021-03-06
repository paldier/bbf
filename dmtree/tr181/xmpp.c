/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include "xmpp.h"

static int add_xmpp_connection(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	struct uci_section *xmpp_connection, *xmpp_connection_server;
	char *value1, *value2, *last_inst;

	last_inst = get_last_instance("cwmp_xmpp", "xmpp_connection", "connection_instance");
	dmuci_add_section_and_rename("cwmp_xmpp", "xmpp_connection", &xmpp_connection, &value1);
	dmuci_add_section_and_rename("cwmp_xmpp", "xmpp_connection_server", &xmpp_connection_server, &value2);
	dmasprintf(instancepara, "%d", (last_inst) ? atoi(last_inst)+1 : 1);
	dmuci_set_value_by_section(xmpp_connection, "connection_instance", *instancepara);
	dmuci_set_value_by_section(xmpp_connection, "enable", "0");
	dmuci_set_value_by_section(xmpp_connection, "interval", "30");
	dmuci_set_value_by_section(xmpp_connection, "attempt", "16");
	dmuci_set_value_by_section(xmpp_connection, "serveralgorithm", "DNS-SRV");
	dmuci_set_value_by_section(xmpp_connection_server, "id_connection", *instancepara);
	dmuci_set_value_by_section(xmpp_connection_server, "connection_server_instance", "1");
	dmuci_set_value_by_section(xmpp_connection_server, "enable", "0");
	dmuci_set_value_by_section(xmpp_connection_server, "port", "5222");
	return 0;
}

static int delete_xmpp_connection(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s, *ss = NULL;
	char *prev_connection_instance;
	
	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string((struct uci_section *)data, "connection_instance", &prev_connection_instance);
			uci_foreach_option_eq("cwmp_xmpp", "xmpp_connection_server", "id_connection", prev_connection_instance, s) {
				dmuci_delete_by_section(s, NULL, NULL);
				break;
			}
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			return 0;
		case DEL_ALL:
			uci_foreach_sections("cwmp_xmpp", "xmpp_connection", s) {
				if (found != 0) {
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			uci_foreach_sections("cwmp_xmpp", "xmpp_connection_server", s) {
				if (found != 0) {
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			return 0;
	}
	return 0;
}

/*#Device.XMPP.ConnectionNumberOfEntries!UCI:cwmp_xmpp/xmpp_connection/*/
static int get_xmpp_connection_nbr_entry(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int cnt = 0;

	uci_foreach_sections("cwmp_xmpp", "xmpp_connection", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int get_xmpp_connection_supported_server_connect_algorithms(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "DNS-SRV,ServerTable";
	return 0;
}

/*#Device.XMPP.Connection.{i}.Enable!UCI:cwmp_xmpp/xmpp_connection,@i-1/enable*/
static int get_connection_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	return 0;
}

static int set_connection_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.Alias!UCI:cwmp_xmpp/xmpp_connection,@i-1/connection_alias*/
static int get_xmpp_connection_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "connection_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_xmpp_connection_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "connection_alias", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.Username!UCI:cwmp_xmpp/xmpp_connection,@i-1/username*/
static int get_xmpp_connection_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "username", value);
	return 0;
}

static int set_xmpp_connection_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "username", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.Password!UCI:cwmp_xmpp/xmpp_connection,@i-1/password*/
static int get_xmpp_connection_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

static int set_xmpp_connection_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "password", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.Domain!UCI:cwmp_xmpp/xmpp_connection,@i-1/domain*/
static int get_xmpp_connection_domain(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "domain", value);
	return 0;
}

static int set_xmpp_connection_domain(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "domain", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.Resource!UCI:cwmp_xmpp/xmpp_connection,@i-1/resource*/
static int get_xmpp_connection_resource(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "resource", value);
	return 0;
}

static int set_xmpp_connection_resource(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "resource", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.ServerConnectAlgorithm!UCI:cwmp_xmpp/xmpp_connection,@i-1/serveralgorithm*/
static int get_xmpp_connection_server_connect_algorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "serveralgorithm", value);
	return 0;
}

static int set_xmpp_connection_server_connect_algorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, ServerConnectAlgorithm, 4, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "serveralgorithm", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.KeepAliveInterval!UCI:cwmp_xmpp/xmpp_connection,@i-1/interval*/
static int get_xmpp_connection_keepalive_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "interval", value);
	return 0;
}

static int set_xmpp_connection_keepalive_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_long(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "interval", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.ServerConnectAttempts!UCI:cwmp_xmpp/xmpp_connection,@i-1/attempt*/
static int get_xmpp_connection_server_attempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "attempt", value);
	return 0;
}

static int set_xmpp_connection_server_attempts(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "attempt", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.ServerRetryInitialInterval!UCI:cwmp_xmpp/xmpp_connection,@i-1/initial_retry_interval*/
static int get_xmpp_connection_retry_initial_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "initial_retry_interval", value);
	return 0;
}

static int set_xmpp_connection_retry_initial_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "initial_retry_interval", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.ServerRetryIntervalMultiplier!UCI:cwmp_xmpp/xmpp_connection,@i-1/retry_interval_multiplier*/
static int get_xmpp_connection_retry_interval_multiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "retry_interval_multiplier", value);
	return 0;
}

static int set_xmpp_connection_retry_interval_multiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1000","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "retry_interval_multiplier", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.ServerRetryMaxInterval!UCI:cwmp_xmpp/xmpp_connection,@i-1/retry_max_interval*/
static int get_xmpp_connection_retry_max_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "retry_max_interval", value);
	return 0;
}

static int set_xmpp_connection_retry_max_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "retry_max_interval", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.UseTLS!UCI:cwmp_xmpp/xmpp_connection,@i-1/usetls*/
static int get_xmpp_connection_server_usetls(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "usetls", value);
	return 0;
}

static int set_xmpp_connection_server_usetls(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action) 
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "usetls", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int get_xmpp_connection_jabber_id(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *resource, *domain, *username;

	dmuci_get_value_by_section_string((struct uci_section *)data, "resource", &resource);
	dmuci_get_value_by_section_string((struct uci_section *)data, "domain", &domain);
	dmuci_get_value_by_section_string((struct uci_section *)data, "username", &username);
	if (*resource != '\0' || *domain != '\0' || *username != '\0')
		dmasprintf(value, "%s@%s/%s", username, domain, resource);
	else
		*value = "";
	return 0;
}

/*#Device.XMPP.Connection.{i}.Status!UCI:cwmp_xmpp/xmpp_connection,@i-1/enable*/
static int get_xmpp_connection_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *status;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", &status);
	if (strcmp(status, "1") == 0)
			*value = "Enabled";
		else
			*value = "Disabled";
	return 0;
}

static int get_xmpp_connection_server_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*#Device.XMPP.Connection.{i}.Server.{i}.Enable!UCI:cwmp_xmpp/xmpp_connection,@i-1/enable*/
static int get_xmpp_connection_server_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	return 0;
}

static int set_xmpp_connection_server_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.Server.{i}.Alias!UCI:cwmp_xmpp/xmpp_connection,@i-1/connection_server_alias*/
static int get_xmpp_connection_server_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "connection_server_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_xmpp_connection_server_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "connection_server_alias", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.Server.{i}.ServerAddress!UCI:cwmp_xmpp/xmpp_connection,@i-1/server_address*/
static int get_xmpp_connection_server_server_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "server_address", value);
	return 0;
}

static int set_xmpp_connection_server_server_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "server_address", value);
			return 0;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.Server.{i}.Port!UCI:cwmp_xmpp/xmpp_connection,@i-1/port*/
static int get_xmpp_connection_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "port", value);
	return 0;
}

static int set_xmpp_connection_server_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "port", value);
			return 0;
	}
	return 0;
}

/**************************************************************************
* LINKER
***************************************************************************/
static int  get_xmpp_connection_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	char *conn_instance;

	if (data) {
		dmuci_get_value_by_section_string((struct uci_section *)data, "connection_instance", &conn_instance);
		dmasprintf(linker,"xmppc:%s", conn_instance);
	} else
		*linker = "";
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.XMPP.Connection.{i}.!UCI:cwmp_xmpp/xmpp_connection/dmmap_cwmp_xmpp*/
static int browsexmpp_connectionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *iconnection = NULL, *iconnection_last = NULL;
	struct uci_section *s = NULL;

	uci_foreach_sections("cwmp_xmpp", "xmpp_connection", s) {
		iconnection = handle_update_instance(1, dmctx, &iconnection_last, update_instance_alias, 3, s, "connection_instance", "connection_instance_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, iconnection) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.XMPP.Connection.{i}.!UCI:cwmp_xmpp/xmpp_connection_server/dmmap_cwmp_xmpp*/
static int browsexmpp_connection_serverInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *iconnectionserver = NULL, *iconnectionserver_last = NULL, *prev_connection_instance;
	struct uci_section *s = NULL, *connsection = (struct uci_section *)prev_data;

	dmuci_get_value_by_section_string(connsection, "connection_instance", &prev_connection_instance);
	uci_foreach_option_eq("cwmp_xmpp", "xmpp_connection_server", "id_connection", prev_connection_instance, s) {
		iconnectionserver = handle_update_instance(1, dmctx, &iconnectionserver_last, update_instance_alias, 3, s, "connection_server_instance", "connection_server_instance_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, iconnectionserver) == DM_STOP)
			break;
	}
	return 0;
}

/* *** Device.XMPP. *** */
DMOBJ tXMPPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Connection", &DMWRITE, add_xmpp_connection, delete_xmpp_connection, NULL, browsexmpp_connectionInst, NULL, NULL, NULL, tXMPPConnectionObj, tXMPPConnectionParams, get_xmpp_connection_linker, BBFDM_BOTH},
{0}
};

DMLEAF tXMPPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ConnectionNumberOfEntries", &DMREAD, DMT_UNINT, get_xmpp_connection_nbr_entry, NULL, NULL, NULL, BBFDM_BOTH},
{"SupportedServerConnectAlgorithms", &DMREAD, DMT_STRING, get_xmpp_connection_supported_server_connect_algorithms, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.XMPP.Connection.{i}. *** */
DMOBJ tXMPPConnectionObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Server", &DMREAD, NULL, NULL, NULL, browsexmpp_connection_serverInst, NULL, NULL, NULL, NULL, tXMPPConnectionServerParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tXMPPConnectionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_connection_enable, set_connection_enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_xmpp_connection_alias, set_xmpp_connection_alias, NULL, NULL, BBFDM_BOTH},
{"Username", &DMWRITE, DMT_STRING, get_xmpp_connection_username, set_xmpp_connection_username, NULL, NULL, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_xmpp_connection_password, set_xmpp_connection_password, NULL, NULL, BBFDM_BOTH},
{"Domain", &DMWRITE, DMT_STRING, get_xmpp_connection_domain, set_xmpp_connection_domain, NULL, NULL, BBFDM_BOTH},
{"Resource", &DMWRITE, DMT_STRING, get_xmpp_connection_resource, set_xmpp_connection_resource, NULL, NULL, BBFDM_BOTH},
{"ServerConnectAlgorithm", &DMWRITE, DMT_STRING, get_xmpp_connection_server_connect_algorithm, set_xmpp_connection_server_connect_algorithm, NULL, NULL, BBFDM_BOTH},
{"KeepAliveInterval", &DMWRITE, DMT_LONG, get_xmpp_connection_keepalive_interval, set_xmpp_connection_keepalive_interval, NULL, NULL, BBFDM_BOTH},
{"ServerConnectAttempts", &DMWRITE, DMT_UNINT, get_xmpp_connection_server_attempts, set_xmpp_connection_server_attempts, NULL, NULL, BBFDM_BOTH},
{"ServerRetryInitialInterval", &DMWRITE, DMT_UNINT, get_xmpp_connection_retry_initial_interval, set_xmpp_connection_retry_initial_interval, NULL, NULL, BBFDM_BOTH},
{"ServerRetryIntervalMultiplier", &DMWRITE, DMT_UNINT, get_xmpp_connection_retry_interval_multiplier, set_xmpp_connection_retry_interval_multiplier, NULL, NULL, BBFDM_BOTH},
{"ServerRetryMaxInterval", &DMWRITE, DMT_UNINT, get_xmpp_connection_retry_max_interval, set_xmpp_connection_retry_max_interval, NULL, NULL, BBFDM_BOTH},
{"UseTLS", &DMWRITE, DMT_BOOL, get_xmpp_connection_server_usetls, set_xmpp_connection_server_usetls, NULL, NULL, BBFDM_BOTH},
{"JabberID", &DMREAD, DMT_STRING, get_xmpp_connection_jabber_id, NULL, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_xmpp_connection_status, NULL, NULL, NULL, BBFDM_BOTH},
{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_xmpp_connection_server_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.XMPP.Connection.{i}.Server.{i}. *** */
DMLEAF tXMPPConnectionServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_xmpp_connection_server_enable, set_xmpp_connection_server_enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_xmpp_connection_server_alias, set_xmpp_connection_server_alias, NULL, NULL, BBFDM_BOTH},
{"ServerAddress", &DMWRITE, DMT_STRING, get_xmpp_connection_server_server_address, set_xmpp_connection_server_server_address, NULL, NULL, BBFDM_BOTH},
{"Port", &DMWRITE, DMT_UNINT, get_xmpp_connection_server_port, set_xmpp_connection_server_port, NULL, NULL, BBFDM_BOTH},
{0}
};
