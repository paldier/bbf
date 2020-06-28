/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#include "x_iopsys_eu_syslog.h"


static int get_server_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("system", "@system[0]", "log_ip", value);
	return 0;
}

static int set_server_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:			
			return 0;
		case VALUESET:
			dmuci_set_value("system", "@system[0]", "log_ip", value);
			return 0;
	}
	return 0;
}
	
static int get_server_port_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("system", "@system[0]", "log_port", "514");
	return 0;
}

static int set_server_port_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:			
			return 0;
		case VALUESET:
			dmuci_set_value("system", "@system[0]", "log_port", value);
			return 0;
	}
	return 0;
}

static int get_remote_log_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_option_value_fallback_def("system", "@system[0]", "conloglevel", "7");
	return 0;
}

static int set_remote_log_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:			
			return 0;
		case VALUESET:
			dmuci_set_value("system", "@system[0]", "conloglevel", value);
			return 0;
	}
	return 0;
}

/*** DMROOT.X_IOPSYS_EU_Syslog. ***/
DMLEAF tSe_SyslogParam[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ServerIPAddress", &DMWRITE, DMT_STRING, get_server_ip_address, set_server_ip_address, NULL, NULL, BBFDM_BOTH},
{"ServerPort", &DMWRITE, DMT_UNINT, get_server_port_number, set_server_port_number, NULL, NULL, BBFDM_BOTH},
{"ConsoleLogLevel", &DMWRITE, DMT_UNINT, get_remote_log_level, set_remote_log_level, NULL, NULL, BBFDM_BOTH},
{0}
};
