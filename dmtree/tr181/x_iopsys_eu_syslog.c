/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2019 iopsys Software Solutions AB
 *		Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#include <uci.h>
#include <stdio.h>
#include <ctype.h>
#include "dmuci.h"
#include "dmubus.h"
#include "dmbbf.h"
#include "dmcommon.h"
#include "x_iopsys_eu_syslog.h"

/*** DMROOT.X_IOPSYS_EU_SyslogCfg. ***/
DMLEAF tSe_SyslogCfgParam[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ServerIPAddress", &DMWRITE, DMT_STRING, get_server_ip_address, set_server_ip_address, NULL, NULL, BBFDM_BOTH},
{"ServerPortNumber", &DMWRITE, DMT_UNINT, get_server_port_number, set_server_port_number, NULL, NULL, BBFDM_BOTH},
{"RemoteLogLevel", &DMWRITE, DMT_UNINT, get_remote_log_level, set_remote_log_level, NULL, NULL, BBFDM_BOTH},
{0}
};

int get_server_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("system", "@system[0]", "log_ip", value);
	return 0;
}

int set_server_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
	
int get_server_port_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp;
	dmuci_get_option_value_string("system", "@system[0]", "log_port", &tmp);
	if (tmp[0] == '\0')
		*value = "514";
	else
		*value = tmp;
	return 0;
}

int set_server_port_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_remote_log_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *tmp;
	dmuci_get_option_value_string("system", "@system[0]", "conloglevel", &tmp);
	if (tmp[0] == '\0')
		*value = "7";
	else
		*value = tmp;
	return 0;
}

int set_remote_log_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
