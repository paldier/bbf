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

#include "x_iopsys_eu_ice.h"

/*** DMROOT.X_IOPSYS_EU_ICE. ***/
DMLEAF tSe_IceParam[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_ice_cloud_enable, set_ice_cloud_enable, NULL, NULL, BBFDM_BOTH},
{"Server", &DMWRITE, DMT_STRING, get_ice_cloud_server, set_ice_cloud_server, NULL, NULL, BBFDM_BOTH},
{0}
};

int get_ice_cloud_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	bool b;
	dmuci_get_option_value_string("ice", "cloud", "enabled", value);

	string_to_bool(*value, &b);
	if (b)
		*value = "1";
	else
		*value = "0";
	return 0;
}

int set_ice_cloud_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if (b)
				dmuci_set_value("ice", "cloud", "enabled", "1");
			else
				dmuci_set_value("ice", "cloud", "enabled", "0");
			return 0;
	}
	return 0;
}

int get_ice_cloud_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("ice", "cloud", "server", value);
	return 0;
}

int set_ice_cloud_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			if (value[0] == '\0')
				return 0;
			dmuci_set_value("ice", "cloud", "server", value);
			return 0;
	}
	return 0;
}
