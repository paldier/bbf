/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2019 iopsys Software Solutions AB
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#include <uci.h>
#include <stdio.h>
#include <ctype.h>
#include "dmuci.h"
#include "dmubus.h"
#include "dmbbf.h"
#include "dmcommon.h"
#include "upnp.h"

/* *** Device.UPnP. *** */
DMOBJ tUPnPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextobj, leaf, linker, bbfdm_type*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUPnPDeviceParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.UPnP.Device. *** */
DMLEAF tUPnPDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_upnp_enable, set_upnp_enable, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"Status", &DMREAD, DMT_STRING, get_upnp_status, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*#Device.UPnP.Device.Enable!UCI:upnpd/upnpd,config/enabled*/
int get_upnp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("upnpd","config","enabled", value);
	if ((*value)[0] == '\0') {
		*value = "1";
	}
	return 0;
}

int set_upnp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	int check;
	switch (action) {
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			if(b)
				dmuci_set_value("upnpd", "config", "enabled", "");
			else 
				dmuci_set_value("upnpd", "config", "enabled", "0");
			return 0;
	}
	return 0;
}

int get_upnp_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	pid_t pid = get_pid("miniupnpd");
	
	if (pid < 0) {
		*value = "Down";
	}
	else {
		*value = "Up";
	}
	return 0;
}
