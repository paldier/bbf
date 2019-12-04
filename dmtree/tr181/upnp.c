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
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Device", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUPnPDeviceParams, NULL, BBFDM_BOTH},
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
	pid_t pid = get_pid("miniupnpd");
	if (pid < 0) {
		*value = "0";
	}
	else {
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
			if(b){
				dmuci_set_value("upnpd", "config", "enabled", "1");
				dmuci_set_value("upnpd", "config", "enable_natpmp", "1");
				dmuci_set_value("upnpd", "config", "enable_upnp", "1");
			} else {
				dmuci_set_value("upnpd", "config", "enabled", "0");
			}
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
