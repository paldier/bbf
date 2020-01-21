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
#include <libbbf_api/dmbbf.h>
#include <libbbf_api/dmuci.h>
#include <libbbf_api/dmubus.h>
#include <libbbf_api/dmcommon.h>
#include "x_iopsys_eu_logincfg.h"

/*** DMROOT.X_IOPSYS_EU_LoginCfg. ***/
DMLEAF tSe_LoginCfgParam[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"AdminPassword", &DMWRITE, DMT_STRING, get_empty, set_x_bcm_admin_password, NULL, NULL, BBFDM_BOTH},
{"SupportPassword", &DMWRITE, DMT_STRING, get_empty, set_x_bcm_support_password, NULL, NULL, BBFDM_BOTH},
{"UserPassword", &DMWRITE, DMT_STRING, get_empty, set_x_bcm_user_password, NULL, NULL, BBFDM_BOTH},
{"RootPassword", &DMWRITE, DMT_STRING, get_empty, set_x_bcm_root_password, NULL, NULL, BBFDM_BOTH},
{0}
};

int set_x_bcm_password(char *refparam, struct dmctx *ctx, int action, char *value, char *user_type)
{
	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value("passwords", user_type, "password", value);
			return 0;
	}
	return 0;
}

int set_x_bcm_admin_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	set_x_bcm_password(refparam, ctx, action, value, "admin");
	return 0;
}

int set_x_bcm_support_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	set_x_bcm_password(refparam, ctx, action, value, "support");
	return 0;
}

int set_x_bcm_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	set_x_bcm_password(refparam, ctx, action, value, "user");
	return 0;
}

int set_x_bcm_root_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	set_x_bcm_password(refparam, ctx, action, value, "root");
	return 0;
}
