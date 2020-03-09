/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *		Author: Mohamed Kallel <mohamed.kallel@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 */

#include "x_iopsys_eu_power_mgmt.h"


static int get_pwr_mgmt_value_ethapd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("power_mgmt", "power_mgmt", "ethapd", value);
	return 0;
}

static int get_pwr_mgmt_value_eee(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("power_mgmt", "power_mgmt", "eee", value);
	return 0;
}

static int get_pwr_nbr_interfaces_up(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char buf[256];
	int pp;

	*value = "";
	pp = dmcmd("pwrctl", 1, "show");
	if (pp) {
		dmcmd_read(pp, buf, 256);
		close(pp);
		return 0;
	}
	return 0;
}

static int get_pwr_nbr_interfaces_down(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char buf[256];
	int pp;

	*value = "";
	pp = dmcmd("pwrctl", 1, "show");
	if (pp) {
		dmcmd_read(pp, buf, 256);
		close(pp);
		return 0;
	}
	return 0;
}

static int set_power_mgmt_param_ethapd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("power_mgmt", "power_mgmt", "ethapd", b ? "1" : "0");
			return 0;
	}
	return 0;
}

static int set_power_mgmt_param_eee(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("power_mgmt", "power_mgmt", "eee", b ? "1" : "0");
			return 0;
	}
	return 0;
}

/*** DMROOT.X_IOPSYS_EU_PowerManagement. ***/
DMLEAF tSe_PowerManagementParam[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"EthernetAutoPowerDownEnable", &DMWRITE, DMT_BOOL, get_pwr_mgmt_value_ethapd, set_power_mgmt_param_ethapd, NULL, NULL, BBFDM_BOTH},
{"EnergyEfficientEthernetEnable", &DMWRITE, DMT_BOOL, get_pwr_mgmt_value_eee, set_power_mgmt_param_eee, NULL, NULL, BBFDM_BOTH},
{"NumberOfEthernetInterfacesPoweredUp", &DMREAD, DMT_UNINT, get_pwr_nbr_interfaces_up, NULL, NULL, NULL, BBFDM_BOTH},
{"NumberOfEthernetInterfacesPoweredDown", &DMREAD, DMT_UNINT, get_pwr_nbr_interfaces_down, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
