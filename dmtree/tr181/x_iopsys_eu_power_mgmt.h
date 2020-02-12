/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 */

#ifndef __POWER_MGMT_H
#define __POWER_MGMT_H

#include <libbbf_api/dmcommon.h>

extern DMLEAF tSe_PowerManagementParam[];

int get_pwr_mgmt_value_ethapd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_pwr_mgmt_value_eee(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_pwr_nbr_interfaces_up(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_pwr_nbr_interfaces_down(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_power_mgmt_param_ethapd(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_power_mgmt_param_eee(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
#endif
