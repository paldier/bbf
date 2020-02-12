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

#ifndef __SE_LOGINCFG_H
#define __SE_LOGINCFG_H

#include <libbbf_api/dmcommon.h>

extern DMLEAF tSe_LoginCfgParam[];

int set_x_bcm_admin_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_support_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_root_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
