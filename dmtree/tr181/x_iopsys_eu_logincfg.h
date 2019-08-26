/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2015 Inteno Broadband Technology AB
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#ifndef __SE_LOGINCFG_H
#define __SE_LOGINCFG_H

extern DMLEAF tSe_LoginCfgParam[];

int set_x_bcm_admin_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_support_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_root_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
