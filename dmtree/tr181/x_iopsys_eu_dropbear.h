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

#ifndef __SE_DROPBEAR_H
#define __SE_DROPBEAR_H

#include <libbbf_api/dmcommon.h>

extern DMLEAF X_IOPSYS_EU_DropbearParams[];

int add_dropbear_instance(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_dropbear_instance(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int browseXIopsysEuDropbear(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

#endif
