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

#ifndef __UPNP_H
#define __UPNP_H

extern DMLEAF tUPnPDeviceParams[];
extern DMOBJ tUPnPObj[];

int get_upnp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_upnp_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_upnp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
