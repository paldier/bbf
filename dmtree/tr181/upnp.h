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

#ifndef __UPNP_H
#define __UPNP_H

extern DMLEAF tUPnPDeviceParams[];
extern DMOBJ tUPnPObj[];

int get_upnp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_upnp_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_upnp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
