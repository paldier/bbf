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

#ifndef __SE_ICE_H
#define __SE_ICE_H

extern DMLEAF tSe_IceParam[];

int get_ice_cloud_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ice_cloud_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_ice_cloud_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_ice_cloud_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
