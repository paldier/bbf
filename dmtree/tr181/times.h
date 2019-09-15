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

#ifndef __TIMES_H
#define __TIMES_H
#include "dmbbf.h"

extern DMLEAF tTimeParams[];

int get_time_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_ntpserver1(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_ntpserver2(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_ntpserver3(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_ntpserver4(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_ntpserver5(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_CurrentLocalTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_LocalTimeZone(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_time_source_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_local_time_zone_olson(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_time_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_time_ntpserver1(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_time_ntpserver2(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_time_ntpserver3(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_time_ntpserver4(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_time_ntpserver5(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_time_LocalTimeZone(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_time_source_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
