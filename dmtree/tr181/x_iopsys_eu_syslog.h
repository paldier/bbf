/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#ifndef __SE_SYSLOG_H
#define __SE_SYSLOG_H

#include <libbbf_api/dmcommon.h>

extern DMLEAF tSe_SyslogCfgParam[];

int get_server_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_server_port_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_remote_log_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_server_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_server_port_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_remote_log_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
