/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2015 Inteno Broadband Technology AB
 *		Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *
 */

#ifndef __SE_SYSLOG_H
#define __SE_SYSLOG_H

extern DMLEAF tSe_SyslogCfgParam[];

int get_server_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_server_port_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_remote_log_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_server_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_server_port_number(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_remote_log_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
