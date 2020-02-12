/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#ifndef __SE_OWSD_H
#define __SE_OWSD_H

#include <libbbf_api/dmcommon.h>

extern DMLEAF XIopsysEuOwsdParams[];
extern DMOBJ XIopsysEuOwsdObj[];
extern DMLEAF X_IOPSYS_EU_ListenObjParams[];
extern DMLEAF UbusProxyParams[];

int browseXIopsysEuOwsdListenObj(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int add_owsd_listen(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_owsd_listen_instance(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);


int get_x_iopsys_eu_owsd_global_sock(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_global_sock(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_global_redirect(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_global_redirect(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_listenobj_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_listenobj_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_listenobj_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_listenobj_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_listenobj_ipv6_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_listenobj_ipv6_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_listenobj_whitelist_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_listenobj_whitelist_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_listenobj_whitelist_dhcp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_listenobj_whitelist_dhcp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_listenobj_origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_listenobj_origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_listenobj_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_listenobj_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_ubus_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_ubus_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_ubus_proxy_cert(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_ubus_proxy_cert(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_ubus_proxy_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_ubus_proxy_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_ubus_proxy_ca(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_ubus_proxy_ca(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_ubus_cert(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_ubus_cert(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_ubus_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_ubus_key(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_x_iopsys_eu_owsd_ubus_ca(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_x_iopsys_eu_owsd_ubus_ca(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
