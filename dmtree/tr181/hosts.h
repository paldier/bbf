/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#ifndef __HOSTS_H
#define __HOSTS_H

#include <libbbf_api/dmcommon.h>

struct host_args
{
	json_object *client;
	char *key;
};

extern DMOBJ tHostsObj[];
extern DMLEAF tHostsParams[];
extern DMLEAF tHostsHostParams[];

int browsehostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int get_host_nbr_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_associateddevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_layer3interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_interface_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_interfacename(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_phy_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_interfacetype(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_address_source(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_leasetime_remaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_host_dhcp_client(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

#endif
