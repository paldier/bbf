/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *
 */

#ifndef __ATM_H
#define __ATM_H

struct atm_args
{
	struct uci_section *atm_sec;
	char *ifname;
};

extern DMOBJ tATMObj[];
extern DMOBJ tATMLinkObj[];
extern DMLEAF tATMLinkParams[];
extern DMLEAF tATMLinkStatsParams[] ;

int browseAtmLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int add_atm_link(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_atm_link(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

int get_atm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_link_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_link_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_destination_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_encapsulation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_stats_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_stats_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_stats_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_atm_stats_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_atm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_atm_link_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_atm_destination_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_atm_encapsulation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

int get_atm_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);

#endif
