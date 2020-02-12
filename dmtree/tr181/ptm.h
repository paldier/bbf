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

#ifndef __PTM_H
#define __PTM_H

#include <libbbf_api/dmcommon.h>

struct ptm_args
{
	struct uci_section *ptm_sec;
	char *ifname;
};

extern DMOBJ tPTMObj[];
extern DMOBJ tPTMLinkObj[];
extern DMLEAF tPTMLinkStatsParams[];
extern DMLEAF tPTMLinkParams[];

int browsePtmLinkInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int add_ptm_link(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_ptm_link(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

int get_ptm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ptm_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ptm_link_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ptm_lower_layer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ptm_stats_bytes_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ptm_stats_bytes_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ptm_stats_pack_sent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ptm_stats_pack_received(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_ptm_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

int get_ptm_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);

#endif
