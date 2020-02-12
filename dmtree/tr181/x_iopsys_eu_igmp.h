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

#ifndef __SE_IGMP_H
#define __SE_IGMP_H

#include <libbbf_api/dmcommon.h>

extern DMLEAF tSe_IgmpParam[];

int get_igmp_dscp_mark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_dscp_mark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_proxy_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_proxy_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_default_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_default_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_query_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_query_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_last_member_queryinterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_last_member_queryinterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_robustness_value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_robustness_value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_multicast_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_multicast_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_fastleave_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_fastleave_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_joinimmediate_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_joinimmediate_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_maxgroup(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_maxgroup(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_maxsources(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_maxsources(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_maxmembers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_maxmembers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_snooping_mode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_igmp_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_igmp_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
