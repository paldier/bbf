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

#ifndef __SE_IGMP_H
#define __SE_IGMP_H

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