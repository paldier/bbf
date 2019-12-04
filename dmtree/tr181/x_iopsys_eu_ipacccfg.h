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

#ifndef __SE_IPACCCFG_H
#define __SE_IPACCCFG_H

extern DMOBJ tSe_IpAccObj[];
extern DMLEAF tSe_IpAccCfgParam[];
extern DMLEAF tSe_PortForwardingParam[];


int browseport_forwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseAccListInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int add_ipacccfg_port_forwarding(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_ipacccfg_port_forwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

int add_ipacccfg_rule(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_ipacccfg_rule(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

int get_port_forwarding_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_external_zone(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_internal_zone(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_external_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_internal_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_source_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_internal_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_external_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_source_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_port_forwarding_src_mac(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_x_iopsys_eu_cfgobj_address_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_x_bcm_com_ip_acc_list_cfgobj_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_x_bcm_com_ip_acc_list_cfgobj_ipversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_x_bcm_com_ip_acc_list_cfgobj_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_x_bcm_com_ip_acc_list_cfgobj_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_x_iopsys_eu_cfgobj_address_netmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_x_bcm_com_ip_acc_list_cfgobj_acc_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_x_bcm_com_ip_acc_list_cfgobj_target(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int set_port_forwarding_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_external_zone(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_internal_zone(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_external_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_internal_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_source_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_internal_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_external_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_source_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_port_forwarding_src_mac(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_iopsys_eu_cfgobj_address_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_com_ip_acc_list_cfgobj_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_com_ip_acc_list_cfgobj_ipversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_com_ip_acc_list_cfgobj_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_com_ip_acc_list_cfgobj_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_iopsys_eu_cfgobj_address_netmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_com_ip_acc_list_cfgobj_acc_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_x_bcm_com_ip_acc_list_cfgobj_target(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif
