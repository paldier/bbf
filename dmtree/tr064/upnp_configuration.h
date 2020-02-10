/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#ifndef UPNP_CONFIGURATION_H
#define UPNP_CONFIGURATION_H
#include <libbbf_api/dmbbf.h>

struct upnp_configuration_args{
	struct uci_section *upnpConfiguration_sec;
	char *systemName;
	char *ipv4address;
	char *ipv6address;
	char *addressingType;
	char *ipAddressType;
	char *prefix;
	char **dnsservers;
	char *netmask;
	char *gateway;
	int numberOfEntries;
};

int upnp_configuration_get_hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_IPInterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_SystemName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv4_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv4_addressingtype(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv4_dnssevers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv4_subnetmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv4_defaultgateway(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv6_addressnumberofentries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv6_dnsservers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv6_defaultgateway(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv6_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv6_IPAddressType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv6_addressingtype(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int upnp_configuration_get_ipv6_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int upnp_configuration_set_hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int upnp_configuration_set_ipv4_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int upnp_configuration_set_ipv4_addressingtype(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int upnp_configuration_set_ipv4_dnssevers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int upnp_configuration_set_ipv4_subnetmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int upnp_configuration_set_ipv4_defaultgateway(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

int upnp_configuration_ipinterface_createinstance(char *refparam, struct dmctx *ctx, void *data, char **instance);
int upnp_configuration_ipinterface_deleteinstance(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int upnp_configuration_address_createinstance(char *refparam, struct dmctx *ctx, void *data, char **instance);
int upnp_configuration_address_deleteinstance(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int upnp_browseIPInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int upnp_browseIPv6Address(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

extern DMOBJ upnpConfigurationNetworkObj[];
extern DMLEAF upnpConfigurationNetworkParams[];
extern DMLEAF upnpConfigurationNetworkObjParams[];
extern DMOBJ upnpConfigurationNetworkIPInterfaceObj[];
extern DMLEAF upnpConfigurationNetworkIPInterfaceParams[];
extern DMLEAF upnpConfigurationNetworkIPInterfaceIpv4Params[];
extern DMOBJ upnpConfigurationNetworkIPInterfaceIpv6Obj[];
extern DMLEAF upnpConfigurationNetworkIPInterfaceIpv6Params[];
extern DMOBJ upnpConfigurationNetworkIPInterfaceIpv6AddressParams[];
extern DMOBJ upnpConfigurationObj[];
#endif
