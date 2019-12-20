/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __IP_H
#define __IP_H

struct ip_args
{
	struct uci_section *ip_sec;
	char *ip_4address;
};

struct ipv6_args
{
	struct uci_section *ip_sec;
	char *ip_6address;
	char *ip_6mask;
	char *ip_6preferred;
	char *ip_6valid;
};

struct ipv6prefix_args
{
	struct uci_section *ip_sec;
	char *ip_6prefixaddress;
	char *ip_6prefixmask;
	char *ip_6prefixpreferred;
	char *ip_6prefixvalid;
};

extern DMOBJ tIPObj[];
extern DMLEAF tIPParams[];
extern DMOBJ tIPInterfaceObj[];
extern DMLEAF tIPInterfaceParams[];
extern DMLEAF tIPInterfaceIPv4AddressParams[];
extern DMLEAF tIPInterfaceIPv6AddressParams[];
extern DMLEAF tIPInterfaceIPv6PrefixParams[];
extern DMLEAF tIPInterfaceStatsParams[];
extern DMLEAF tIPInterfaceTWAMPReflectorParams[];

unsigned char get_ipv4_finform(char *refparam, struct dmctx *dmctx, void *data, char *instance);
unsigned char get_ipv6_finform(char *refparam, struct dmctx *dmctx, void *data, char *instance);

int get_linker_ip_interface(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);
int get_linker_ipv6_prefix(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);

int browseIPIfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseIfaceIPv4Inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseIfaceIPv6Inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseIfaceIPv6PrefixInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseIPInterfaceTWAMPReflectorInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int add_ip_interface(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_ip_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int add_ipv4(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_ipv4(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int add_ipv6(char *refparam, struct dmctx *ctx, void *data, char **instancepara);
int delete_ipv6(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int add_ipv6_prefix(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delete_ipv6_prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int addObjIPInterfaceTWAMPReflector(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjIPInterfaceTWAMPReflector(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

int get_IP_IPv4Capable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IP_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IP_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IP_IPv4Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IP_IPv6Capable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IP_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IP_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IP_IPv6Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IP_ULAPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IP_ULAPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IP_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int get_ipv4_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_ipv4_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_firewall_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_firewall_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_ipv4_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_ipv4_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_ipv4_netmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_ipv4_netmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_ipv4_addressing_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_ipv4_addressing_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

int get_IPInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_IPv4Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_IPv6Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_Router(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_Router(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_MaxMTUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_MaxMTUSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterface_Loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterface_Loopback(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterface_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterface_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterface_IPv6PrefixNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterface_TWAMPReflectorNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int get_IPInterfaceIPv6Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Address_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Address_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterfaceIPv6Address_IPAddressStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterfaceIPv6Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Address_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Address_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterfaceIPv6Address_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Address_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

int get_IPInterfaceIPv6Prefix_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Prefix_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Prefix_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterfaceIPv6Prefix_PrefixStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterfaceIPv6Prefix_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Prefix_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Prefix_Origin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterfaceIPv6Prefix_StaticType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Prefix_StaticType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Prefix_ParentPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Prefix_ParentPrefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Prefix_ChildPrefixBits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Prefix_ChildPrefixBits(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

int get_IPInterfaceTWAMPReflector_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceTWAMPReflector_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceTWAMPReflector_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_IPInterfaceTWAMPReflector_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceTWAMPReflector_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceTWAMPReflector_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceTWAMPReflector_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceTWAMPReflector_MaximumTTL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceTWAMPReflector_MaximumTTL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceTWAMPReflector_IPAllowedList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceTWAMPReflector_IPAllowedList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_IPInterfaceTWAMPReflector_PortAllowedList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_IPInterfaceTWAMPReflector_PortAllowedList(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

int get_ip_interface_statistics_tx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_rx_bytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_tx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_rx_packets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_tx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_rx_errors(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_tx_discardpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_rx_discardpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_tx_unicastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_rx_unicastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_tx_multicastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_rx_multicastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_tx_broadcastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_rx_broadcastpackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_ip_interface_statistics_rx_unknownprotopackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

#endif
