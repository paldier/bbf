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

#ifndef __DHCP_H
#define __DHCP_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tDHCPv4Obj[];
extern DMOBJ tDHCPv4ServerObj[];
extern DMOBJ tDHCPv4ServerPoolObj[];
extern DMOBJ tDHCPv4ServerPoolClientObj[];
extern DMLEAF tDHCPv4ServerPoolParams[];
extern DMLEAF tDHCPv4ServerPoolAddressParams[];
extern DMLEAF tDHCPv4ServerPoolClientParams[];
extern DMLEAF tDHCPv4ServerPoolClientIPv4AddressParams[];

extern DMLEAF tDHCPv4Params[];
extern DMOBJ tDHCPv4ClientObj[];
extern DMLEAF tDHCPv4ClientParams[];
extern DMLEAF tDHCPv4ClientSentOptionParams[];
extern DMLEAF tDHCPv4ClientReqOptionParams[];
extern DMOBJ tDHCPv4ServerObj[];
extern DMLEAF tDHCPv4ServerParams[];
extern DMLEAF tDHCPv4ServerPoolOptionParams[];
extern DMLEAF tDHCPv4ServerPoolClientIPv4AddressParams[];
extern DMLEAF tDHCPv4ServerPoolClientOptionParams[];
extern DMOBJ tDHCPv4RelayObj[];
extern DMLEAF tDHCPv4RelayParams[];
extern DMLEAF tDHCPv4RelayForwardingParams[];

int set_section_order(char *package, char *dmpackage, char* sect_type, struct uci_section *dmmap_sect, struct uci_section *conf, int set_force, char* order);

#endif
