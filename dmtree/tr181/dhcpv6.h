/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __DHCPV6_H
#define __DHCPV6_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tDHCPv6Obj[];
extern DMLEAF tDHCPv6Params[];
extern DMOBJ tDHCPv6ClientObj[];
extern DMLEAF tDHCPv6ClientParams[];
extern DMLEAF tDHCPv6ClientServerParams[];
extern DMLEAF tDHCPv6ClientSentOptionParams[];
extern DMLEAF tDHCPv6ClientReceivedOptionParams[];
extern DMOBJ tDHCPv6ServerObj[];
extern DMLEAF tDHCPv6ServerParams[];
extern DMOBJ tDHCPv6ServerPoolObj[];
extern DMLEAF tDHCPv6ServerPoolParams[];
extern DMOBJ tDHCPv6ServerPoolClientObj[];
extern DMLEAF tDHCPv6ServerPoolClientParams[];
extern DMLEAF tDHCPv6ServerPoolClientIPv6AddressParams[];
extern DMLEAF tDHCPv6ServerPoolClientIPv6PrefixParams[];
extern DMLEAF tDHCPv6ServerPoolClientOptionParams[];
extern DMLEAF tDHCPv6ServerPoolOptionParams[];

#endif //__DHCPV6_H

