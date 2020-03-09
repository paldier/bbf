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

#include <libbbf_api/dmcommon.h>

extern DMOBJ tIPObj[];
extern DMLEAF tIPParams[];
extern DMOBJ tIPInterfaceObj[];
extern DMLEAF tIPInterfaceParams[];
extern DMLEAF tIPInterfaceIPv4AddressParams[];
extern DMLEAF tIPInterfaceIPv6AddressParams[];
extern DMLEAF tIPInterfaceIPv6PrefixParams[];
extern DMLEAF tIPInterfaceStatsParams[];
extern DMLEAF tIPInterfaceTWAMPReflectorParams[];

#endif
