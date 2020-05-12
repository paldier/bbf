/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#ifndef __HOSTS_H
#define __HOSTS_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tHostsObj[];
extern DMLEAF tHostsParams[];
extern DMOBJ tHostsHostObj[];
extern DMLEAF tHostsHostParams[];
extern DMLEAF tHostsHostIPv4AddressParams[];
extern DMLEAF tHostsHostIPv6AddressParams[];

#endif //__HOSTS_H
