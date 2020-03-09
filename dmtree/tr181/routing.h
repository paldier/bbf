/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __ROUTING_H
#define __ROUTING_H

#include <libbbf_api/dmcommon.h>

extern struct dm_permession_s DMRouting;

extern DMOBJ tRoutingObj[];
extern DMLEAF tRoutingParams[];
extern DMOBJ tRoutingRouterObj[];
extern DMLEAF tRoutingRouterParams[];
extern DMLEAF tRoutingRouterIPv4ForwardingParams[];
extern DMLEAF tRoutingRouterIPv6ForwardingParams[];
extern DMOBJ tRoutingRouteInformationObj[];
extern DMLEAF tRoutingRouteInformationParams[];
extern DMLEAF tRoutingRouteInformationInterfaceSettingParams[];

#endif
