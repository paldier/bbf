/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Rahul Thakur <rahul.thakur@iopsys.eu>
 *
 */ 

#ifndef __SE_IGMP_H
#define __SE_IGMP_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ X_IOPSYS_EU_IGMPObj[];
extern DMLEAF X_IOPSYS_EU_IGMPParams[];

extern DMOBJ X_IOPSYS_EU_IGMPSnoopingObj[];
extern DMLEAF X_IOPSYS_EU_IGMPSnoopingParams[];
extern DMOBJ IGMPSnoopingCLientGroupObj[];
extern DMLEAF IGMPSnoopingClientGroupParams[];
extern DMLEAF IGMPSnoopingClientGroupStatsParams[];
extern DMLEAF IGMPSnoopingClientGroupAssociatedDeviceParams[];
extern DMLEAF IGMPSnoopingFilterParams[];

extern DMOBJ X_IOPSYS_EU_IGMPProxyObj[];
extern DMLEAF X_IOPSYS_EU_IGMPProxyParams[];
extern DMLEAF IGMPProxyInterfaceParams[];
extern DMOBJ IGMPProxyCLientGroupObj[];
extern DMLEAF IGMPProxyClientGroupParams[];
extern DMLEAF IGMPProxyClientGroupStatsParams[];
extern DMLEAF IGMPProxyClientGroupAssociatedDeviceParams[];
extern DMLEAF IGMPProxyFilterParams[];
#endif
