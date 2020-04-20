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

#ifndef __SE_MLD_H
#define __SE_MLD_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ X_IOPSYS_EU_MLDObj[];
extern DMLEAF X_IOPSYS_EU_MLDParams[];

extern DMOBJ X_IOPSYS_EU_MLDSnoopingObj[];
extern DMLEAF X_IOPSYS_EU_MLDSnoopingParams[];
extern DMOBJ MLDSnoopingCLientGroupObj[];
extern DMLEAF MLDSnoopingClientGroupParams[];
extern DMLEAF MLDSnoopingClientGroupStatsParams[];
extern DMLEAF MLDSnoopingClientGroupAssociatedDeviceParams[];
extern DMLEAF MLDSnoopingFilterParams[];

extern DMOBJ X_IOPSYS_EU_MLDProxyObj[];
extern DMLEAF X_IOPSYS_EU_MLDProxyParams[];
extern DMLEAF MLDProxyInterfaceParams[];
extern DMOBJ MLDProxyCLientGroupObj[];
extern DMLEAF MLDProxyClientGroupParams[];
extern DMLEAF MLDProxyClientGroupStatsParams[];
extern DMLEAF MLDProxyClientGroupAssociatedDeviceParams[];
extern DMLEAF MLDProxyFilterParams[];
#endif
