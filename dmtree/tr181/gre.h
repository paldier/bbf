/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __GRE_H
#define __GRE_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tGREObj[];
extern DMLEAF tGREParams[];
extern DMOBJ tGRETunnelObj[];
extern DMLEAF tGRETunnelParams[];
extern DMLEAF tGRETunnelStatsParams[];
extern DMOBJ tGRETunnelInterfaceObj[];
extern DMLEAF tGRETunnelInterfaceParams[];
extern DMLEAF tGRETunnelInterfaceStatsParams[];
extern DMLEAF tGREFilterParams[];

#endif //__GRE_H

