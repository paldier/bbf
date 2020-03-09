/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: AMIN Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#ifndef __DSL_H
#define __DSL_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tDSLObj[];
extern DMLEAF tDSLParams[];
extern DMOBJ tDSLLineObj[];
extern DMLEAF tDSLLineParams[];
extern DMOBJ tDSLLineStatsObj[];
extern DMLEAF tDSLLineStatsParams[];
extern DMLEAF tDSLLineStatsTotalParams[];
extern DMLEAF tDSLLineStatsShowtimeParams[];
extern DMLEAF tDSLLineStatsLastShowtimeParams[];
extern DMLEAF tDSLLineStatsCurrentDayParams[];
extern DMLEAF tDSLLineStatsQuarterHourParams[];
extern DMOBJ tDSLChannelObj[];
extern DMLEAF tDSLChannelParams[];
extern DMOBJ tDSLChannelStatsObj[];
extern DMLEAF tDSLChannelStatsParams[];
extern DMLEAF tDSLChannelStatsTotalParams[];
extern DMLEAF tDSLChannelStatsShowtimeParams[];
extern DMLEAF tDSLChannelStatsLastShowtimeParams[];
extern DMLEAF tDSLChannelStatsCurrentDayParams[];
extern DMLEAF tDSLChannelStatsQuarterHourParams[];

#endif //__DSL_H
