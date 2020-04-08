/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __QOS_H
#define __QOS_H

#include <libbbf_api/dmcommon.h>
#include "dmentry.h"

extern DMOBJ tQoSObj[];
extern DMLEAF tQoSParams[];
extern DMLEAF tQoSClassificationParams[];
extern DMLEAF tQoSAppParams[];
extern DMLEAF tQoSFlowParams[];
extern DMLEAF tQoSPolicerParams[];
extern DMLEAF tQoSQueueParams[];
extern DMLEAF tQoSQueueStatsParams[];
extern DMLEAF tQoSShaperParams[];

#endif //__QOS_H

