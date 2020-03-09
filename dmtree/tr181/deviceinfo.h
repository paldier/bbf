/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 */

#ifndef __DEVICE_INFO_H
#define __DEVICE_INFO_H

#include <libbbf_api/dmcommon.h>

#define UPTIME "/proc/uptime"
#define DEFAULT_CONFIG_DIR "/etc/config/"

extern DMLEAF tDeviceInfoParams[];
extern DMLEAF tCatTvParams[];
extern DMLEAF tDeviceInfoVendorConfigFileParams[];
extern DMLEAF tDeviceInfoVendorLogFileParams[];
extern DMLEAF tDeviceInfoMemoryStatusParams[];
extern DMOBJ tDeviceInfoProcessStatusObj[];
extern DMLEAF tDeviceInfoProcessStatusParams[];
extern DMOBJ tDeviceInfoObj[];
extern DMLEAF tDeviceInfoProcessStatusProcessParams[];

#endif
