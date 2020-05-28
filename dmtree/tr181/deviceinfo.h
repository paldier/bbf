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

extern DMLEAF tDeviceInfoParams[];
extern DMLEAF tDeviceInfoVendorConfigFileParams[];
extern DMLEAF tDeviceInfoVendorLogFileParams[];
extern DMLEAF tDeviceInfoMemoryStatusParams[];
extern DMOBJ tDeviceInfoProcessStatusObj[];
extern DMLEAF tDeviceInfoProcessStatusParams[];
extern DMOBJ tDeviceInfoObj[];
extern DMLEAF tDeviceInfoProcessStatusProcessParams[];
extern DMLEAF tDeviceInfoProcessorParams[];

char *get_deviceid_manufacturer();
char *get_deviceid_manufactureroui();
char *get_deviceid_productclass();
char *get_deviceid_serialnumber();
char *get_softwareversion();
int lookup_vcf_name(char *instance, char **value);

#endif
