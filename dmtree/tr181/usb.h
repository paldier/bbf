/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __USB_H
#define __USB_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tUSBObj[];
extern DMLEAF tUSBParams[];
extern DMOBJ tUSBInterfaceObj[];
extern DMLEAF tUSBInterfaceParams[];
extern DMLEAF tUSBInterfaceStatsParams[];
extern DMLEAF tUSBPortParams[];
extern DMOBJ tUSBUSBHostsObj[];
extern DMLEAF tUSBUSBHostsParams[];
extern DMOBJ tUSBUSBHostsHostObj[];
extern DMLEAF tUSBUSBHostsHostParams[];
extern DMOBJ tUSBUSBHostsHostDeviceObj[];
extern DMLEAF tUSBUSBHostsHostDeviceParams[];
extern DMOBJ tUSBUSBHostsHostDeviceConfigurationObj[];
extern DMLEAF tUSBUSBHostsHostDeviceConfigurationParams[];
extern DMLEAF tUSBUSBHostsHostDeviceConfigurationInterfaceParams[];

#endif //__USB_H

