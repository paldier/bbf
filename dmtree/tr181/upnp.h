/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 */

#ifndef __UPNP_H
#define __UPNP_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tUPnPObj[];
extern DMOBJ tUPnPDeviceObj[];
extern DMLEAF tUPnPDeviceParams[];
extern DMLEAF tUPnPDeviceCapabilitiesParams[];
extern DMOBJ tUPnPDiscoveryObj[];
extern DMLEAF tUPnPDiscoveryParams[];
extern DMLEAF tUPnPDiscoveryRootDeviceParams[];
extern DMLEAF tUPnPDiscoveryDeviceParams[];
extern DMLEAF tUPnPDiscoveryServiceParams[];
extern DMOBJ tUPnPDescriptionObj[];
extern DMLEAF tUPnPDescriptionParams[];
extern DMLEAF tUPnPDescriptionDeviceDescriptionParams[];
extern DMLEAF tUPnPDescriptionDeviceInstanceParams[];
extern DMLEAF tUPnPDescriptionServiceInstanceParams[];

#endif //__UPNP_H

