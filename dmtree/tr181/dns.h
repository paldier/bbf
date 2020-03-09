/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#ifndef _DNS_H
#define _DNS_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tDNSObj[];
extern DMLEAF tDNSParams[];
extern DMLEAF tDNSClientParams[];
extern DMOBJ tDNSClientObj[];
extern DMLEAF tDNSClientServerParams[];
extern DMLEAF tDNSRelayParams[];
extern DMOBJ tDNSRelayObj[];
extern DMLEAF tDNSRelayForwardingParams[];
extern DMOBJ tDNSDiagnosticsObj[];
extern DMLEAF tDNSDiagnosticsNSLookupDiagnosticsParams[];
extern DMOBJ tDNSDiagnosticsNSLookupDiagnosticsObj[];
extern DMLEAF tDNSDiagnosticsNSLookupDiagnosticsResultParams[];

#endif
