/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __DIAGNOSTICS_H
#define __DIAGNOSTICS_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tIPDiagnosticsObj[];
extern DMLEAF tIPDiagnosticsParams[];
extern DMLEAF tIPDiagnosticsIPPingParams[];
extern DMOBJ tIPDiagnosticsTraceRouteObj[];
extern DMLEAF tIPDiagnosticsTraceRouteParams[];
extern DMLEAF tIPDiagnosticsTraceRouteRouteHopsParams[];
extern DMOBJ tIPDiagnosticsDownloadDiagnosticsObj[];
extern DMLEAF tIPDiagnosticsDownloadDiagnosticsParams[];
extern DMLEAF tIPDiagnosticsDownloadDiagnosticsPerConnectionResultParams[];
extern DMOBJ tIPDiagnosticsUploadDiagnosticsObj[];
extern DMLEAF tIPDiagnosticsUploadDiagnosticsParams[];
extern DMLEAF tIPDiagnosticsUploadDiagnosticsPerConnectionResultParams[];
extern DMLEAF tIPDiagnosticsUDPEchoConfigParams[];
extern DMLEAF tIPDiagnosticsUDPEchoDiagnosticsParams[];
extern DMLEAF tIPDiagnosticsServerSelectionDiagnosticsParams[];

#endif
