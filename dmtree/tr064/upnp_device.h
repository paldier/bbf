/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2019 iopsys Software Solutions AB
 *	  Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#ifndef __UPNPDEVICE_H
#define __UPNPDEVICE_H

#ifdef BBF_TR064
extern DMOBJ tEntry098ObjUPNP[];
extern DMOBJ tRoot098ObjUPNP[];
extern DMOBJ tRoot098ObjUPNPDMROOT[];
extern DMOBJ tRoot098ObjUPNPDM[];
extern DMOBJ tRoot098ObjUPNPBBF[];
extern DMOBJ tEntry181ObjUPNP[];
extern DMOBJ tRoot181ObjUPNP[];
extern DMOBJ tRoot181ObjUPNPDMROOT[];
extern DMOBJ tRoot181ObjUPNPDM[];
extern DMOBJ tRoot181ObjUPNPBBF[];
extern UPNP_SUPPORTED_DM tUPNPSupportedDM[];
extern UPNP_SUPPORTED_DM tUPNPSupportedDM_098[];
extern UPNP_SUPPORTED_DM tUPNPSupportedDM_181[];
extern size_t tr98_size;
extern size_t tr181_size;

#define UPNP_SUPPORTED_PARAMETERS_VERSION 1 //Should be incremented each time the Parameters are updated
#define UPNP_SUPPORTED_DATAMODEL_VERSION 1 //Should be incremented each time the tUPNPSupportedDM array is updated

#define DMROOT_URI_098 "urn:broadband-forum-org:tr-098-1-8-0"
#define DMROOT_URL_098 "https://www.broadband-forum.org/cwmp/tr-098-1-8-0.html"
#define DMROOT_DESC_098 "TR-098 InternetGatewayDevice:1 Root Object definition"
#define DMROOT_URI_181 "urn:broadband-forum-org:tr-181-2-11-0"
#define DMROOT_URL_181 "https://www.broadband-forum.org/cwmp/tr-181-2-11-0.html"
#define DMROOT_DESC_181 "TR-181 Device:2 Root Object definition"

#endif
#endif
