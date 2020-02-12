/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#ifndef UPNP_COMMON_H
#define UPNP_COMMON_H

#include <libbbf_api/dmcommon.h>

char *upnp_get_softwareversion();
int upnp_get_NetworkInterfaceNumberOfEntries();
int upnp_get_IPInterfaceNumberOfEntries();
void upnp_getMacAddress(char *interfaceName, char **macAddress);
void upnp_getInterfaceStatus(char *interfaceName, char **status);
int upnp_getInterfaceTotalPacketSent(char *interfaceName, char **totalPktSent);
int upnp_getInterfaceTotalPacketReceived(char *interfaceName, char **totalPktReceived);
char *upnp_get_deviceid_manufactureroui();

#endif
