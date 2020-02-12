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

struct upnpdiscovery {
	char *st;
	char *usn;
	char *uuid;
	char *urn;
	char *descurl;
	struct uci_section *dmmap_sect;
};

struct upnp_device_inst {
	char *device_type;
	char *friendly_name;
	char *manufacturer;
	char *manufacturer_url;
	char *model_description;
	char *model_name;
	char *model_number;
	char *model_url;
	char *serial_number;
	char *udn;
	char *uuid;
	char *preentation_url;
	char *parentudn;
	char *upc;
	struct uci_section *dmmap_sect;
};

struct upnp_service_inst {
	char *parentudn;
	char *serviceid;
	char *servicetype;
	char *scpdurl;
	char *controlurl;
	char *eventsuburl;
	struct uci_section *dmmap_sect;
};

struct upnp_description_file_info {
	char *desc_url;
	struct uci_section *dmmap_sect;
};

int browseUPnPDiscoveryRootDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseUPnPDiscoveryDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseUPnPDiscoveryServiceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseUPnPDescriptionDeviceDescriptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseUPnPDescriptionDeviceInstanceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseUPnPDescriptionServiceInstanceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int get_UPnPDevice_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPMediaServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPMediaServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPMediaRenderer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPMediaRenderer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPWLANAccessPoint(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPWLANAccessPoint(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPQoSDevice (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPQoSDevice (char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPQoSPolicyHolder(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPQoSPolicyHolder(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPIGD(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPIGD(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPDMBasicMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPDMBasicMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPDMConfigurationMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPDMConfigurationMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDevice_UPnPDMSoftwareMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_UPnPDevice_UPnPDMSoftwareMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_UPnPDeviceCapabilities_UPnPArchitecture(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPArchitectureMinorVer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPMediaServer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPMediaRenderer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPWLANAccessPoint(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPBasicDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPQoSDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPQoSPolicyHolder(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPIGD(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPDMBasicMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPDMConfigurationMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDeviceCapabilities_UPnPDMSoftwareMgmt(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscovery_RootDeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscovery_DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscovery_ServiceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryRootDevice_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryRootDevice_UUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryRootDevice_USN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryRootDevice_LeaseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryRootDevice_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryRootDevice_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryRootDevice_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryRootDevice_LastUpdate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryDevice_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryDevice_UUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryDevice_USN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryDevice_LeaseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryDevice_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryDevice_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryDevice_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryDevice_LastUpdate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryService_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryService_USN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryService_LeaseTime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryService_Location(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryService_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryService_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryService_LastUpdate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDiscoveryService_ParentDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescription_DeviceDescriptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescription_DeviceInstanceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescription_ServiceInstanceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceDescription_URLBase(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceDescription_SpecVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceDescription_Host(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_UDN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_ParentDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_DiscoveryDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_DeviceType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_FriendlyName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_DeviceCategory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_Manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_ManufacturerOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_ManufacturerURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_ModelDescription(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_ModelName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_ModelNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_ModelURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_UPC(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionDeviceInstance_PresentationURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionServiceInstance_ParentDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionServiceInstance_ServiceId(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionServiceInstance_ServiceDiscovery(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionServiceInstance_ServiceType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionServiceInstance_SCPDURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionServiceInstance_ControlURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_UPnPDescriptionServiceInstance_EventSubURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_upnp_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int get_root_device_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);
int get_device_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);
int get_device_instance_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);
int get_service_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);
#endif //__UPNP_H

