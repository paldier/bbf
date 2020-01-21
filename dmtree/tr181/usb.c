/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include <dirent.h>
#include <libbbf_api/dmbbf.h>
#include <libbbf_api/dmcommon.h>
#include <libbbf_api/dmuci.h>
#include "dmentry.h"
#include "usb.h"

/* *** Device.USB. *** */
DMOBJ tUSBObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseUSBInterfaceInst, NULL, NULL, NULL, tUSBInterfaceObj, tUSBInterfaceParams, NULL, BBFDM_BOTH},
{"Port", &DMREAD, NULL, NULL, NULL, browseUSBPortInst, NULL, NULL, NULL, NULL, tUSBPortParams, get_linker_usb_port, BBFDM_BOTH},
{"USBHosts", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUSBUSBHostsObj, tUSBUSBHostsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tUSBParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_USB_InterfaceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"PortNumberOfEntries", &DMREAD, DMT_UNINT, get_USB_PortNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.Interface.{i}. *** */
DMOBJ tUSBInterfaceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Stats", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tUSBInterfaceStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tUSBInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_USBInterface_Enable, set_USBInterface_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_USBInterface_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_USBInterface_Alias, set_USBInterface_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_USBInterface_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"LastChange", &DMREAD, DMT_UNINT, get_USBInterface_LastChange, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayers", &DMWRITE, DMT_STRING, get_USBInterface_LowerLayers, set_USBInterface_LowerLayers, NULL, NULL, BBFDM_BOTH},
{"Upstream", &DMREAD, DMT_BOOL, get_USBInterface_Upstream, NULL, NULL, NULL, BBFDM_BOTH},
{"MACAddress", &DMREAD, DMT_STRING, get_USBInterface_MACAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxBitRate", &DMREAD, DMT_UNINT, get_USBInterface_MaxBitRate, NULL, NULL, NULL, BBFDM_BOTH},
{"Port", &DMREAD, DMT_STRING, get_USBInterface_Port, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.Interface.{i}.Stats. *** */
DMLEAF tUSBInterfaceStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"BytesSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_BytesSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BytesReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_BytesReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_PacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"PacketsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_PacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_ErrorsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"ErrorsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_ErrorsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastPacketsSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_UnicastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"UnicastPacketsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_UnicastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_DiscardPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"DiscardPacketsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_DiscardPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_MulticastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"MulticastPacketsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_MulticastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastPacketsSent", &DMREAD, DMT_UNINT, get_USBInterfaceStats_BroadcastPacketsSent, NULL, NULL, NULL, BBFDM_BOTH},
{"BroadcastPacketsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_BroadcastPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{"UnknownProtoPacketsReceived", &DMREAD, DMT_UNINT, get_USBInterfaceStats_UnknownProtoPacketsReceived, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.Port.{i}. *** */
DMLEAF tUSBPortParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_USBPort_Alias, set_USBPort_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_USBPort_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"Standard", &DMREAD, DMT_STRING, get_USBPort_Standard, NULL, NULL, NULL, BBFDM_BOTH},
{"Type", &DMREAD, DMT_STRING, get_USBPort_Type, NULL, NULL, NULL, BBFDM_BOTH},
//{"Receptacle", &DMREAD, DMT_STRING, get_USBPort_Receptacle, NULL, NULL, NULL, BBFDM_BOTH},
{"Rate", &DMREAD, DMT_STRING, get_USBPort_Rate, NULL, NULL, NULL, BBFDM_BOTH},
{"Power", &DMREAD, DMT_STRING, get_USBPort_Power, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts. *** */
DMOBJ tUSBUSBHostsObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Host", &DMREAD, NULL, NULL, NULL, browseUSBUSBHostsHostInst, NULL, NULL, NULL, tUSBUSBHostsHostObj, tUSBUSBHostsHostParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tUSBUSBHostsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"HostNumberOfEntries", &DMREAD, DMT_UNINT, get_USBUSBHosts_HostNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts.Host.{i}. *** */
DMOBJ tUSBUSBHostsHostObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Device", &DMREAD, NULL, NULL, NULL, browseUSBUSBHostsHostDeviceInst, NULL, NULL, NULL, tUSBUSBHostsHostDeviceObj, tUSBUSBHostsHostDeviceParams, get_linker_usb_host_device, BBFDM_BOTH},
{0}
};

DMLEAF tUSBUSBHostsHostParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_USBUSBHostsHost_Alias, set_USBUSBHostsHost_Alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_USBUSBHostsHost_Enable, set_USBUSBHostsHost_Enable, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_USBUSBHostsHost_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"Type", &DMREAD, DMT_STRING, get_USBUSBHostsHost_Type, NULL, NULL, NULL, BBFDM_BOTH},
{"Reset", &DMWRITE, DMT_BOOL, get_USBUSBHostsHost_Reset, set_USBUSBHostsHost_Reset, NULL, NULL, BBFDM_BOTH},
{"PowerManagementEnable", &DMWRITE, DMT_BOOL, get_USBUSBHostsHost_PowerManagementEnable, set_USBUSBHostsHost_PowerManagementEnable, NULL, NULL, BBFDM_BOTH},
{"USBVersion", &DMREAD, DMT_STRING, get_USBUSBHostsHost_USBVersion, NULL, NULL, NULL, BBFDM_BOTH},
{"DeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_USBUSBHostsHost_DeviceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts.Host.{i}.Device.{i}. *** */
DMOBJ tUSBUSBHostsHostDeviceObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Configuration", &DMREAD, NULL, NULL, NULL, browseUSBUSBHostsHostDeviceConfigurationInst, NULL, NULL, NULL, tUSBUSBHostsHostDeviceConfigurationObj, tUSBUSBHostsHostDeviceConfigurationParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tUSBUSBHostsHostDeviceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DeviceNumber", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_DeviceNumber, NULL, NULL, NULL, BBFDM_BOTH},
{"USBVersion", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_USBVersion, NULL, NULL, NULL, BBFDM_BOTH},
{"DeviceClass", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDevice_DeviceClass, NULL, NULL, NULL, BBFDM_BOTH},
{"DeviceSubClass", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDevice_DeviceSubClass, NULL, NULL, NULL, BBFDM_BOTH},
{"DeviceVersion", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_DeviceVersion, NULL, NULL, NULL, BBFDM_BOTH},
{"DeviceProtocol", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDevice_DeviceProtocol, NULL, NULL, NULL, BBFDM_BOTH},
{"ProductID", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_ProductID, NULL, NULL, NULL, BBFDM_BOTH},
{"VendorID", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_VendorID, NULL, NULL, NULL, BBFDM_BOTH},
{"Manufacturer", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_Manufacturer, NULL, NULL, NULL, BBFDM_BOTH},
{"ProductClass", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_ProductClass, NULL, NULL, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_SerialNumber, NULL, NULL, NULL, BBFDM_BOTH},
{"Port", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_Port, NULL, NULL, NULL, BBFDM_BOTH},
{"USBPort", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_USBPort, NULL, NULL, NULL, BBFDM_BOTH},
{"Rate", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_Rate, NULL, NULL, NULL, BBFDM_BOTH},
{"Parent", &DMREAD, DMT_STRING, get_USBUSBHostsHostDevice_Parent, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxChildren", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_MaxChildren, NULL, NULL, NULL, BBFDM_BOTH},
{"IsSuspended", &DMREAD, DMT_BOOL, get_USBUSBHostsHostDevice_IsSuspended, NULL, NULL, NULL, BBFDM_BOTH},
//{"IsSelfPowered", &DMREAD, DMT_BOOL, get_USBUSBHostsHostDevice_IsSelfPowered, NULL, NULL, NULL, BBFDM_BOTH},
{"ConfigurationNumberOfEntries", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDevice_ConfigurationNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}. *** */
DMOBJ tUSBUSBHostsHostDeviceConfigurationObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Interface", &DMREAD, NULL, NULL, NULL, browseUSBUSBHostsHostDeviceConfigurationInterfaceInst, NULL, NULL, NULL, NULL, tUSBUSBHostsHostDeviceConfigurationInterfaceParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tUSBUSBHostsHostDeviceConfigurationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ConfigurationNumber", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDeviceConfiguration_ConfigurationNumber, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDeviceConfiguration_InterfaceNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.USB.USBHosts.Host.{i}.Device.{i}.Configuration.{i}.Interface.{i}. *** */
DMLEAF tUSBUSBHostsHostDeviceConfigurationInterfaceParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"InterfaceNumber", &DMREAD, DMT_UNINT, get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceNumber, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceClass", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceClass, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceSubClass", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceSubClass, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceProtocol", &DMREAD, DMT_HEXBIN, get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceProtocol, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*************************************************************
 * INIT
/*************************************************************/
void init_usb_port(struct uci_section *dm, char *folder_name, char *folder_path, struct usb_port *port){
	port->dm_usb_port= dm;
	port->folder_name= dmstrdup(folder_name);
	port->folder_path= dmstrdup(folder_path);
}

void init_usb_interface(struct uci_section *dm, char *iface_name, char *iface_path, char *statistics_path, char *portlink, struct usb_interface *iface){
	iface->dm_usb_iface= dm;
	iface->iface_name= dmstrdup(iface_name);
	iface->iface_path= dmstrdup(iface_path);
	iface->portlink= dmstrdup(portlink);
	iface->statistics_path= dmstrdup(statistics_path);
}

/*************************************************************
 * ENTRY METHOD
/*************************************************************/
int browseUSBInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DIR *dir;
	struct dirent *ent;
    char *netfolderpath, *iface_name, *iface_path, *statistics_path, *port_link, *v, *instnbr = NULL, *instance = NULL;
    size_t length;
    char **foldersplit;
    struct uci_section *s;
    struct usb_interface iface= {};
    LIST_HEAD(dup_list);
    struct sysfs_dmsection *p;

    synchronize_system_folders_with_dmmap_opt(SYSFS_USB_DEVICES_PATH, "dmmap_usb", "dmmap_interface", "port_link", "usb_iface_instance", &dup_list);
    list_for_each_entry(p, &dup_list, list) {
		dmasprintf(&netfolderpath, "%s/%s/net", SYSFS_USB_DEVICES_PATH, p->sysfs_folder_name);
		if(!isfolderexist(netfolderpath)){
			//dmuci_delete_by_section_unnamed_bbfdm(p->dm, NULL, NULL);
			continue;
		}
		if(p->dm){
			foldersplit= strsplit(p->sysfs_folder_name, ":", &length);
			dmasprintf(&port_link, "%s", foldersplit[0]);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, p->dm, "port_link", port_link);
		}
		sysfs_foreach_file(netfolderpath, dir, ent) {
			if(strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0)
				continue;
			dmasprintf(&iface_name, "%s", ent->d_name);
			break;
		}
		if (dir) closedir(dir);
		dmasprintf(&iface_path, "%s/%s", netfolderpath, iface_name);
		dmasprintf(&statistics_path, "%s/statistics", iface_path);
		init_usb_interface(p->dm, iface_name, iface_path, statistics_path, port_link, &iface);
		instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias, 3, p->dm, "usb_iface_instance", "usb_iface_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &iface, instance) == DM_STOP)
			return 0;
    }
    free_dmmap_config_dup_list(&dup_list);
    return 0;
}

int browseUSBPortInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	int ret1, ret2;
	char *folderpath, *instnbr = NULL, *instance = NULL, *v;
	struct uci_section *s;
	struct usb_port port= {};
	LIST_HEAD(dup_list);
	struct sysfs_dmsection *p;

    ret1= regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]$", 0);
    ret2= regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);
    check_create_dmmap_package("dmmap_usb");
    synchronize_system_folders_with_dmmap_opt(SYSFS_USB_DEVICES_PATH, "dmmap_usb", "dmmap_port", "port_link", "usb_port_instance", &dup_list);
    list_for_each_entry(p, &dup_list, list) {
		if(regexec(&regex1, p->sysfs_folder_name, 0, NULL, 0) != 0 && regexec(&regex2, p->sysfs_folder_name, 0, NULL, 0) !=0 && strstr(p->sysfs_folder_name, "usb") != p->sysfs_folder_name){
			dmuci_delete_by_section_unnamed_bbfdm(p->dm, NULL, NULL);
			continue;
		}
		init_usb_port(p->dm, p->sysfs_folder_name, p->sysfs_folder_path, &port);

		instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, p->dm, "usb_port_instance", "usb_port_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &port, instance) == DM_STOP)
			return 0;
	}
    free_dmmap_config_dup_list(&dup_list);
    return 0;
}

int browseUSBUSBHostsHostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DIR *dir;
	struct dirent *ent;
	LIST_HEAD(dup_list);
	struct sysfs_dmsection *p;
	char *instance = NULL, *instnbr = NULL;
	struct usb_port port= {};

	check_create_dmmap_package("dmmap_usb");
	synchronize_system_folders_with_dmmap_opt(SYSFS_USB_DEVICES_PATH, "dmmap_usb", "dmmap_host", "port_link", "usb_host_instance", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if(strstr(p->sysfs_folder_name, "usb") != p->sysfs_folder_name){
			dmuci_delete_by_section_unnamed_bbfdm(p->dm, NULL, NULL);
			continue;
		}
		init_usb_port(p->dm, p->sysfs_folder_name, p->sysfs_folder_path, &port);
		port.dmsect= p->dm;
		instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, p->dm, "usb_host_instance", "usb_host_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &port, instance) == DM_STOP)
			return 0;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int synchronize_usb_devices_with_dmmap_opt_recursively(char *sysfsrep, char *dmmap_package, char *dmmap_section, char *opt_name, char* inst_opt, int is_root, struct list_head *dup_list)
{
	struct uci_section *s, *stmp, *dmmap_sect;
	FILE *fp;
	DIR *dir;
	struct dirent *ent;
	char *v, *dmmap_file_path, *sysfs_rep_path, *instance= NULL;
	struct sysfs_dmsection *p;
	int ret1, ret2;
	char *deviceClassFile= NULL, *deviceClass= NULL, *hubpath;

	ret1= regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]$", 0);
	ret2= regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);

	LIST_HEAD(dup_list_no_inst);

	dmasprintf(&dmmap_file_path, "/etc/bbfdm/%s", dmmap_package);
	if (access(dmmap_file_path, F_OK)) {
		/*
		 *File does not exist
		 **/
		fp = fopen(dmmap_file_path, "w"); // new empty file
		fclose(fp);
	}
	sysfs_foreach_file(sysfsrep, dir, ent) {
		if(strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0)
			continue;
		if(regexec(&regex1, ent->d_name, 0, NULL, 0) == 0 || regexec(&regex2, ent->d_name, 0, NULL, 0) ==0){
			dmasprintf(&deviceClassFile, "%s/%s/bDeviceClass", sysfsrep, ent->d_name);
			deviceClass= readFileContent(deviceClassFile);
			if(strncmp(deviceClass, "09", 2) == 0){
				dmasprintf(&hubpath, "%s/%s", sysfsrep, ent->d_name);
				synchronize_usb_devices_with_dmmap_opt_recursively(hubpath, dmmap_package, dmmap_section, opt_name, inst_opt, 0, dup_list);
			}
			/*
			 * create/update corresponding dmmap section that have same config_section link and using param_value_array
			 */
			dmasprintf(&sysfs_rep_path, "%s/%s", sysfsrep, ent->d_name);
			if ((dmmap_sect = get_dup_section_in_dmmap_opt(dmmap_package, dmmap_section, opt_name, sysfs_rep_path)) == NULL) {
				dmuci_add_section_bbfdm(dmmap_package, dmmap_section, &dmmap_sect, &v);
				DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, opt_name, sysfs_rep_path);
			}
			dmuci_get_value_by_section_string(dmmap_sect, inst_opt, &instance);
			/*
			 * Add system and dmmap sections to the list
			 */
			if(instance == NULL || strlen(instance) <= 0)
				add_sysfs_sectons_list_paramameter(&dup_list_no_inst, dmmap_sect, ent->d_name, sysfs_rep_path);
			else
				add_sysfs_sectons_list_paramameter(dup_list, dmmap_sect, ent->d_name, sysfs_rep_path);
		}
	}
	if (dir) closedir(dir);
	/*
	 * fusion two lists
	 */
	list_for_each_entry(p, &dup_list_no_inst, list) {
		add_sysfs_sectons_list_paramameter(dup_list, p->dm, p->sysfs_folder_name, p->sysfs_folder_path);
	}
	/*
	 * Delete unused dmmap sections
	 */
	if(is_root){
		uci_path_foreach_sections_safe(bbfdm, dmmap_package, dmmap_section, stmp, s) {
			dmuci_get_value_by_section_string(s, opt_name, &v);
			if(isfolderexist(v) == 0){
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
		}
	}
	return 0;
}

int browseUSBUSBHostsHostDeviceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DIR *dir;
	struct dirent *ent;
	LIST_HEAD(dup_list);
	struct sysfs_dmsection *p;
	char *instance = NULL, *instnbr = NULL;
	struct usb_port port= {};
	struct usb_port *prev_port= (struct usb_port *)prev_data;
	check_create_dmmap_package("dmmap_usb");
	synchronize_usb_devices_with_dmmap_opt_recursively(prev_port->folder_path, "dmmap_usb", "dmmap_host_device", "port_link", "usb_host_device_instance", 1, &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		init_usb_port(p->dm, p->sysfs_folder_name, p->sysfs_folder_path, &port);
		port.dmsect= prev_port->dmsect;
		instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, p->dm, "usb_host_device_instance", "usb_host_device_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &port, instance) == DM_STOP)
			return 0;
	}
	return 0;
}

int browseUSBUSBHostsHostDeviceConfigurationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct usb_port *usb_dev= (struct usb_port*)prev_data;
	struct usb_port port= {};
	struct uci_section *s;
	char *v, *instance, *instnbr = NULL, *nbre;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/bNumConfigurations", usb_dev->folder_path);
	nbre= readFileContent(filepath);
	if(nbre[0] == '0')
		return 0;
	check_create_dmmap_package("dmmap_usb");
	s=is_dmmap_section_exist("dmmap_usb", "usb_device_conf");
	if(!s)
		dmuci_add_section_bbfdm("dmmap_usb", "usb_device_conf", &s, &v);

	init_usb_port(s, usb_dev->folder_name, usb_dev->folder_path, &port);
	instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias, 3, s, "usb_device_conf_instance", "usb_device_conf_alias");

	DM_LINK_INST_OBJ(dmctx, parent_node, &port, "1");
	return 0;
}

int browseUSBUSBHostsHostDeviceConfigurationInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DIR *dir;
	struct dirent *ent;
	struct usb_port *usb_dev = (struct usb_port*)prev_data;
	struct usb_port port = {};
	int ret1, ret2;
	char *sysfs_rep_path, *v, *instance = NULL, *instnbr = NULL;
	struct uci_section *dmmap_sect;

	ret1 = regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]:[0-9][0-9]*\\.[0-9]*[0-9]$", 0);
	ret2 = regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]:[0-9][0-9]*\\.[0-9]*[0-9]$", 0);
	check_create_dmmap_package("dmmap_usb");
	sysfs_foreach_file(usb_dev->folder_path, dir, ent) {
		if(strcmp(ent->d_name, ".")==0 || strcmp(ent->d_name, "..")==0)
			continue;
		if(regexec(&regex1, ent->d_name, 0, NULL, 0) == 0 || regexec(&regex2, ent->d_name, 0, NULL, 0) ==0) {
			dmasprintf(&sysfs_rep_path, "%s/%s", usb_dev->folder_path, ent->d_name);
			if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_usb", "usb_device_conf_interface", "port_link", sysfs_rep_path)) == NULL) {
				dmuci_add_section_bbfdm("dmmap_usb", "usb_device_conf_interface", &dmmap_sect, &v);
				DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "port_link", sysfs_rep_path);
			}

			init_usb_port(dmmap_sect, ent->d_name, sysfs_rep_path, &port);
			instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, dmmap_sect, "usb_device_conf_iface_instance", "usb_device_conf_iface_alias");
			if (DM_LINK_INST_OBJ(dmctx, parent_node, &port, instance) == DM_STOP)
				break;
		}
	}
	if (dir) closedir(dir);
	return 0;
}

/*************************************************************
 * GET & SET PARAM
/*************************************************************/
int get_USB_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	DIR *dir;
	struct dirent *ent;
	char filename[100];
	char *buffer= NULL;
	int size = 100;
	int nbre= 0;

	if ((dir = opendir ("/sys/class/net")) == NULL)
		return 0;
	while ((ent = readdir (dir)) != NULL) {
		buffer= (char*)dmmalloc(100*sizeof(char));
		sprintf(filename, "/sys/class/net/%s", ent->d_name);
		readlink (filename, buffer, size);
		if(strstr(buffer, "/usb") == NULL)
			continue;
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

int get_USB_PortNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	DIR *dir;
	struct dirent *ent;
	int ret1, ret2, nbre = 0;

    ret1 = regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]$", 0);
    ret2 = regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);


	sysfs_foreach_file(SYSFS_USB_DEVICES_PATH, dir, ent) {
		if(regexec(&regex1, ent->d_name, 0, NULL, 0) == 0 || regexec(&regex2, ent->d_name, 0, NULL, 0) ==0 || strstr(ent->d_name, "usb") == ent->d_name)
			nbre++;
	}
	if (dir) closedir(dir);
	dmasprintf(value, "%d", nbre);
	return 0;
}

int get_USBInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL, *carrier;
	dmasprintf(&filepath, "%s/carrier", usbiface->iface_path);
	if(!isfileexist(filepath)){
		*value= "0";
		return 0;
	}
	carrier= readFileContent(filepath);
	*value= carrier[0]=='0'?"0":"1";
	return 0;
}

int set_USBInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_USBInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL, *carrier;
	dmasprintf(&filepath, "%s/carrier", usbiface->iface_path);
	carrier= readFileContent(filepath);
	*value= carrier[0]=='0'?"Down":"Up";
	return 0;
}

int get_USBInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmuci_get_value_by_section_string(usbiface->dm_usb_iface, "usb_iface_alias", value);
	return 0;
}

int set_USBInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, usbiface->dm_usb_iface, "usb_iface_alias", value);
			break;
	}
	return 0;
}

int get_USBInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmasprintf(value, "%s", usbiface->iface_name);
	return 0;
}

int get_USBInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_USBInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *iface= (struct usb_interface *)data;
	adm_entry_get_linker_param(ctx, dm_print_path("%s%Ethernet%Interface%c", dmroot, dm_delim, dm_delim, dm_delim), iface->iface_name, value);
	return 0;
}

int set_USBInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_USBInterface_Upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_USBInterface_MACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/address", usbiface->iface_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterface_MaxBitRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/queues/tx-0/tx_maxrate", usbiface->iface_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterface_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_USBInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/tx_bytes", usbiface->statistics_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/rx_bytes", usbiface->statistics_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/tx_packets", usbiface->statistics_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/rx_packets", usbiface->statistics_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/tx_errors", usbiface->statistics_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/rx_errors", usbiface->statistics_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterfaceStats_UnicastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmasprintf(value, "%d", get_stats_from_ifconfig_command(usbiface->iface_name, "TX", "unicast"));
	return 0;
}

int get_USBInterfaceStats_UnicastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmasprintf(value, "%d", get_stats_from_ifconfig_command(usbiface->iface_name, "RX", "unicast"));
	return 0;
}

int get_USBInterfaceStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/tx_dropped", usbiface->statistics_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterfaceStats_DiscardPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/rx_dropped", usbiface->statistics_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBInterfaceStats_MulticastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmasprintf(value, "%d", get_stats_from_ifconfig_command(usbiface->iface_name, "TX", "multicast"));
	return 0;
}

int get_USBInterfaceStats_MulticastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmasprintf(value, "%d", get_stats_from_ifconfig_command(usbiface->iface_name, "RX", "multicast"));
	return 0;
}

int get_USBInterfaceStats_BroadcastPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmasprintf(value, "%d", get_stats_from_ifconfig_command(usbiface->iface_name, "TX", "broadcast"));
	return 0;
}

int get_USBInterfaceStats_BroadcastPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_interface *usbiface= (struct usb_interface *)data;
	dmasprintf(value, "%d", get_stats_from_ifconfig_command(usbiface->iface_name, "RX", "broadcast"));
	return 0;
}

int get_USBInterfaceStats_UnknownProtoPacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_USBPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* port=(struct usb_port *)data;
	dmuci_get_value_by_section_string(port->dm_usb_port, "usb_port_alias", value);
	return 0;
}

int set_USBPort_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct usb_port* port=(struct usb_port *)data;
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(port->dm_usb_port, "usb_port_alias", value);
			break;
	}
	return 0;
}

int get_USBPort_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* port=(struct usb_port *)data;
	*value= dmstrdup(port->folder_name);
	return 0;
}

int get_USBPort_Standard(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* port= (struct usb_port *) data;
	char *filepath= NULL, *bcddev, *strhex;

	dmasprintf(&filepath, "%s/bcdDevice", port->folder_path);
	bcddev= readFileContent(filepath);
	int bcdusb = (int)strtol(bcddev, NULL, 16);
	dmasprintf(&strhex, "%04X", bcdusb);
	dmasprintf(value, "%c.%c", strhex[1], strhex[2]);
	return 0;
}

int get_USBPort_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL, *deviceclass;
	dmasprintf(&filepath, "%s/bDeviceClass", port->folder_path);
	deviceclass= readFileContent(filepath);
	if(strstr(port->folder_name,"usb") == port->folder_name)
		*value= "Host";
	else if(strcmp(deviceclass, "09") ==0)
		*value= "Hub";
	else
		*value= "Device";
	return 0;
}

int get_USBPort_Receptacle(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return 0;
}

int get_USBPort_Rate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL, *speed;
	dmasprintf(&filepath, "%s/speed", port->folder_path);
	speed= readFileContent(filepath);
	if(strcmp(speed, "1.5") == 0)
		*value= "Low";
	else if(strcmp(speed, "12") == 0)
		*value= "Full";
	else if(strcmp(speed, "480") == 0)
		*value= "High";
	else
		*value= "Super";
	return 0;
}

int get_USBPort_Power(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL, *folderpath= NULL, *powercontrol;

	dmasprintf(&folderpath, "%s/power", port->folder_path);
	if(!isfolderexist(folderpath))
	{
		*value= "";
		return 0;
	}
	dmasprintf(&filepath, "%s/power/control", port->folder_path);
	powercontrol= readFileContent(filepath);
	if(strcmp(powercontrol, "auto") == 0)
		*value="Self";
	else
		*value="Bus";
	return 0;
}

int get_USBUSBHosts_HostNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	DIR *dir;
	struct dirent *ent;
	int nbre= 0;

	sysfs_foreach_file(SYSFS_USB_DEVICES_PATH, dir, ent) {
		if(strstr(ent->d_name, "usb") == ent->d_name)
			nbre++;
	}
	if (dir) closedir(dir);
	dmasprintf(value, "%d", nbre);
	return 0;
}

int get_USBUSBHostsHost_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* port=(struct usb_port *)data;
	dmuci_get_value_by_section_string(port->dm_usb_port, "usb_host_alias", value);
	return 0;
}

int set_USBUSBHostsHost_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct usb_port* port=(struct usb_port *)data;
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section(port->dm_usb_port, "usb_host_alias", value);
			break;
	}
	return 0;
}

int get_USBUSBHostsHost_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *usbhost= (struct usb_port *)data;
	char *filepath= NULL, *up;
	dmasprintf(&filepath, "%s/power/wakeup", usbhost->folder_path);
	up= readFileContent(filepath);
	*value= strcmp(up, "enabled") == 0 ?"1":"0";
	return 0;
}

int set_USBUSBHostsHost_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct usb_port *usbhost= (struct usb_port *)data;
	bool b;
	char *filepath;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmasprintf(&filepath, "%s/power/wakeup", usbhost->folder_path);
			if(b)
				writeFileContent(usbhost->folder_path, "enabled");
			else
				writeFileContent(usbhost->folder_path, "disabled");
			break;
	}
	return 0;
}

int get_USBUSBHostsHost_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* port=(struct usb_port *)data;
	dmasprintf(value, "%s", port->folder_name);
	return 0;
}

int get_USBUSBHostsHost_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *host= (struct usb_port *)data;
	char *filepath= NULL, *serial;
	dmasprintf(&filepath, "%s/serial", host->folder_path);
	serial= readFileContent(filepath);
	if(strcasestr(serial, "ohci")!=NULL)
		*value= "OHCI";
	else if(strcasestr(serial, "ehci")!=NULL)
		*value= "EHCI";
	else if(strcasestr(serial, "uhci")!=NULL)
		*value= "UHCI";
	else
		*value= "xHCI";
	return 0;
}

int get_USBUSBHostsHost_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= "false";
	return 0;
}

int set_USBUSBHostsHost_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_USBUSBHostsHost_PowerManagementEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *host= (struct usb_port *)data;
	char *filepath= NULL, *power;
	dmasprintf(&filepath, "%s/power/level", host->folder_path);
	if(!isfileexist(filepath)){
		*value= "false";
		return 0;
	}
	power= readFileContent(filepath);
	if(strcmp(power, "suspend") == 0)
		*value= "false";
	else
		*value= "true";

	return 0;
}

int set_USBUSBHostsHost_PowerManagementEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct usb_port *host= (struct usb_port *)data;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			char *filepath;
			dmasprintf(&filepath, "%s/power/level", host->folder_path);
			if (!isfileexist(filepath))
				break;
			writeFileContent(filepath, b?"on":"suspend");
			break;
	}
	return 0;
}

int get_USBUSBHostsHost_USBVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *usbhost= (struct usb_port *)data;
	char *strhex, *filepath= NULL;

	dmasprintf(&filepath, "%s/bcdDevice", usbhost->folder_path);
	strhex= readFileContent(filepath);

	dmasprintf(value, "%c.%c", strhex[1], strhex[2]);
	return 0;
}

int get_number_devices(char *folderpath, int *nbre)
{
	DIR *dir;
	struct dirent *ent;
	int ret1, ret2;
	char *deviceClassFile= NULL, *deviceClass= NULL, *hubpath;

	ret1= regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]$", 0);
	ret2= regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);

	sysfs_foreach_file(folderpath, dir, ent) {
		if(regexec(&regex1, ent->d_name, 0, NULL, 0) == 0 || regexec(&regex2, ent->d_name, 0, NULL, 0) ==0){
			dmasprintf(&deviceClassFile, "%s/%s/bDeviceClass", folderpath, ent->d_name);
			deviceClass= readFileContent(deviceClassFile);
			if(strncmp(deviceClass, "09", 2) == 0){
				dmasprintf(&hubpath, "%s/%s", folderpath, ent->d_name);
				get_number_devices(hubpath, nbre);
			}
			(*nbre)++;
		}
	}
	if (dir) closedir(dir);
	return 0;
}

int get_USBUSBHostsHost_DeviceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usb_host= (struct usb_port *) data;
	int dev_nbre= 0;

	get_number_devices(usb_host->folder_path, &dev_nbre);
	dmasprintf(value, "%d", dev_nbre);
	return 0;
}

int get_USBUSBHostsHostDevice_DeviceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *usbdev= (struct usb_port *)data;
	size_t length;
	char **filename= strsplit(usbdev->folder_name, "-", &length);
	char **port= strsplit(filename[1], ".", &length);
	dmasprintf(value ,"%s", port[0]);
	return 0;
}

int get_USBUSBHostsHostDevice_USBVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *strhex, *filepath;

	dmasprintf(&filepath,"%s/bcdDevice", usbdev->folder_path);
	strhex= readFileContent(filepath);
	dmasprintf(value, "%c.%c", strhex[1], strhex[2]);
	return 0;
}

int get_USBUSBHostsHostDevice_DeviceClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *bDevCls, *filepath;

	dmasprintf(&filepath,"%s/bDeviceClass", usbdev->folder_path);
	bDevCls= readFileContent(filepath);

	dmasprintf(value, "%c%c", bDevCls[0], bDevCls[1]);
	return 0;
}

int get_USBUSBHostsHostDevice_DeviceSubClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *bDevCls, *filepath;

	dmasprintf(&filepath,"%s/bDeviceSubClass", usbdev->folder_path);
	bDevCls= readFileContent(filepath);

	dmasprintf(value, "%c%c", bDevCls[0], bDevCls[1]);

	return 0;
}

int get_USBUSBHostsHostDevice_DeviceVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_USBUSBHostsHostDevice_DeviceProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *bDevProto, *filepath;

	dmasprintf(&filepath,"%s/bDeviceProtocol", usbdev->folder_path);
	bDevProto= readFileContent(filepath);

	dmasprintf(value, "%c%c", bDevProto[0], bDevProto[1]);

	return 0;
}

int get_USBUSBHostsHostDevice_ProductID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *idProd, *filepath;

	dmasprintf(&filepath,"%s/idProduct", usbdev->folder_path);
	idProd= readFileContent(filepath);

	dmasprintf(value, "%c%c%c%c", idProd[0], idProd[1], idProd[2], idProd[3]);
	return 0;
}

int get_USBUSBHostsHostDevice_VendorID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *idVendor, *filepath;

	dmasprintf(&filepath,"%s/idVendor", usbdev->folder_path);
	idVendor= readFileContent(filepath);

	dmasprintf(value, "%c%c%c%c", idVendor[0], idVendor[1], idVendor[2], idVendor[3]);
	return 0;
}

int get_USBUSBHostsHostDevice_Manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *filepath;

	dmasprintf(&filepath,"%s/manufacturer", usbdev->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDevice_ProductClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *filepath;

	dmasprintf(&filepath,"%s/product", usbdev->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDevice_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port* usbdev= (struct usb_port *) data;
	char *filepath;

	dmasprintf(&filepath,"%s/urbnum", usbdev->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDevice_Port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	int ret1, ret2, length;
	char **busname, **portname;

	ret1 = regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]$", 0);
	ret2 = regcomp(&regex2, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);
	if(regexec(&regex1, port->folder_name, 0, NULL, 0) == 0 || regexec(&regex2, port->folder_name, 0, NULL, 0) ==0){
		busname = strsplit(port->folder_name, "-", &length);
		portname = strsplit(busname[1], ".", &length);
		*value = dmstrdup(portname[0]);
		return 0;
	}
	*value = "0";
	return 0;
}

int get_USBUSBHostsHostDevice_USBPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cUSB%cPort%c", dmroot, dm_delim, dm_delim, dm_delim), port->folder_name, value);
	return 0;
}

int get_USBUSBHostsHostDevice_Rate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL, *speed;
	dmasprintf(&filepath, "%s/speed", port->folder_path);
	speed= readFileContent(filepath);
	if(strcmp(speed, "1.5") == 0)
		*value= "Low";
	else if(strcmp(speed, "12") == 0)
		*value= "Full";
	else if(strcmp(speed, "480") == 0)
		*value= "High";
	else
		*value= "Super";
	return 0;
}

int get_USBUSBHostsHostDevice_Parent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port*)data;
	int ret1;
	char *v;
	ret1= regcomp(&regex1, "^[0-9][0-9]*-[0-9]*[0-9]\\.[0-9]*[0-9]$", 0);

	if(regexec(&regex1, port->folder_name, 0, NULL, 0) != 0 || port->dmsect == NULL){
		*value= "";
		return 0;
	}
	dmuci_get_value_by_section_string(port->dmsect, "usb_host_instance", &v);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cUSB%cUSBHosts%cHost%c%s%vDevice%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim, v, dm_delim, dm_delim), port->folder_name, value);
	return 0;
}

int get_USBUSBHostsHostDevice_MaxChildren(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL, *maxchild;
	dmasprintf(&filepath, "%s/maxchild", port->folder_path);
	maxchild= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDevice_IsSuspended(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL, *status;
	dmasprintf(&filepath, "%s/power/runtime_status", port->folder_path);
	status= readFileContent(filepath);
	if(strncmp(status, "suspended", 9) == 0)
		*value= "1";
	else
		*value= "0";
	return 0;
}

int get_USBUSBHostsHostDevice_IsSelfPowered(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_USBUSBHostsHostDevice_ConfigurationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/bNumConfigurations", port->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDeviceConfiguration_ConfigurationNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= "";
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/bConfigurationValue", port->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDeviceConfiguration_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/bNumInterfaces", port->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/bInterfaceNumber", port->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/bInterfaceClass", port->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceSubClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/bInterfaceSubClass", port->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_USBUSBHostsHostDeviceConfigurationInterface_InterfaceProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct usb_port *port= (struct usb_port *)data;
	char *filepath= NULL;
	dmasprintf(&filepath, "%s/bInterfaceProtocol", port->folder_path);
	*value= readFileContent(filepath);
	return 0;
}

int get_linker_usb_port(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker) {
	struct usb_port *port= (struct usb_port *)data;
	if(port && port->folder_name) {
		*linker= dmstrdup(port->folder_name);
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}

int get_linker_usb_host_device(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker){
	struct usb_port *port= (struct usb_port *)data;
	if(port && port->folder_name) {
		*linker= dmstrdup(port->folder_name);
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}
