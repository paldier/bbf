/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 *		Author: Feten Besbes <feten.besbes@pivasoftware.com>
 */

#include "deviceinfo.h"
#include "os.h"

struct Supported_Data_Models
{
	char url[128];
	char urn[128];
	char features[128];
};

struct Supported_Data_Models Data_Models[] = {
{"http://www.broadband-forum.org/cwmp/tr-181-2-13-0.xml","urn:broadband-forum-org:tr-181-2-13-0","IP,Wireless,Firewall,NAT,DHCP,QoS,DNS,GRE,UPnP"},
{"http://www.broadband-forum.org/cwmp/tr-104-1-1-0.xml","urn:broadband-forum-org:tr-104-1-1-0", "VoiceService"},
{"http://www.broadband-forum.org/cwmp/tr-143-1-1-0.xml","urn:broadband-forum-org:tr-143-1-1-0", "Ping,TraceRoute,Download,Upload,UDPecho,ServerSelectionDiag"},
{"http://www.broadband-forum.org/cwmp/tr-157-1-3-0.xml","urn:broadband-forum-org:tr-157-1-3-0", "Bulkdata,SoftwareModules"},
};

/*
 *DeviceInfo. functions
 */
char *get_deviceid_manufacturer()
{
	return os__get_deviceid_manufacturer();
}

char *get_deviceid_manufactureroui()
{
	return os__get_deviceid_manufactureroui();
}

char *get_deviceid_productclass()
{
	return os__get_deviceid_productclass();
}

char *get_deviceid_serialnumber()
{
	return os__get_deviceid_serialnumber();
}

char *get_softwareversion()
{
	return os__get_softwareversion();
}

int lookup_vcf_name(char *instance, char **value)
{
	struct uci_section *s = NULL;
	uci_path_foreach_option_eq(bbfdm, DMMAP, "vcf", "vcf_instance", instance, s) {
		dmuci_get_value_by_section_string(s, "name", value);
	}
	return 0;
}

static int get_device_manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_deviceid_manufacturer();
	return 0;
}

static int get_device_manufactureroui(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_deviceid_manufactureroui();
	return 0;
}

static int get_device_productclass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_deviceid_productclass();
	return 0;
}

static int get_device_serialnumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_deviceid_serialnumber();
	return 0;
}

static int get_device_softwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_softwareversion();
	return 0;
}

/*#Device.DeviceInfo.UpTime!PROCFS:/proc/uptime*/
static int get_device_info_uptime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	FILE *fp = NULL;
	char *pch, *spch, buf[64];
	*value = "0";

	fp = fopen(UPTIME, "r");
	if (fp != NULL) {
		if (fgets(buf, 64, fp) != NULL) {
			pch = strtok_r(buf, ".", &spch);
			*value = (pch) ? dmstrdup(pch) : "0";
		}
		fclose(fp);
	}
	return 0;
}

/*#Device.DeviceInfo.ProvisioningCode!UCI:cwmp/cpe,cpe/provisioning_code*/
static int get_device_provisioningcode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "provisioning_code", value);
	return 0;
}

static int set_device_provisioningcode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "provisioning_code", value);
			return 0;
	}
	return 0;
}

static int get_number_of_cpus(void)
{
	char val[16];

	dm_read_sysfs_file("/sys/devices/system/cpu/present", val, sizeof(val));
	char *max = strchr(val, '-');
	return max ? atoi(max+1)+1 : 0;
}

static int get_DeviceInfo_ProcessorNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%d", get_number_of_cpus());
	return 0;
}

static int get_DeviceInfo_SupportedDataModelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%d", sizeof(Data_Models)/sizeof(struct Supported_Data_Models));
	return 0;
}

static int get_vcf_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

static int get_vcf_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "version", value);
	return 0;
}

static int get_vcf_date(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	DIR *dir;
	struct dirent *d_file;
	struct stat attr;
	char path[280];
	char date[sizeof "AAAA-MM-JJTHH:MM:SSZ"];

	*value = "";
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	if ((dir = opendir (DEFAULT_CONFIG_DIR)) != NULL) {
		while ((d_file = readdir (dir)) != NULL) {
			if(strcmp(*value, d_file->d_name) == 0) {
				snprintf(path, sizeof(path), DEFAULT_CONFIG_DIR"%s", d_file->d_name);
				stat(path, &attr);
				strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%SZ", localtime(&attr.st_mtime));
				*value = dmstrdup(date);
			}
		}
		closedir (dir);
	}
	return 0;
}

static int get_vcf_backup_restore(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "backup_restore", value);
	return 0;
}

static int get_vcf_desc(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "description", value);
	return 0;
}

static int get_vcf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "vcf_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_vcf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "vcf_alias", value);
			return 0;
	}
	return 0;
}

static int check_file_dir(char *name)
{
	DIR *dir;
	struct dirent *d_file;
	if ((dir = opendir (DEFAULT_CONFIG_DIR)) != NULL) {
		while ((d_file = readdir (dir)) != NULL) {
			if (strcmp(name, d_file->d_name) == 0) {
				closedir(dir);
				return 1;
			}
		}
		closedir(dir);
	}
	return 0;
}

static int get_vlf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "vlf_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_vlf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "vlf_alias", value);
			return 0;
	}
	return 0;
}

static int get_vlf_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "log_file", value);
	return 0;
}

static int get_vlf_max_size (char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "log_size", value);
	*value = (**value) ? *value : "0";
	return 0;
}

static int get_vlf_persistent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int browseVcfInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *vcf = NULL, *vcf_last = NULL, *name;
	struct uci_section *s = NULL, *del_sec = NULL;
	DIR *dir;
	struct dirent *d_file;

	if ((dir = opendir (DEFAULT_CONFIG_DIR)) != NULL) {
		while ((d_file = readdir (dir)) != NULL) {
			if(d_file->d_name[0] == '.')
				continue;
			update_section_list(DMMAP,"vcf", "name", 1, d_file->d_name, NULL, NULL, "backup_restore", "1");
		}
		closedir (dir);
	}
	uci_path_foreach_sections(bbfdm, DMMAP, "vcf", s) {
		dmuci_get_value_by_section_string(s, "name", &name);
		if(del_sec) {
			DMUCI_DELETE_BY_SECTION(bbfdm, del_sec, NULL, NULL);
			del_sec = NULL;
		}
		if (check_file_dir(name) == 0) {
			del_sec = s;
			continue;
		}
		vcf = handle_update_instance(1, dmctx, &vcf_last, update_instance_alias_bbfdm, 3, s, "vcf_instance", "vcf_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, vcf) == DM_STOP)
			break;
	}
	if(del_sec)
		DMUCI_DELETE_BY_SECTION(bbfdm, del_sec, NULL, NULL);
	return 0;
}

static int browseVlfInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *sys_log_sec, *dm_sec;
	char *log_file,*log_size;
	int i = 1;

	uci_foreach_sections("system", "system", sys_log_sec) {
		if (!sys_log_sec)
			break;
		dmuci_get_value_by_section_string(sys_log_sec, "log_file", &log_file);
		dmuci_get_value_by_section_string(sys_log_sec, "log_size", &log_size);
		uci_path_foreach_sections(bbfdm, "dmmap", "vlf", dm_sec) {
			if (dm_sec)
				break;
		}
		if (!dm_sec) {
			update_section_list(DMMAP,"vlf", NULL, i++, NULL, "log_file", log_file, "log_size", log_size);
		} else {
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dm_sec, "log_file", log_file);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dm_sec, "log_size", log_size);
		}
	}
	uci_path_foreach_sections(bbfdm, "dmmap", "vlf", dm_sec) {
		char *instance, *last_instance = NULL;

		instance = handle_update_instance(1, dmctx, &last_instance, update_instance_alias_bbfdm, 3, dm_sec, "vlf_instance", "vlf_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)dm_sec, instance) == DM_STOP){
			break;
		}
	}
	return 0;
}

static int browseDeviceInfoProcessorInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *idx = NULL, *idx_last = NULL;
	int i;

	for (i = 0; i < get_number_of_cpus(); i++) {
		idx = handle_update_instance(1, dmctx, &idx_last, update_instance_without_section, 1, i+1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, NULL, idx) == DM_STOP)
			break;
	}
	return 0;
}

static int get_DeviceInfoProcessor_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "processor", "processor_inst", instance, s) {
		dmuci_get_value_by_section_string(s, "alias", value);
		break;
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DeviceInfoProcessor_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;
	char *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap", "processor", "processor_inst", instance, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap", "processor", &dmmap, &v);
			dmuci_set_value_by_section(dmmap, "processor_inst", instance);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

static int get_DeviceInfoProcessor_Architecture(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct utsname utsname;

	if (uname(&utsname) < 0)
		return 0;

	if (strstr(utsname.machine, "arm")) {
		*value = "arm";
	} else if(strstr(utsname.machine, "mips")) {
		const bool is_big_endian = IS_BIG_ENDIAN;
		*value = (is_big_endian) ? "mipseb" : "mipsel";
	} else
		*value = dmstrdup(utsname.machine);
	return 0;
}

static int browseDeviceInfoSupportedDataModelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *idx = NULL, *idx_last = NULL;
	int i;

	for (i = 0; i < sizeof(Data_Models)/sizeof(struct Supported_Data_Models); i++) {
		idx = handle_update_instance(1, dmctx, &idx_last, update_instance_without_section, 1, i+1);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&Data_Models[i], idx) == DM_STOP)
			break;
	}
	return 0;
}

static int get_DeviceInfoSupportedDataModel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	uci_path_foreach_option_eq(bbfdm, "dmmap", "data_model", "data_model_inst", instance, s) {
		dmuci_get_value_by_section_string(s, "alias", value);
		break;
	}
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DeviceInfoSupportedDataModel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;
	char *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap", "data_model", "data_model_inst", instance, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				return 0;
			}
			dmuci_add_section_bbfdm("dmmap", "data_model", &dmmap, &v);
			dmuci_set_value_by_section(dmmap, "data_model_inst", instance);
			dmuci_set_value_by_section(dmmap, "alias", value);
			break;
	}
	return 0;
}

static int get_DeviceInfoSupportedDataModel_URL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct Supported_Data_Models *)data)->url);
	return 0;
}

static int get_DeviceInfoSupportedDataModel_URN(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct Supported_Data_Models *)data)->urn);
	return 0;
}

static int get_DeviceInfoSupportedDataModel_Features(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct Supported_Data_Models *)data)->features);
	return 0;
}

/* *** Device.DeviceInfo. *** */
DMOBJ tDeviceInfoObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"VendorConfigFile", &DMREAD, NULL, NULL, NULL, browseVcfInst, NULL, NULL, NULL, NULL, tDeviceInfoVendorConfigFileParams, NULL, BBFDM_BOTH},
{"MemoryStatus", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoMemoryStatusParams, NULL, BBFDM_BOTH},
{"ProcessStatus", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoProcessStatusObj, tDeviceInfoProcessStatusParams, NULL, BBFDM_BOTH},
{"Processor", &DMREAD, NULL, NULL, NULL, browseDeviceInfoProcessorInst, NULL, NULL, NULL, NULL, tDeviceInfoProcessorParams, NULL, BBFDM_BOTH},
{"VendorLogFile", &DMREAD, NULL, NULL, NULL, browseVlfInst, NULL, NULL, NULL, NULL, tDeviceInfoVendorLogFileParams, NULL, BBFDM_BOTH},
{"SupportedDataModel", &DMREAD, NULL, NULL, NULL, browseDeviceInfoSupportedDataModelInst, NULL, NULL, NULL, NULL, tDeviceInfoSupportedDataModelParams, NULL, BBFDM_CWMP},
{0}
};

DMLEAF tDeviceInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Manufacturer", &DMREAD, DMT_STRING, get_device_manufacturer, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"ManufacturerOUI", &DMREAD, DMT_STRING, get_device_manufactureroui, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"ModelName", &DMREAD, DMT_STRING, os__get_device_modelname, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"Description", &DMREAD, DMT_STRING, os__get_device_description, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"ProductClass", &DMREAD, DMT_STRING, get_device_productclass, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_device_serialnumber, NULL,  &DMFINFRM, NULL, BBFDM_BOTH},
{"HardwareVersion", &DMREAD, DMT_STRING, os__get_device_hardwareversion, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"SoftwareVersion", &DMREAD, DMT_STRING, get_device_softwareversion, NULL, &DMFINFRM, &DMACTIVE, BBFDM_BOTH},
{"ProvisioningCode", &DMWRITE, DMT_STRING, get_device_provisioningcode, set_device_provisioningcode, &DMFINFRM, &DMACTIVE, BBFDM_BOTH},
{"UpTime", &DMREAD, DMT_UNINT, get_device_info_uptime, NULL, NULL, NULL, BBFDM_BOTH},
{"ProcessorNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_ProcessorNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"SupportedDataModelNumberOfEntries", &DMREAD, DMT_UNINT, get_DeviceInfo_SupportedDataModelNumberOfEntries, NULL, NULL, NULL, BBFDM_CWMP},
{CUSTOM_PREFIX"BaseMACAddress", &DMREAD, DMT_STRING, os__get_base_mac_addr, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.VendorConfigFile.{i}. *** */
DMLEAF tDeviceInfoVendorConfigFileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_vcf_alias, set_vcf_alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_vcf_name, NULL, NULL, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_vcf_version, NULL, NULL, NULL, BBFDM_BOTH},
{"Date", &DMREAD, DMT_TIME, get_vcf_date, NULL, NULL, NULL, BBFDM_BOTH},
{"Description", &DMREAD, DMT_STRING, get_vcf_desc, NULL, NULL, NULL, BBFDM_BOTH},
{"UseForBackupRestore", &DMREAD, DMT_BOOL, get_vcf_backup_restore, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.MemoryStatus. *** */
DMLEAF tDeviceInfoMemoryStatusParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Total", &DMREAD, DMT_UNINT, os__get_memory_status_total, NULL, NULL, NULL, BBFDM_BOTH},
{"Free", &DMREAD, DMT_UNINT, os__get_memory_status_free, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.ProcessStatus. *** */
DMOBJ tDeviceInfoProcessStatusObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Process", &DMREAD, NULL, NULL, NULL, os__browseProcessEntriesInst, NULL, NULL, NULL, NULL, tDeviceInfoProcessStatusProcessParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDeviceInfoProcessStatusParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"CPUUsage", &DMREAD, DMT_UNINT, os__get_process_cpu_usage, NULL, NULL, NULL, BBFDM_BOTH},
{"ProcessNumberOfEntries", &DMREAD, DMT_UNINT, os__get_process_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.ProcessStatus.Process.{i}. *** */
DMLEAF tDeviceInfoProcessStatusProcessParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"PID", &DMREAD, DMT_UNINT, os__get_process_pid, NULL, NULL, NULL, BBFDM_BOTH},
{"Command", &DMREAD, DMT_STRING, os__get_process_command, NULL, NULL, NULL, BBFDM_BOTH},
{"Size", &DMREAD, DMT_UNINT, os__get_process_size, NULL, NULL, NULL, BBFDM_BOTH},
{"Priority", &DMREAD, DMT_UNINT, os__get_process_priority, NULL, NULL, NULL, BBFDM_BOTH},
{"CPUTime", &DMREAD, DMT_UNINT, os__get_process_cpu_time, NULL, NULL, NULL, BBFDM_BOTH},
{"State", &DMREAD, DMT_STRING, os__get_process_state, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.VendorLogFile.{i}. *** */
DMLEAF tDeviceInfoVendorLogFileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_vlf_alias, set_vlf_alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_vlf_name, NULL, NULL, NULL, BBFDM_BOTH},
{"MaximumSize", &DMREAD, DMT_UNINT, get_vlf_max_size, NULL, NULL, NULL, BBFDM_BOTH},
{"Persistent", &DMREAD, DMT_BOOL, get_vlf_persistent, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.Processor.{i}. *** */
DMLEAF tDeviceInfoProcessorParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoProcessor_Alias, set_DeviceInfoProcessor_Alias, NULL, NULL, BBFDM_BOTH},
{"Architecture", &DMREAD, DMT_STRING, get_DeviceInfoProcessor_Architecture, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.SupportedDataModel.{i}. *** */
DMLEAF tDeviceInfoSupportedDataModelParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_DeviceInfoSupportedDataModel_Alias, set_DeviceInfoSupportedDataModel_Alias, NULL, NULL, BBFDM_CWMP},
{"URL", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_URL, NULL, NULL, NULL, BBFDM_CWMP},
{"URN", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_URN, NULL, NULL, NULL, BBFDM_CWMP},
{"Features", &DMREAD, DMT_STRING, get_DeviceInfoSupportedDataModel_Features, NULL, NULL, NULL, BBFDM_CWMP},
{0}
};
