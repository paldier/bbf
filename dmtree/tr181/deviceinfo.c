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

/*
 *DeviceInfo. functions
 */
static char *get_deviceid_manufacturer()
{
	char *v;
	dmuci_get_option_value_string("cwmp","cpe","manufacturer", &v);
	return v;
}

static char *get_deviceid_manufactureroui()
{
	char *v, *mac = NULL, str[16], macreadfile[18] = {0};
	json_object *res;
	FILE *nvrammac = NULL;
	
	dmuci_get_option_value_string("cwmp", "cpe", "override_oui", &v);
	if (v[0] == '\0') {
		dmubus_call("router.system", "info", UBUS_ARGS{{}}, 0, &res);
		if (!(res)) {
			db_get_value_string("hw", "board", "basemac", &mac);
			if (!mac || strlen(mac) == 0) {
				if ((nvrammac = fopen("/proc/nvram/BaseMacAddr", "r")) == NULL) {
					mac = NULL;
				} else {
					fscanf(nvrammac,"%17[^\n]", macreadfile);
					macreadfile[17] = '\0';
					sscanf(macreadfile,"%2c %2c %2c", str, str+2, str+4);
					str[6] = '\0';
					v = dmstrdup(str); // MEM WILL BE FREED IN DMMEMCLEAN
					fclose(nvrammac);
					return v;
				}
			}
		} else
			mac = dmjson_get_value(res, 2, "system", "basemac");

		if(mac) {
			size_t ln = strlen(mac);
			if (ln < 17) goto not_found;
			sscanf (mac,"%2c:%2c:%2c",str,str+2,str+4);
			str[6] = '\0';
			v = dmstrdup(str); // MEM WILL BE FREED IN DMMEMCLEAN
			return v;
		} else
			goto not_found;
	}
	return v;
not_found:
	v = "";
	return v;
}

static char *get_deviceid_productclass()
{
	char *v;
	dmuci_get_option_value_string("cwmp", "cpe", "override_productclass", &v);
	if (v[0] == '\0') {
		db_get_value_string("hw", "board", "iopVerBoard", &v);
		return v;
	}
	return v;
}

static char *get_deviceid_serialnumber()
{
	char *v;
	db_get_value_string("hw", "board", "serial_number", &v);
	return v;
}

static char *get_softwareversion()
{
	char *v;
	db_get_value_string("hw", "board", "iopVersion", &v);
	return v;
}

/*#Device.DeviceInfo.Manufacturer!UCI:cwmp/cwmp,cpe/manufacturer*/
static int get_device_manufacturer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_deviceid_manufacturer();
	return 0;
}

/*#Device.DeviceInfo.ManufacturerOUI!UCI:cwmp/cwmp,cpe/override_oui*/
static int get_device_manufactureroui(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_deviceid_manufactureroui();
	return 0;
}

/*#Device.DeviceInfo.ProductClass!UCI:cwmp/cwmp,cpe/override_productclass*/
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

static int get_device_hardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("hw", "board", "hardwareVersion", value);
	return 0;
}

static int get_device_routermodel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("hw", "board", "routerModel", value);
	return 0;
}

static int get_device_info_uptime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	FILE *fp = NULL;
	char *pch, *spch, buf[64];
	*value = "0";

	fp = fopen(UPTIME, "r");
	if (fp != NULL) {		
		fgets(buf, 64, fp);
		pch = strtok_r(buf, ".", &spch);
		if (pch)
			*value = dmstrdup(pch); // MEM WILL BE FREED IN DMMEMCLEAN
		fclose(fp);
	}
	return 0;
}

static int get_device_devicelog(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	int i = 0, nbrlines = 4;
	char buff[512], *msg = NULL;
	int len = klogctl(3 , buff, sizeof(buff) - 1); /* read ring buffer */
	if (len <= 0)
		return 0;
	buff[len] = '\0';
	char *p = buff;
	while (*p) {
		if (*p == '<') {
			*p = '(';
			if (p == buff || *(p-1) == '\n') {
				if(msg == NULL) msg = p;
				i++;
				if (i == nbrlines) {
					*(p-1) = '\0';
					break;
				}
			}
		}
		else if (*p == '>')
			*p = ')';
		p++;
	}
	if (msg == NULL)
		*value = "";
	else
		*value = dmstrdup(msg);// MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int get_device_specversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1.0";
	return 0;
}

/*#Device.DeviceInfo.ProvisioningCode!UCI:cwmp/cwmp,cpe/provisioning_code*/
static int get_device_provisioningcode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "provisioning_code", value);
	return 0;
}

static int set_device_provisioningcode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("cwmp", "cpe", "provisioning_code", value);
			return 0;
	}
	return 0;
}

static int get_base_mac_addr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{	
	json_object *res;
	dmubus_call("router.system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 2, "system", "basemac");
	return 0;
}

static int get_device_memory_bank(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "memory_bank", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "code");
	return 0;
}

static int set_device_memory_bank(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			//TODO
			return 0;
		case VALUESET:
			dmubus_call_set("router.system", "memory_bank", UBUS_ARGS{{"bank", value, Integer}}, 1);
			return 0;
	}
	return 0;
}

static int get_catv_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *catv;
	dmuci_get_option_value_string("catv", "catv", "enable", &catv);
	if (strcmp(catv, "on") == 0)
		*value = "1";
	else 
		*value = "0";
	return 0;	
}

static int set_device_catvenabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("catv", "catv", "enable", b ? "on" : "off");
			return 0;
	}
	return 0;
}

static int get_catv_optical_input_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("catv", "vpd", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "VPD");
	return 0;
}

static int get_catv_rf_output_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("catv", "rf", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "RF");
	return 0;
}

static int get_catv_temperature(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("catv", "temp", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "Temperature");
	return 0;
}

static int get_catv_voltage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("catv", "vcc", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "VCC");
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
	char date[sizeof "AAAA-MM-JJTHH:MM:SS.000Z"];

	*value = "";
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	if ((dir = opendir (DEFAULT_CONFIG_DIR)) != NULL) {
		while ((d_file = readdir (dir)) != NULL) {
			if(strcmp(*value, d_file->d_name) == 0) {
				snprintf(path, sizeof(path), DEFAULT_CONFIG_DIR"%s", d_file->d_name);
				stat(path, &attr);
				strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S.000Z", localtime(&attr.st_mtime));
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
	return 0;
}

static int set_vcf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
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
	return 0;
}

static int set_vlf_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
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

/*#Device.DeviceInfo.MemoryStatus.Total!UBUS:router.system/info//memoryKB.total*/
static int get_memory_status_total(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "memoryKB", "total");
	return 0;
}

/*#Device.DeviceInfo.MemoryStatus.Free!UBUS:router.system/info//memoryKB.free*/
static int get_memory_status_free(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "memoryKB", "free");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.CPUUsage!UBUS:router.system/info//system.cpu_per*/
static int get_process_cpu_usage(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 2, "system", "cpu_per");
	return 0;
}

static int get_process_number_of_entries(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *processes = NULL;
	int nbre_process = 0;

	dmubus_call("router.system", "processes", UBUS_ARGS{}, 0, &res);
	if (res) {
		json_object_object_get_ex(res, "processes", &processes);
		if (processes)
			nbre_process = json_object_array_length(processes);
	}
	dmasprintf(value, "%d", nbre_process);
	return 0;
}

static int get_process_pid(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "pid");
	return 0;
}

static int get_process_command(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "command");
	return 0;
}

static int get_process_size(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "vsz");
	return 0;
}

static int get_process_priority(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "priority");
	return 0;
}

static int get_process_cpu_time(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "cputime");
	return 0;
}

static int get_process_state(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "state");
	return 0;
}

static int browsePocessEntriesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *processes = NULL, *arrobj = NULL;
	char *idx, *idx_last = NULL;
	int id = 0, i = 0;

	dmubus_call("router.system", "processes", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, processes, i, 1, "processes") {
			idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)processes, idx) == DM_STOP)
				break;
		}
	}
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

//Browse VendorLogFile instances
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

/* *** Device.DeviceInfo. *** */
DMOBJ tDeviceInfoObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{CUSTOM_PREFIX"CATV", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tCatTvParams, NULL, BBFDM_BOTH},
{"VendorConfigFile", &DMREAD, NULL, NULL, NULL, browseVcfInst, NULL, NULL, NULL, NULL, tDeviceInfoVendorConfigFileParams, NULL, BBFDM_BOTH},
{"VendorLogFile", &DMREAD, NULL, NULL, NULL, browseVlfInst, NULL, NULL, NULL, NULL, tDeviceInfoVendorLogFileParams, NULL, BBFDM_BOTH},
{"MemoryStatus", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoMemoryStatusParams, NULL, BBFDM_BOTH},
{"ProcessStatus", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDeviceInfoProcessStatusObj, tDeviceInfoProcessStatusParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDeviceInfoParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Manufacturer", &DMREAD, DMT_STRING, get_device_manufacturer, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"ManufacturerOUI", &DMREAD, DMT_STRING, get_device_manufactureroui, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"ModelName", &DMREAD, DMT_STRING, get_device_routermodel, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"ProductClass", &DMREAD, DMT_STRING, get_device_productclass, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_device_serialnumber, NULL,  &DMFINFRM, NULL, BBFDM_BOTH},
{"HardwareVersion", &DMREAD, DMT_STRING, get_device_hardwareversion, NULL, &DMFINFRM, NULL, BBFDM_BOTH},
{"SoftwareVersion", &DMREAD, DMT_STRING, get_device_softwareversion, NULL, &DMFINFRM, &DMACTIVE, BBFDM_BOTH},
{"UpTime", &DMREAD, DMT_UNINT, get_device_info_uptime, NULL, NULL, NULL, BBFDM_BOTH},
{"DeviceLog", &DMREAD, DMT_STRING, get_device_devicelog, NULL, NULL, NULL, BBFDM_BOTH},
{"SpecVersion", &DMREAD, DMT_STRING, get_device_specversion, NULL,  &DMFINFRM, NULL, BBFDM_BOTH},
{"ProvisioningCode", &DMWRITE, DMT_STRING, get_device_provisioningcode, set_device_provisioningcode, &DMFINFRM, &DMACTIVE, BBFDM_BOTH},
{CUSTOM_PREFIX"BaseMacAddr", &DMREAD, DMT_STRING, get_base_mac_addr, NULL, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"CATVEnabled", &DMWRITE, DMT_BOOL, get_catv_enabled, set_device_catvenabled, NULL, NULL, BBFDM_BOTH},
{CUSTOM_PREFIX"MemoryBank", &DMWRITE, DMT_INT, get_device_memory_bank, set_device_memory_bank, NULL, NULL, BBFDM_BOTH},
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
{"Total", &DMREAD, DMT_UNINT, get_memory_status_total, NULL, NULL, NULL, BBFDM_BOTH},
{"Free", &DMREAD, DMT_UNINT, get_memory_status_free, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.ProcessStatus. *** */
DMOBJ tDeviceInfoProcessStatusObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Process", &DMREAD, NULL, NULL, NULL, browsePocessEntriesInst, NULL, NULL, NULL, NULL, tDeviceInfoProcessStatusProcessParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDeviceInfoProcessStatusParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"CPUUsage", &DMREAD, DMT_UNINT, get_process_cpu_usage, NULL, NULL, NULL, BBFDM_BOTH},
{"ProcessNumberOfEntries", &DMREAD, DMT_UNINT, get_process_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DeviceInfo.ProcessStatus.Process.{i}. *** */
DMLEAF tDeviceInfoProcessStatusProcessParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"PID", &DMREAD, DMT_UNINT, get_process_pid, NULL, NULL, NULL, BBFDM_BOTH},
{"Command", &DMREAD, DMT_STRING, get_process_command, NULL, NULL, NULL, BBFDM_BOTH},
{"Size", &DMREAD, DMT_UNINT, get_process_size, NULL, NULL, NULL, BBFDM_BOTH},
{"Priority", &DMREAD, DMT_UNINT, get_process_priority, NULL, NULL, NULL, BBFDM_BOTH},
{"CPUTime", &DMREAD, DMT_UNINT, get_process_cpu_time, NULL, NULL, NULL, BBFDM_BOTH},
{"State", &DMREAD, DMT_STRING, get_process_state, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** DeviceInfo.X_IOPSYS_EU_CATV. ***/
DMLEAF tCatTvParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enabled", &DMWRITE, DMT_STRING, get_catv_enabled, set_device_catvenabled, NULL, NULL, BBFDM_BOTH},
{"OpticalInputLevel", &DMREAD, DMT_STRING, get_catv_optical_input_level, NULL, NULL, NULL, BBFDM_BOTH},
{"RFOutputLevel", &DMREAD, DMT_STRING, get_catv_rf_output_level, NULL, NULL, NULL, BBFDM_BOTH},
{"Temperature", &DMREAD, DMT_STRING, get_catv_temperature, NULL, NULL, NULL, BBFDM_BOTH},
{"Voltage", &DMREAD, DMT_STRING, get_catv_voltage, NULL, NULL, NULL, BBFDM_BOTH},
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
