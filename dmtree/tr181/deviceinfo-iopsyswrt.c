#include "os.h"

#include <libbbf_api/dmcommon.h>

/*#Device.DeviceInfo.Manufacturer!UCI:cwmp/cpe,cpe/manufacturer*/
char * os__get_deviceid_manufacturer()
{
	char *v;
	dmuci_get_option_value_string("cwmp","cpe","manufacturer", &v);
	if (v[0] == '\0') {
		db_get_value_string("device", "deviceinfo", "Manufacturer", &v);
		return v;
	}
	return v;
}

/*#Device.DeviceInfo.ProductClass!UCI:cwmp/cpe,cpe/product_class*/
char * os__get_deviceid_productclass()
{
	char *v;
	dmuci_get_option_value_string("cwmp", "cpe", "product_class", &v);
	if (v[0] == '\0') {
		db_get_value_string("device", "deviceinfo", "ProductClass", &v);
		return v;
	}
	return v;
}

char * os__get_deviceid_serialnumber()
{
	char *v;
	db_get_value_string("device", "deviceinfo", "SerialNumber", &v);
	return v;
}

char * os__get_softwareversion()
{
	char *v;
	db_get_value_string("device", "deviceinfo", "SoftwareVersion", &v);
	return v;
}

int os__get_device_hardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "HardwareVersion", value);
	return 0;
}

int os__get_device_devicecategory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "DeviceCategory", value);
	return 0;
}

int os__get_device_additionalhardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "AdditionalHardwareVersion", value);
	return 0;
}

int os__get_device_additionalsoftwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "AdditionalSoftwareVersion", value);
	return 0;
}

/*#Device.DeviceInfo.ModelName!UCI:cwmp/cpe,cpe/model_name*/
int os__get_device_modelname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "model_name", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "ModelName", value);
	return 0;
}

/*#Device.DeviceInfo.Description!UCI:cwmp/cpe,cpe/description*/
int os__get_device_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp", "cpe", "description", value);
	if (*value[0] == '\0')
		db_get_value_string("device", "deviceinfo", "Description", value);
	return 0;
}

/*#Device.DeviceInfo.ManufacturerOUI!UCI:cwmp/cpe,cpe/manufacturer_oui*/
char * os__get_deviceid_manufactureroui()
{
	char *v;
	dmuci_get_option_value_string("cwmp", "cpe", "manufacturer_oui", &v);
	if (v[0] == '\0') {
		db_get_value_string("device", "deviceinfo", "ManufacturerOUI", &v);
		return v;
	}
	return v;
}

int os__get_base_mac_addr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("device", "deviceinfo", "BaseMACAddress", value);
	return 0;
}

/*#Device.DeviceInfo.MemoryStatus.Total!UBUS:router.system/memory//total*/
int os__get_memory_status_total(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "memory", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "total");
	return 0;
}

/*#Device.DeviceInfo.MemoryStatus.Free!UBUS:router.system/memory//free*/
int os__get_memory_status_free(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "memory", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "free");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.CPUUsage!UBUS:router.system/process//cpu_usage*/
int os__get_process_cpu_usage(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "process", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "0");
	*value = dmjson_get_value(res, 1, "cpu_usage");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.ProcessNumberOfEntries!UBUS:router.system/processes//processes*/
int os__get_process_number_of_entries(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.PID!UBUS:router.system/processes//processes[@i-1].pid*/
int os__get_process_pid(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "pid");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.Command!UBUS:router.system/processes//processes[@i-1].command*/
int os__get_process_command(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "command");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.Size!UBUS:router.system/processes//processes[@i-1].vsz*/
int os__get_process_size(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "vsz");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.Priority!UBUS:router.system/processes//processes[@i-1].priority*/
int os__get_process_priority(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "priority");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.CPUTime!UBUS:router.system/processes//processes[@i-1].cputime*/
int os__get_process_cpu_time(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "cputime");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.State!UBUS:router.system/processes//processes[@i-1].state*/
int os__get_process_state(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "state");
	return 0;
}

/*#Device.DeviceInfo.ProcessStatus.Process.{i}.!UBUS:router.system/processes//processes*/
int os__browseProcessEntriesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
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
