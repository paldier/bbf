#include "os.h"

#include <libbbf_api/dmcommon.h>

char * os__get_deviceid_manufacturer()
{
	char *v;
	dmuci_get_option_value_string("cwmp","cpe","manufacturer", &v);
	if (v[0] == '\0') {
		db_get_value_string("hw", "board", "manufacturer", &v);
		return v;
	}
	return v;
}

char * os__get_deviceid_productclass()
{
	char *v;
	dmuci_get_option_value_string("cwmp", "cpe", "override_productclass", &v);
	if (v[0] == '\0') {
		db_get_value_string("hw", "board", "iopVerFam", &v);
		return v;
	}
	return v;
}

char * os__get_deviceid_serialnumber()
{
	char *v;
	db_get_value_string("hw", "board", "serial_number", &v);
	return v;
}

char * os__get_softwareversion()
{
	char *v;
	db_get_value_string("hw", "board", "iopVersion", &v);
	return v;
}

int os__get_device_hardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	db_get_value_string("hw", "board", "model_name", value);
	return 0;
}

char * os__get_deviceid_manufactureroui()
{
	char *v, *mac = NULL, str[16];
	json_object *res;

	dmuci_get_option_value_string("cwmp", "cpe", "override_oui", &v);
	if (v[0])
		return v;

	dmubus_call("router.system", "info", UBUS_ARGS{{}}, 0, &res);
	if (!(res))
		db_get_value_string("hw", "board", "basemac", &mac);
	else
		mac = dmjson_get_value(res, 1, "basemac");

	if(mac) {
		size_t ln = strlen(mac);
		if (ln < 17) goto not_found;
		sscanf (mac,"%2c:%2c:%2c",str,str+2,str+4);
		str[6] = '\0';
		v = dmstrdup(str); // MEM WILL BE FREED IN DMMEMCLEAN
		return v;
	}

not_found:
	return "";
}

int os__get_base_mac_addr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "info", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "basemac");
	return 0;
}

int os_iopsys_get_device_memory_bank(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("router.system", "memory_bank", UBUS_ARGS{{}}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "code");
	return 0;
}

int os_iopsys_set_device_memory_bank(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int os_iopsys_get_catv_enabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *catv;

	dmuci_get_option_value_string("catv", "catv", "enable", &catv);
	if (strcmp(catv, "on") == 0)
		*value = "1";
	else
		*value = "0";
	return 0;
}

int os_iopsys_set_device_catvenabled(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int os_iopsys_get_catv_optical_input_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	dmubus_call("catv", "vpd", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "VPD");
	return 0;
}

int os_iopsys_get_catv_rf_output_level(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("catv", "rf", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "RF");
	return 0;
}

int os_iopsys_get_catv_temperature(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("catv", "temp", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "Temperature");
	return 0;
}

int os_iopsys_get_catv_voltage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;
	dmubus_call("catv", "vcc", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value(res, 1, "VCC");
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

int os__get_process_pid(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "pid");
	return 0;
}

int os__get_process_command(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "command");
	return 0;
}

int os__get_process_size(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "vsz");
	return 0;
}

int os__get_process_priority(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "priority");
	return 0;
}

int os__get_process_cpu_time(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "cputime");
	return 0;
}

int os__get_process_state(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "state");
	return 0;
}

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
