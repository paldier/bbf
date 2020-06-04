#include "os.h"

#include <libbbf_api/dmcommon.h>

#define BASE_IFACE "br-lan"

static char * get_uci_deviceinfo(char *opt)
{
	char *v;

	dmuci_get_option_value_string("cwmp", "@deviceinfo[0]", opt, &v);
	return v;
}

char * os__get_deviceid_manufacturer()
{
	return get_uci_deviceinfo("Manufacturer");
}

char * os__get_deviceid_productclass()
{
	return get_uci_deviceinfo("ProductClass");
}

char * os__get_deviceid_serialnumber()
{
	return get_uci_deviceinfo("SerialNumber");
}

char * os__get_softwareversion()
{
	return get_uci_deviceinfo("SoftwareVersion");
}

int os__get_device_hardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("HardwareVersion");
	return 0;
}

int os__get_device_devicecategory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("DeviceCategory");
	return 0;
}

int os__get_device_additionalhardwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("AdditionalHardwareVersion");
	return 0;
}

int os__get_device_additionalsoftwareversion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("AdditionalSoftwareVersion");
	return 0;
}

int os__get_device_modelname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("ModelName");
	return 0;
}

int os__get_device_description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = get_uci_deviceinfo("Description");
	return 0;
}

char * os__get_deviceid_manufactureroui()
{
	return get_uci_deviceinfo("ManufacturerOUI");
}

int os__get_base_mac_addr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return get_net_device_sysfs(BASE_IFACE, "address", value);
}

static int not_implemented(char **value)
{
	*value = "";
	return 0;
}

int os__get_memory_status_total(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_memory_status_free(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_process_cpu_usage(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_process_number_of_entries(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_process_pid(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_process_command(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_process_size(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_process_priority(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_process_cpu_time(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_process_state(char* refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__browseProcessEntriesInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}
