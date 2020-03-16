#include "os.h"

#include <libbbf_api/dmcommon.h>

#define BASE_IFACE "br-lan"

char * os__get_deviceid_manufactureroui()
{
	char *v;

	get_net_device_sysfs(BASE_IFACE, "address", &v);
	return v;
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
