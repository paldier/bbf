#include "os.h"


static int not_implemented(char **value)
{
	*value = "";
	return 0;
}

int os__browsehostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

int os__get_host_nbr_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_associateddevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_layer3interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_phy_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_address_source(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_leasetime_remaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_host_dhcp_client(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}
