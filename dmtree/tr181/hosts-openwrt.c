#include "os.h"

static int not_implemented(char **value)
{
	*value = "";
	return 0;
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
int os__browseHostsHostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

int os__browseHostsHostIPv4AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

int os__browseHostsHostIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
int os__get_Hosts_HostNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__set_HostsHost_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

int os__get_HostsHost_PhysAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_AddressSource(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_DHCPClient(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_LeaseTimeRemaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_AssociatedDevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_Layer1Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_Layer3Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_InterfaceType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_ClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_HostName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_Active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_IPv4AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHost_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostIPv4Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostWANStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostWANStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostWANStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostWANStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostWANStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostWANStats_RetransCount(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os__get_HostsHostWANStats_DiscardPacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}
