#include "os.h"
#include "dmentry.h"

struct host_args
{
	json_object *client;
	char *key;
};


static char * get_interface_type(char *mac, char *ndev)
{
	json_object *res;
	int wlctl_num;
	struct uci_section *s, *d;
	char buf[8], *p, *network, *value, *wunit;

	uci_foreach_sections("wireless", "wifi-device", d) {
		wlctl_num = 0;
		wunit = section_name(d);
		uci_foreach_option_eq("wireless", "wifi-iface", "device", wunit, s) {
			dmuci_get_value_by_section_string(s, "network", &network);
			if (strcmp(network, ndev) == 0) {
				if (wlctl_num != 0) {
					snprintf(buf, sizeof(buf), "%s.%d", wunit, wlctl_num);
					p = buf;
				} else {
					p = wunit;
				}
				dmubus_call("router.wireless", "stas", UBUS_ARGS{{"vif", p, String}}, 1, &res);
				if(res) {
					json_object_object_foreach(res, key, val) {
						UNUSED(key);
						value = dmjson_get_value(val, 1, "macaddr");
						if (strcasecmp(value, mac) == 0)
							return "802.11";
					}
				}
				wlctl_num++;
			}
		}
	}
	return "Ethernet";
}

static inline int init_host_args(struct host_args *args, json_object *clients, char *key)
{
	args->client = clients;
	args->key = key;
	return 0;
}

int os__browsehostInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res;
	char *idx, *idx_last = NULL, *connected;
	int id = 0;
	struct host_args curr_host_args = {0};

	dmubus_call("router.network", "clients", UBUS_ARGS{}, 0, &res);
	if (res) {
		json_object_object_foreach(res, key, client_obj) {
			connected = dmjson_get_value(client_obj, 1, "connected");
			if(strcmp(connected, "false") == 0)
				continue;
			init_host_args(&curr_host_args, client_obj, key);
			idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_host_args, idx) == DM_STOP)
				break;
		}
	}
	return 0;
}

int os__get_host_nbr_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int entries = 0;
	json_object *res;

	dmubus_call("router.network", "clients", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_foreach(res, key, client_obj) {
		UNUSED(key);
		UNUSED(client_obj);
		entries++;
	}
	dmasprintf(value, "%d", entries); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

int os__get_host_interfacetype(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mac, *network;

	mac = dmjson_get_value(((struct host_args *)data)->client, 1, "macaddr");
	network = dmjson_get_value(((struct host_args *)data)->client, 1, "network");
	*value = get_interface_type(mac, network);
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
int os__get_host_associateddevice(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *ss;
	char *accesspointInstance = NULL, *wifiAssociativeDeviecPath;
	char *macaddr_linker = dmjson_get_value(((struct host_args *)data)->client, 1, "macaddr");

	uci_path_foreach_sections(bbfdm, "dmmap_wireless", "wifi-iface", ss) {
		dmuci_get_value_by_section_string(ss, "accesspointinstance", &accesspointInstance);
		if(accesspointInstance[0] != '\0')
			dmasprintf(&wifiAssociativeDeviecPath, "Device.WiFi.AccessPoint.%s.AssociatedDevice.", accesspointInstance);
		accesspointInstance = NULL;
		adm_entry_get_linker_param(ctx, wifiAssociativeDeviecPath, macaddr_linker, value);
		if(*value != NULL)
			break;
	}

	if (*value == NULL)
		*value = "";
	return 0;
}

int os__get_host_layer3interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ip_linker=dmjson_get_value(((struct host_args *)data)->client, 1, "network");
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", ip_linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int os__get_host_interface_type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *type= NULL;
	char *ifname = dmjson_get_value(((struct host_args *)data)->client, 1, "network");
	struct uci_section *ss = NULL;

	uci_foreach_sections("network", "interface", ss) {
		if (!strcmp(ifname, section_name(ss))) {
			dmuci_get_value_by_section_string(ss, "type", &type);
			if (type!=NULL) {
				if (!strcmp(type, "bridge")) *value="Bridge";else *value= "Normal";
				break;
			}
		}
	}
	return 0;
}

int os__get_host_interfacename(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *frequency, *wireless;

	frequency = dmjson_get_value(((struct host_args *)data)->client, 1, "frequency");
	wireless = dmjson_get_value(((struct host_args *)data)->client, 1, "wireless");
	if ((*frequency != '\0') && (strcmp(wireless, "true")==0)) {
		if(strcmp(frequency,"5GHz")==0)
			*value = "WiFi@5GHz";
		else
			*value = "WiFi@2.4GHz";
	} else {
		*value = dmjson_get_value(((struct host_args *)data)->client, 1, "ethport");
		if (*value == NULL)
			*value = "";
	}
	return 0;
}

int os__get_host_ipaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct host_args *)data)->client, 1, "ipaddr");
	return 0;
}

int os__get_host_hostname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct host_args *)data)->client, 1, "hostname");
	return 0;
}

int os__get_host_active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct host_args *)data)->client, 1, "connected");
	return 0;
}

int os__get_host_phy_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct host_args *)data)->client, 1, "macaddr");
	return 0;
}

int os__get_host_address_source(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dhcp;

	dhcp = dmjson_get_value(((struct host_args *)data)->client, 1, "dhcp");
	if (strcasecmp(dhcp, "true") == 0)
		*value = "DHCP";
	else
		*value = "Static";
	return 0;
}

int os__get_host_leasetime_remaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dhcp;
	FILE *fp;
	char line[MAX_DHCP_LEASES];
	char *leasetime, *mac_f, *mac, *line1;
	char delimiter[] = " \t";

	dhcp = dmjson_get_value(((struct host_args *)data)->client, 1, "dhcp");
	if (strcmp(dhcp, "false") == 0) {
		*value = "0";
	}
	else {
		mac = dmjson_get_value(((struct host_args *)data)->client, 1, "macaddr");
		fp = fopen(DHCP_LEASES_FILE, "r");
		if ( fp != NULL)
		{
			while (fgets(line, MAX_DHCP_LEASES, fp) != NULL )
			{
				if (line[0] == '\n')
					continue;
				line1 = dmstrdup(line);
				leasetime = cut_fx(line, delimiter, 1);
				mac_f = cut_fx(line1, delimiter, 2);
				if (strcasecmp(mac, mac_f) == 0) {
					int rem_lease = atoi(leasetime) - time(NULL);
					if (rem_lease < 0)
						*value = "-1";
					else
						dmasprintf(value, "%d", rem_lease); // MEM WILL BE FREED IN DMMEMCLEAN
					fclose(fp) ;
					return 0;
				}
			}
			fclose(fp);
			*value = "0";
		}
	}
	return 0;
}

int os__get_host_dhcp_client(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;
	dmasprintf(&linker, "%s", ((struct host_args *)data)->key);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cDHCPv4%c", dmroot, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL) {
		*value = "";
	}
	dmfree(linker);
	return 0;
}