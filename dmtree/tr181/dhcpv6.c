/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "dmentry.h"
#include "dhcpv4.h"
#include "dhcpv6.h"


struct dhcpv6_client_args
{
	struct uci_section *dhcp_client_conf;
	struct uci_section *dhcp_client_dm;
	char *ip;
};

struct dhcpv6_args
{
	struct uci_section *dhcp_sec;
	char *interface;
};

struct clientv6_args
{
	json_object *client;
	json_object *clientparam;
	int idx;
};

struct dhcpv6_client_option_args {
	struct uci_section *opt_sect;
	struct uci_section *client_sect;
	char *option_tag;
	char *value;
};

struct uci_section* get_dhcpv6_classifier(char *classifier_name, char *network)
{
	struct uci_section *s = NULL;
	char *v;

	uci_foreach_sections("dhcp", classifier_name, s) {
		dmuci_get_value_by_section_string(s, "networkid", &v);
		if (strcmp(v, network) == 0)
			return s;
	}
	return NULL;
}

static inline int init_dhcpv6_client_args(struct clientv6_args *args, json_object *client, json_object *client_param, int i)
{
	args->client = client;
	args->clientparam = client_param;
	args->idx = i;
	return 0;
}

struct uci_section* exist_other_section_dhcp6_same_order(struct uci_section *dmmap_sect, char * package, char* sect_type, char *order)
{
	struct uci_section *s;
	uci_path_foreach_option_eq(bbfdm, package, sect_type, "order", order, s) {
		if (strcmp(section_name(s), section_name(dmmap_sect)) != 0) {
			return s;
		}
	}
	return NULL;
}

static int set_section_dhcp6_order(char *package, char *dmpackage, char* sect_type, struct uci_section *dmmap_sect, struct uci_section *conf, int set_force, char* order)
{
	char *v = NULL, *sect_name, *incrorder;
	struct uci_section *s, *dm;
	dmuci_get_value_by_section_string(dmmap_sect, "order", &v);
	if(strlen(v) > 0 && strcmp(v, order) == 0)
		return 0;
	DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "order", order);
	if (conf == NULL) {
		dmuci_get_value_by_section_string(dmmap_sect, "section_name", &sect_name);
		get_config_section_of_dmmap_section(package, sect_type, sect_name, &s);
	} else
		s= conf;

	if (strcmp(order, "1") != 0 && s != NULL) {
		dmuci_set_value_by_section(s, "force", "");
	}

	if (set_force==1 && strcmp(order, "1") == 0 && s != NULL) {
		dmuci_set_value_by_section(s, "force", "1");
	}

	if ((dm = exist_other_section_dhcp6_same_order(dmmap_sect, dmpackage, sect_type, order)) != NULL) {
		dmuci_get_value_by_section_string(dm, "section_name", &sect_name);
		get_config_section_of_dmmap_section(package, sect_type, sect_name, &s);
		dmasprintf(&incrorder, "%d", atoi(order)+1);
		if (s != NULL && strcmp(order, "1") == 0) {
			dmuci_set_value_by_section(s, "force", "");
		}
		set_section_dhcp6_order(package, dmpackage, sect_type, dm, s, set_force, incrorder);
	}
	return 0;

}

static inline int init_dhcpv6_args(struct dhcpv6_args *args, struct uci_section *s, char *interface)
{
	args->interface = interface;
	args->dhcp_sec = s;
	return 0;
}

/*#Device.DHCPv6.Client.{i}.!UCI:network/interface/dmmap_dhcpv6*/
static int browseDHCPv6ClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p;
	struct dhcpv6_client_args dhcpv6_client_arg = {0};
	json_object *res, *jobj;
	char *instance, *instnbr = NULL, *ipv6addr = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq_no_delete("network", "interface", "dmmap_dhcpv6", "proto", "dhcpv6", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(p->config_section), String}}, 1, &res);
		if (res) {
			jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
			ipv6addr = dmjson_get_value(jobj, 1, "address");
		}
		dhcpv6_client_arg.dhcp_client_conf = p->config_section;
		dhcpv6_client_arg.dhcp_client_dm = p->dmmap_section;
		dhcpv6_client_arg.ip = dmstrdup(ipv6addr?ipv6addr:"");
		instance = handle_update_instance(1, dmctx, &instnbr, update_instance_alias, 3, p->dmmap_section, "bbf_dhcpv6client_instance", "bbf_dhcpv6client_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &dhcpv6_client_arg, instance) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.!UCI:dhcp/dhcp/dmmap_dhcpv6*/
static int browseDHCPv6ServerPoolInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *interface, *idhcp = NULL, *idhcp_last = NULL, *v;
	struct dhcpv6_args curr_dhcp6_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq("dhcp", "dhcp", "dmmap_dhcpv6", "dhcpv6", "server", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "interface", &interface);
		init_dhcpv6_args(&curr_dhcp6_args, p->config_section, interface);
		idhcp = handle_update_instance(1, dmctx, &idhcp_last, update_instance_alias_bbfdm, 3, p->dmmap_section, "dhcpv6_serv_pool_instance", "dhcpv6_serv_pool_alias");
		dmuci_get_value_by_section_string(p->dmmap_section, "order", &v);
		if (v == NULL || strlen(v) == 0)
			set_section_dhcp6_order("dhcp", "dmmap_dhcpv6", "dhcp", p->dmmap_section, p->config_section, 0, idhcp);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp6_args, idhcp) == DM_STOP)
			break;
	}

	free_dmmap_config_dup_list(&dup_list);

	return 0;
}

static int browseDHCPv6ServerPoolClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcpv6_args *dhcp_arg= (struct dhcpv6_args*)prev_data;
	json_object *res, *res1, *jobj, *dev_obj= NULL, *net_obj= NULL;
	struct clientv6_args curr_dhcp_client_args = {0};
	int i = 0;
	char *idx = NULL, *idx_last = NULL, *device;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(dhcp_arg->dhcp_sec), String}}, 1, &res1);
	if (!res1) return 0;
	device = dmjson_get_value(res1, 1, "device");
	dmubus_call("dhcp", "ipv6leases", UBUS_ARGS{}, 0, &res);
	if (!res) return 0;
	dev_obj = dmjson_get_obj(res, 1, "device");
	if (!dev_obj) return 0;
	net_obj = dmjson_get_obj(dev_obj, 1, device);
	if (!net_obj) return 0;

	while (1) {
		jobj = dmjson_select_obj_in_array_idx(net_obj, i, 1, "leases");
		if (!jobj) break;
		init_dhcpv6_client_args(&curr_dhcp_client_args, jobj, NULL, i);
		i++;
		idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, i);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_client_args, idx) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv6ServerPoolOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e;
	struct dhcpv6_args *curr_dhcp_args = (struct dhcpv6_args*)prev_data;
	struct uci_section *dmmap_sect;
	char **tagvalue = NULL, *instance, *instnbr = NULL, *optionvalue= NULL, *tmp, *v1, *v2, *v;
	size_t length;
	int j;
	struct dhcpv6_client_option_args dhcp_client_opt_args = {0};

	check_create_dmmap_package("dmmap_dhcpv6");
	dmuci_get_value_by_section_list(curr_dhcp_args->dhcp_sec, "dhcp_option", &dhcp_options_list);
	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {
			tagvalue= strsplit(e->name, ",", &length);
			if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcpv6", "servpool_option", section_name(curr_dhcp_args->dhcp_sec), "option_tag", tagvalue[0])) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcpv6", "servpool_option", &dmmap_sect, &v);
				DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_tag", tagvalue[0]);
				DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(curr_dhcp_args->dhcp_sec));
			}
			optionvalue=dmstrdup(length>1?tagvalue[1]:"");
			if (length > 2) {
				for (j = 2; j < length; j++){
					tmp=dmstrdup(optionvalue);
					dmfree(optionvalue);
					optionvalue= NULL;
					dmasprintf(&optionvalue, "%s,%s", tmp, tagvalue[j]);
					dmfree(tmp);
					tmp= NULL;
				}
			}
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_value", optionvalue);
		}
	}
	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcpv6", "servpool_option", "section_name", section_name(curr_dhcp_args->dhcp_sec), dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &v1);
		dmuci_get_value_by_section_string(dmmap_sect, "option_value", &v2);
		dhcp_client_opt_args.client_sect= curr_dhcp_args->dhcp_sec;
		dhcp_client_opt_args.option_tag = dmstrdup(v1);
		dhcp_client_opt_args.value = dmstrdup(v2);
		dhcp_client_opt_args.opt_sect = dmmap_sect;
		instance= handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, dmmap_sect, "bbf_dhcpv6_servpool_option_instance", "bbf_dhcpv6_servpool_option_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &dhcp_client_opt_args, instance) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv6ServerPoolClientIPv6AddressInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct clientv6_args *dhcpv6_serv_pool_client = (struct clientv6_args *)prev_data;
	json_object *address_obj= NULL;
	struct clientv6_args curr_dhcv6_address_args = {0};
	char *idx = NULL, *idx_last = NULL;
	int i = 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(dhcpv6_serv_pool_client->client, i, 1, "ipv6-addr");
		if (address_obj == NULL)
			break;
		init_dhcpv6_client_args(&curr_dhcv6_address_args, dhcpv6_serv_pool_client->client, address_obj, i);
		i++;
		idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, i);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcv6_address_args, idx) == DM_STOP)
			break;
	}

	return 0;
}

static int browseDHCPv6ServerPoolClientIPv6PrefixInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct clientv6_args *dhcpv6_serv_pool_client = (struct clientv6_args *)prev_data;
	json_object *address_obj = NULL;
	struct clientv6_args curr_dhcv6_address_args = {0};
	char *idx = NULL, *idx_last = NULL;
	int i = 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(dhcpv6_serv_pool_client->client, i, 1, "ipv6-prefix");
		if (address_obj == NULL)
			break;
		init_dhcpv6_client_args(&curr_dhcv6_address_args, dhcpv6_serv_pool_client->client, address_obj, i);
		i++;
		idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, i);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcv6_address_args, idx) == DM_STOP)
			break;
	}

	return 0;
}

static int addObjDHCPv6Client(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s, *dmmap_sect;
	char *value, *instancepara, *v;

	check_create_dmmap_package("dmmap_dhcpv6");
	instancepara = get_last_instance_bbfdm("dmmap_dhcpv6", "interface", "bbf_dhcpv6client_instance");
	dmuci_add_section("network", "interface", &s, &value);
	dmuci_set_value_by_section(s, "proto", "dhcpv6");
	dmuci_set_value_by_section(s, "ifname", "@wan");
	dmuci_set_value_by_section(s, "type", "anywan");
	dmuci_add_section_bbfdm("dmmap_dhcpv6", "interface", &dmmap_sect, &v);
	dmuci_set_value_by_section(dmmap_sect, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_sect, instancepara, "bbf_dhcpv6client_instance");
	return 0;
}

static int delObjDHCPv6Client(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dhcpv6_client_args *dhcpv6_client_args = (struct dhcpv6_client_args*)data;
	struct uci_section *s, *dmmap_section, *ss = NULL;
	int found = 0;
	char *proto;

	switch (del_action) {
		case DEL_INST:
			if(dhcpv6_client_args->dhcp_client_conf != NULL && is_section_unnamed(section_name(dhcpv6_client_args->dhcp_client_conf))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_dhcpv6", "interface", "bbf_dhcpv6client_instance", section_name(dhcpv6_client_args->dhcp_client_conf), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "bbf_dhcpv6client_instance", "dmmap_dhcpv6", "interface");
				dmuci_delete_by_section_unnamed(dhcpv6_client_args->dhcp_client_conf, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_dhcpv6", "interface", section_name(dhcpv6_client_args->dhcp_client_conf), &dmmap_section);
				dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(dhcpv6_client_args->dhcp_client_conf, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("network", "interface", s) {
				if (found != 0) {
					dmuci_get_value_by_section_string(ss, "proto", &proto);
					if(strcmp(proto, "dhcpv6") == 0) {
						get_dmmap_section_of_config_section("dmmap_dhcpv6", "interface", section_name(ss), &dmmap_section);
						if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
						dmuci_delete_by_section(ss, NULL, NULL);
					}
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				dmuci_get_value_by_section_string(ss, "proto", &proto);
				if (strcmp(proto, "dhcpv6") == 0) {
					get_dmmap_section_of_config_section("dmmap_dhcpv6", "interface", section_name(ss), &dmmap_section);
					if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
			}
			break;
	}
	return 0;
}

static int addObjDHCPv6ServerPool(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *value, *v, *instancepara;
	struct uci_section *s = NULL, *dmmap_dhcp= NULL;

	check_create_dmmap_package("dmmap_dhcpv6");
	instancepara = get_last_instance_bbfdm("dmmap_dhcpv6", "dhcp", "dhcpv6_serv_pool_instance");
	dmuci_add_section("dhcp", "dhcp", &s, &value);
	dmuci_set_value_by_section(s, "dhcpv6", "server");
	dmuci_set_value_by_section(s, "start", "100");
	dmuci_set_value_by_section(s, "leasetime", "12h");
	dmuci_set_value_by_section(s, "limit", "150");

	dmuci_add_section_bbfdm("dmmap_dhcpv6", "dhcp", &dmmap_dhcp, &v);
	dmuci_set_value_by_section(dmmap_dhcp, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_dhcp, instancepara, "dhcpv6_serv_pool_instance");
	return 0;
}

static int delObjDHCPv6ServerPool(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	char *dhcpv6 = NULL;

	switch (del_action) {
		case DEL_INST:
			if(is_section_unnamed(section_name(((struct dhcpv6_args *)data)->dhcp_sec))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_dhcpv6", "dhcp", "dhcpv6_serv_pool_instance", section_name(((struct dhcpv6_args *)data)->dhcp_sec), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "dhcpv6_serv_pool_instance", "dmmap_dhcpv6", "dhcp");
				dmuci_delete_by_section_unnamed(((struct dhcpv6_args *)data)->dhcp_sec, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_section);
				if(dmmap_section) dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(((struct dhcpv6_args *)data)->dhcp_sec, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("dhcp", "dhcp", s) {
				if (found != 0){
					dmuci_get_value_by_section_string(ss, "dhcpv6", &dhcpv6);
					if(strcmp(dhcpv6, "server") == 0){
						get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(s), &dmmap_section);
						if (dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
						dmuci_delete_by_section(ss, NULL, NULL);
					}
				}
				ss = s;
				found++;
			}
			if (ss != NULL){
				dmuci_get_value_by_section_string(ss, "dhcpv6", &dhcpv6);
				if(strcmp(dhcpv6, "server") == 0){
					get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(ss), &dmmap_section);
					if(dmmap_section) dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
			}
			break;
	}
	return 0;
}

static int addObjDHCPv6ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcpv6_args *dhcp_arg = (struct dhcpv6_args*)data;
	struct uci_section *dmmap_sect;
	char *value, *instancepara;

	check_create_dmmap_package("dmmap_dhcpv6");
	instancepara = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_dhcpv6", "servpool_option", "bbf_dhcpv6_servpool_option_instance", "section_name", section_name(dhcp_arg->dhcp_sec));
	dmuci_add_section_bbfdm("dmmap_dhcpv6", "servpool_option", &dmmap_sect, &value);
	if (dhcp_arg->dhcp_sec != NULL)
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(dhcp_arg->dhcp_sec));
	DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_tag", "0");
	*instance = update_instance_bbfdm(dmmap_sect, instancepara, "bbf_dhcpv6_servpool_option_instance");
	return 0;
}

static int delObjDHCPv6ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s, *stmp;
	char *opt_value = NULL;
	struct uci_list *dhcp_options_list = NULL;

	switch (del_action) {
		case DEL_INST:
			if (strcmp(((struct dhcpv6_client_option_args*) data)->option_tag, "0") != 0) {
				dmasprintf(&opt_value, "%s,%s", ((struct dhcpv6_client_option_args*) data)->option_tag, ((struct dhcpv6_client_option_args*) data)->value);
				dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args*) data)->client_sect, "dhcp_option", &dhcp_options_list);
				if (dhcp_options_list != NULL) {
					dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args*) data)->client_sect, "dhcp_option", opt_value);
				}
			}
			dmuci_delete_by_section_unnamed_bbfdm(((struct dhcpv6_client_option_args*) data)->opt_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dhcpv6_args*) data)->dhcp_sec, "dhcp_option", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcpv6", "servpool_option", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int get_DHCPv6_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_sections(bbfdm, "dmmap_dhcpv6", "interface", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.DHCPv6.Client.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv6Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;

	if (((struct dhcpv6_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "0";
		return 0;
	}

	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "disabled", &v);
	if (v == NULL || strlen(v) == 0 || strcmp(v, "1") != 0)
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_DHCPv6Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		return 0;
	case VALUESET:
		string_to_bool(value, &b);
		dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "disabled", b ? "0" : "1");
		return 0;
	}
	return 0;
}

static int get_DHCPv6Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_dm, "bbf_dhcpv6client_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv6Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_dm, "bbf_dhcpv6client_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv6Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct dhcpv6_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "";
		return 0;
	}

	char *linker = dmstrdup(section_name(((struct dhcpv6_client_args *)data)->dhcp_client_conf));
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim), linker, value);
	return 0;
}

static int set_DHCPv6Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *linker = NULL, *newvalue = NULL, *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;

			if (strlen(value) == 0 || strcmp(value, "") == 0) {
				return FAULT_9007;
			}

			if (value[strlen(value)-1] != '.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else {
				adm_entry_get_linker_value(ctx, value, &linker);
			}
			uci_path_foreach_sections(bbfdm, "dmmap_dhcpv6", "interface", s) {
				dmuci_get_value_by_section_string(s, "section_name", &v);
				if (strcmp(v, linker) == 0)
					return FAULT_9007;
			}
			uci_foreach_sections("network", "interface", s) {
				if (strcmp(section_name(s), linker) == 0) {
					dmuci_get_value_by_section_string(s, "proto", &v);
					if (strcmp(v, "dhcpv6") != 0)
						return FAULT_9007;
				}
			}
			break;
		case VALUESET:
			if (value[strlen(value)-1]!='.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else {
				adm_entry_get_linker_value(ctx, value, &linker);
			}
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcpv6_client_args *)data)->dhcp_client_dm, "section_name", linker);
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv6Client_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;
	if(((struct dhcpv6_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "Error_Misconfigured";
		return 0;
	}

	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "disabled", &v);
	if (v == NULL || strlen(v) == 0 || strcmp(v, "1") != 0)
		*value = "Enabled";
	else
		*value = "Disabled";
	return 0;
}

/*#Device.DHCPv6.Client.{i}.DUID!UBUS:network.interface/status/interface,@Name/data.passthru*/
static int get_DHCPv6Client_DUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dhcpv6_client_args *)data)->dhcp_client_conf), String}}, 1, &res);
	if (res) {
		*value = dmjson_get_value(res, 2, "data", "passthru");
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestAddresses!UCI:network/interface,@i-1/reqaddress*/
static int get_DHCPv6Client_RequestAddresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;
	if(((struct dhcpv6_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "";
		return 0;
	}

	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqaddress", &v);
	if (strcmp(v, "none") == 0)
		*value = "0";
	else
		*value = "1";
	return 0;
}

static int set_DHCPv6Client_RequestAddresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqaddress", b ? "force" : "none");
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestPrefixes!UCI:network/interface,@i-1/reqprefix*/
static int get_DHCPv6Client_RequestPrefixes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = "";
	if (((struct dhcpv6_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "";
		return 0;
	}

	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqprefix", &v);
	if (strcmp(v, "no") == 0)
		*value = "0";
	else
		*value = "1";
	return 0;
}

static int set_DHCPv6Client_RequestPrefixes(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqprefix", b ? "auto" : "no");
			return 0;
	}
	return 0;
}

static int get_DHCPv6Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	return 0;
}

static int set_DHCPv6Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res;
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if (((struct dhcpv6_client_args *)data)->dhcp_client_conf == NULL && !b)
				return 0;

			dmubus_call("network.interface", "renew", UBUS_ARGS{{"interface", section_name(((struct dhcpv6_client_args *)data)->dhcp_client_conf), String}}, 1, &res);
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Client.{i}.RequestedOptions!UCI:network/interface,@i-1/reqopts*/
static int get_DHCPv6Client_RequestedOptions(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct dhcpv6_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "";
		return 0;
	}
	dmuci_get_value_by_section_string(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqopts", value);
	return 0;
}

static int set_DHCPv6Client_RequestedOptions(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt_list(value, -1, -1, -1, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcpv6_client_args *)data)->dhcp_client_conf, "reqopts", value);
			break;
	}
	return 0;
}

static int get_DHCPv6Server_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*odhcpd";
	if (check_file(path))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_DHCPv6Server_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmcmd("/etc/init.d/odhcpd", 1, b ? "enable" : "disable");
			break;
	}
    return 0;
}

static int get_DHCPv6Server_PoolNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int i = 0;
	char *v = NULL;

	uci_foreach_sections("dhcp", "dhcp", s) {
		dmuci_get_value_by_section_string(s, "dhcpv6", &v);
		if (v!=NULL && strcmp(v, "server") == 0)
			i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Enable!UCI:dhcp/dhcp,@i-1/ignore*/
static int get_DHCPv6ServerPool_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcpv6_args *)data)->interface, s) {
		dmuci_get_value_by_section_string(s, "ignore", value);
		if ((*value)[0] == '\0')
			*value = "1";
		else
			*value = "0";
		return 0;
	}
	*value = "0";
	return 0;
}

static int set_DHCPv6ServerPool_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcpv6_args *)data)->interface, s) {
				dmuci_set_value_by_section(s, "ignore", b ? "0" : "1");
				break;
			}
			return 0;
	}
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Status!UCI:dhcp/dhcp,@i-1/ignore*/
static int get_DHCPv6ServerPool_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *v= NULL;

	uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcpv6_args *)data)->interface, s) {
		dmuci_get_value_by_section_string(s, "ignore", &v);
		*value = (v && *v == '1') ? "Disabled" : "Enabled";
		return 0;
	}
	*value="Error_Misconfigured";
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.Alias!UCI:dmmap_dhcpv6/dhcp,@i-1/dhcpv6_serv_pool_alias*/
static int get_DHCPv6ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_sect);
	dmuci_get_value_by_section_string(dmmap_sect, "dhcpv6_serv_pool_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv6ServerPool_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_sect);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "dhcpv6_serv_pool_alias", value);
			return 0;
	}
	return 0;
}

static int get_DHCPv6ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_sect);
	if (dmmap_sect)
		dmuci_get_value_by_section_string(dmmap_sect, "order", value);
	return 0;
}

static int set_DHCPv6ServerPool_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcpv6", "dhcp", section_name(((struct dhcpv6_args *)data)->dhcp_sec), &dmmap_sect);
			if (dmmap_sect)
				set_section_order("dhcp", "dmmap_dhcpv6", "dhcp", dmmap_sect, ((struct dhcpv6_args *)data)->dhcp_sec, 1, value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;
	linker = dmstrdup(((struct dhcpv6_args *)data)->interface);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	dmfree(linker);
	return 0;
}

static int set_DHCPv6ServerPool_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmuci_set_value_by_section(((struct dhcpv6_args *)data)->dhcp_sec, "interface", linker);
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.VendorClassID!UCI:dhcp/dhcp,@i-1/vendorclass*/
static int get_DHCPv6ServerPool_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value) //TODO return wrong value
{
	struct uci_section *vendorclassidclassifier = get_dhcpv6_classifier("vendorclass", ((struct dhcpv6_args *)data)->interface);
	if (vendorclassidclassifier)
		dmuci_get_value_by_section_string(vendorclassidclassifier, "vendorclass", value);
	return 0;
}

static int set_DHCPv6ServerPool_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *vendorclassidclassifier = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			vendorclassidclassifier = get_dhcpv6_classifier("vendorclass", ((struct dhcpv6_args *)data)->interface);
			if (vendorclassidclassifier)
				dmuci_set_value_by_section(vendorclassidclassifier, "vendorclass", value);
			break;
	}
	return 0;
}

/*#Device.DHCPv6.Server.Pool.{i}.UserClassID!UCI:dhcp/dhcp,@i-1/userclass*/
static int get_DHCPv6ServerPool_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *userclassidclassifier= get_dhcpv6_classifier("userclass", ((struct dhcpv6_args *)data)->interface);
	if (userclassidclassifier)
		dmuci_get_value_by_section_string(userclassidclassifier, "userclass", value);
	return 0;
}

static int set_DHCPv6ServerPool_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *userclassidclassifier;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			userclassidclassifier= get_dhcpv6_classifier("userclass", ((struct dhcpv6_args *)data)->interface);
			if (userclassidclassifier)
				dmuci_set_value_by_section(userclassidclassifier, "userclass", value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_SourceAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *macaddrclassifier;
	char *mac, **macarray, *res = NULL, *tmp = "";
	int i;
	size_t length;

	macaddrclassifier = get_dhcpv6_classifier("mac", ((struct dhcpv6_args *)data)->interface);
	if (macaddrclassifier == NULL) {
		*value= "";
		return 0;
	}
	dmuci_get_value_by_section_string(macaddrclassifier, "mac", &mac);
	macarray = strsplit(mac, ":", &length);
	res = (char*)dmcalloc(18, sizeof(char));
	tmp = res;
	for (i = 0; i < 6; i++) {
		if(strcmp(macarray[i], "*") == 0) {
			sprintf(tmp, "%s", "00");
		} else {
			sprintf(tmp, "%s", macarray[i]);
		}
		tmp += 2;

		if (i < 5) {
			sprintf(tmp, "%s", ":");
			tmp++;
		}
	}
	dmasprintf(value, "%s", res);
	return 0;
}

static int set_DHCPv6ServerPool_SourceAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPv6Address, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_SourceAddressMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)  //TODO: return wrong value
{
	struct uci_section *macaddrclassifier;
	char *mac, **macarray, *res = NULL, *tmp = "";
	int i;
	size_t length;

	macaddrclassifier = get_dhcpv6_classifier("mac", ((struct dhcpv6_args *)data)->interface);
	if (macaddrclassifier == NULL) {
		*value= "";
		return 0;
	}
	dmuci_get_value_by_section_string(macaddrclassifier, "mac", &mac);
	macarray = strsplit(mac, ":", &length);
	res = (char *)dmcalloc(18, sizeof(char));
	tmp = res;
	for (i = 0; i < 6; i++) {
		if (strcmp(macarray[i], "*") == 0) {
			sprintf(tmp, "%s", "00");
		} else {
			sprintf(tmp, "%s", "FF");
		}
		tmp += 2;
		if (i < 5) {
			sprintf(tmp, "%s", ":");
			tmp++;
		}
	}
	dmasprintf(value, "%s", res);
	return 0;
}

static int set_DHCPv6ServerPool_SourceAddressMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPv6Address, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPool_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res, *res1, *jobj, *dev_obj = NULL, *next_obj = NULL;
	char *device;
	int i = 0;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dhcpv6_args *)data)->dhcp_sec), String}}, 1, &res1);
	DM_ASSERT(res1, *value = "0");
	device = dmjson_get_value(res1, 1, "device");
	dmubus_call("dhcp", "ipv6leases", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	dev_obj = dmjson_get_obj(res, 1, "device");
	DM_ASSERT(dev_obj, *value = "0");
	next_obj = dmjson_get_obj(dev_obj, 1, device);
	DM_ASSERT(next_obj, *value = "0");
	while (1) {
		jobj = dmjson_select_obj_in_array_idx(next_obj, i, 1, "leases");
		if (jobj == NULL)
			break;
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv6ServerPool_OptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e;
	int i = 0;

	dmuci_get_value_by_section_list(((struct dhcpv6_args *)data)->dhcp_sec, "dhcp_option", &dhcp_options_list);
	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {
			i++;
		}
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv6ServerPoolClient_IPv6AddressNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *address_obj = NULL;
	int i = 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(((struct clientv6_args *)data)->client, i, 1, "ipv6-addr");
		if (address_obj == NULL)
			break;
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv6ServerPoolClient_IPv6PrefixNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *address_obj = NULL;
	int i= 0;

	while (1) {
		address_obj = dmjson_select_obj_in_array_idx(((struct clientv6_args *)data)->client, i, 1, "ipv6-prefix");
		if (address_obj == NULL)
			break;
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Address_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "address");
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Address_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "preferred-lifetime");
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Address_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "valid-lifetime");
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Prefix_Prefix(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "address");
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Prefix_PreferredLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "preferred-lifetime");
	return 0;
}

static int get_DHCPv6ServerPoolClientIPv6Prefix_ValidLifetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value(((struct clientv6_args *)data)->clientparam, 1, "valid-lifetime");
	return 0;
}

static int get_DHCPv6ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_option_list;
	struct uci_element *e;
	char **buf;
	size_t length;

	if(strcmp(((struct dhcpv6_client_option_args *)data)->option_tag, "0") == 0){
		*value= "0";
		return 0;
	}

	dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
	if (dhcp_option_list != NULL) {
		uci_foreach_element(dhcp_option_list, e) {
			buf = strsplit(e->name, ",", &length);
			if (strcmp(buf[0], ((struct dhcpv6_client_option_args *)data)->option_tag) == 0) {
				*value= "1";
				return 0;
			}
		}
	}

	*value= "0";
	return 0;
}

static int set_DHCPv6ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_list *dhcp_option_list;
	struct uci_element *e;
	char **buf, *opt_value;
	size_t length;
	bool test = false, b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);

			if (strcmp(((struct dhcpv6_client_option_args *)data)->option_tag, "0") == 0)
				return 0;

			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmasprintf(&opt_value, "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, ((struct dhcpv6_client_option_args *)data)->value);

			if (dhcp_option_list != NULL) {
				uci_foreach_element(dhcp_option_list, e) {
					buf = strsplit(e->name, ",", &length);
					if (strcmp(buf[0], ((struct dhcpv6_client_option_args *)data)->option_tag) == 0) {
						test = true;
						if (!b)
							dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", opt_value);
						break;
					}
				}
			}
			if (!test && b)
				dmuci_add_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", opt_value);
	}
	return 0;
}

static int get_DHCPv6ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcpv6_client_option_args *)data)->opt_sect, "bbf_dhcpv6_servpool_option_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;

}

static int set_DHCPv6ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcpv6_client_option_args *)data)->opt_sect, "bbf_dhcpv6_servpool_option_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcpv6_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv6ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *opttagvalue, **option, *oldopttagvalue;
	size_t length;
	struct uci_list *dhcp_option_list= NULL;
	struct uci_element *e;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);

			if (dhcp_option_list == NULL)
				return 0;

			uci_foreach_element(dhcp_option_list, e) {
				option = strsplit(e->name, ",", &length);
				if (strcmp(option[0], value)==0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmasprintf(&oldopttagvalue, "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, ((struct dhcpv6_client_option_args *)data)->value);
			dmasprintf(&opttagvalue, "%s,%s", value, ((struct dhcpv6_client_option_args *)data)->value);
			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", oldopttagvalue);
			dmuci_add_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", opttagvalue);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcpv6_client_option_args *)data)->opt_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv6ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value= dmstrdup(((struct dhcpv6_client_option_args *)data)->value);
	return 0;
}

static int set_DHCPv6ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *opttagvalue, **option, *oldopttagvalue;
	size_t length;
	struct uci_list *dhcp_option_list = NULL;
	struct uci_element *e;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"0","65535"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			if (dhcp_option_list == NULL)
				return 0;

			uci_foreach_element(dhcp_option_list, e) {
				option = strsplit(e->name, ",", &length);
				if (strcmp(option[0], value) == 0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmasprintf(&oldopttagvalue, "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, ((struct dhcpv6_client_option_args *)data)->value);
			dmasprintf(&opttagvalue, "%s,%s", ((struct dhcpv6_client_option_args *)data)->option_tag, value);
			dmuci_get_value_by_section_list(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmuci_del_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", oldopttagvalue);
			dmuci_add_list_value_by_section(((struct dhcpv6_client_option_args *)data)->client_sect, "dhcp_option", opttagvalue);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcpv6_client_option_args *)data)->opt_sect, "option_value", value);
			break;
	}
	return 0;
}

/* *** Device.DHCPv6. *** */
DMOBJ tDHCPv6Obj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Client", &DMWRITE, addObjDHCPv6Client, delObjDHCPv6Client, NULL, browseDHCPv6ClientInst, NULL, NULL, NULL, tDHCPv6ClientObj, tDHCPv6ClientParams, NULL, BBFDM_BOTH},
{"Server", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDHCPv6ServerObj, tDHCPv6ServerParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv6Params[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6_ClientNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Client.{i}. *** */
DMOBJ tDHCPv6ClientObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
//{"Server", &DMREAD, NULL, NULL, NULL, browseDHCPv6ClientServerInst, NULL, NULL, NULL, NULL, tDHCPv6ClientServerParams, NULL, BBFDM_BOTH},
//{"SentOption", &DMWRITE, addObjDHCPv6ClientSentOption, delObjDHCPv6ClientSentOption, NULL, browseDHCPv6ClientSentOptionInst, NULL, NULL, NULL, NULL, tDHCPv6ClientSentOptionParams, NULL, BBFDM_BOTH},
//{"ReceivedOption", &DMREAD, NULL, NULL, NULL, browseDHCPv6ClientReceivedOptionInst, NULL, NULL, NULL, NULL, tDHCPv6ClientReceivedOptionParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv6ClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6Client_Enable, set_DHCPv6Client_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6Client_Alias, set_DHCPv6Client_Alias, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv6Client_Interface, set_DHCPv6Client_Interface, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv6Client_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"DUID", &DMREAD, DMT_HEXBIN, get_DHCPv6Client_DUID, NULL, NULL, NULL, BBFDM_BOTH},
{"RequestAddresses", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RequestAddresses, set_DHCPv6Client_RequestAddresses, NULL, NULL, BBFDM_BOTH},
{"RequestPrefixes", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RequestPrefixes, set_DHCPv6Client_RequestPrefixes, NULL, NULL, BBFDM_BOTH},
//{"RapidCommit", &DMWRITE, DMT_BOOL, get_DHCPv6Client_RapidCommit, set_DHCPv6Client_RapidCommit, NULL, NULL, BBFDM_BOTH},
{"Renew", &DMWRITE, DMT_BOOL, get_DHCPv6Client_Renew, set_DHCPv6Client_Renew, NULL, NULL, BBFDM_BOTH},
//{"SuggestedT1", &DMWRITE, DMT_INT, get_DHCPv6Client_SuggestedT1, set_DHCPv6Client_SuggestedT1, NULL, NULL, BBFDM_BOTH},
//{"SuggestedT2", &DMWRITE, DMT_INT, get_DHCPv6Client_SuggestedT2, set_DHCPv6Client_SuggestedT2, NULL, NULL, BBFDM_BOTH},
//{"SupportedOptions", &DMREAD, DMT_STRING, get_DHCPv6Client_SupportedOptions, NULL, NULL, NULL, BBFDM_BOTH},
{"RequestedOptions", &DMWRITE, DMT_STRING, get_DHCPv6Client_RequestedOptions, set_DHCPv6Client_RequestedOptions, NULL, NULL, BBFDM_BOTH},
//{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_ServerNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"SentOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_SentOptionNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"ReceivedOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Client_ReceivedOptionNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Client.{i}.Server.{i}. *** */
DMLEAF tDHCPv6ClientServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"SourceAddress", &DMREAD, DMT_STRING, get_DHCPv6ClientServer_SourceAddress, NULL, NULL, NULL, BBFDM_BOTH},
//{"DUID", &DMREAD, DMT_HEXBIN, get_DHCPv6ClientServer_DUID, NULL, NULL, NULL, BBFDM_BOTH},
//{"InformationRefreshTime", &DMREAD, DMT_TIME, get_DHCPv6ClientServer_InformationRefreshTime, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Client.{i}.SentOption.{i}. *** */
DMLEAF tDHCPv6ClientSentOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6ClientSentOption_Enable, set_DHCPv6ClientSentOption_Enable, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ClientSentOption_Alias, set_DHCPv6ClientSentOption_Alias, NULL, NULL, BBFDM_BOTH},
//{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv6ClientSentOption_Tag, set_DHCPv6ClientSentOption_Tag, NULL, NULL, BBFDM_BOTH},
//{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv6ClientSentOption_Value, set_DHCPv6ClientSentOption_Value, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Client.{i}.ReceivedOption.{i}. *** */
DMLEAF tDHCPv6ClientReceivedOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Tag", &DMREAD, DMT_UNINT, get_DHCPv6ClientReceivedOption_Tag, NULL, NULL, NULL, BBFDM_BOTH},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv6ClientReceivedOption_Value, NULL, NULL, NULL, BBFDM_BOTH},
//{"Server", &DMREAD, DMT_STRING, get_DHCPv6ClientReceivedOption_Server, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server. *** */
DMOBJ tDHCPv6ServerObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Pool", &DMWRITE, addObjDHCPv6ServerPool, delObjDHCPv6ServerPool, NULL, browseDHCPv6ServerPoolInst, NULL, NULL, NULL, tDHCPv6ServerPoolObj, tDHCPv6ServerPoolParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv6ServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6Server_Enable, set_DHCPv6Server_Enable, NULL, NULL, BBFDM_BOTH},
{"PoolNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6Server_PoolNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}. *** */
DMOBJ tDHCPv6ServerPoolObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Client", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientInst, NULL, NULL, NULL, tDHCPv6ServerPoolClientObj, tDHCPv6ServerPoolClientParams, NULL, BBFDM_BOTH},
{"Option", &DMWRITE, addObjDHCPv6ServerPoolOption, delObjDHCPv6ServerPoolOption, NULL, browseDHCPv6ServerPoolOptionInst, NULL, NULL, NULL, NULL, tDHCPv6ServerPoolOptionParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv6ServerPoolParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_Enable, set_DHCPv6ServerPool_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_Alias, set_DHCPv6ServerPool_Alias, NULL, NULL, BBFDM_BOTH},
{"Order", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPool_Order, set_DHCPv6ServerPool_Order, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_Interface, set_DHCPv6ServerPool_Interface, NULL, NULL, BBFDM_BOTH},
//{"DUID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_DUID, set_DHCPv6ServerPool_DUID, NULL, NULL, BBFDM_BOTH},
//{"DUIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_DUIDExclude, set_DHCPv6ServerPool_DUIDExclude, NULL, NULL, BBFDM_BOTH},
{"VendorClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_VendorClassID, set_DHCPv6ServerPool_VendorClassID, NULL, NULL, BBFDM_BOTH},
//{"VendorClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_VendorClassIDExclude, set_DHCPv6ServerPool_VendorClassIDExclude, NULL, NULL, BBFDM_BOTH},
{"UserClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPool_UserClassID, set_DHCPv6ServerPool_UserClassID, NULL, NULL, BBFDM_BOTH},
//{"UserClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_UserClassIDExclude, set_DHCPv6ServerPool_UserClassIDExclude, NULL, NULL, BBFDM_BOTH},
{"SourceAddress", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_SourceAddress, set_DHCPv6ServerPool_SourceAddress, NULL, NULL, BBFDM_BOTH},
{"SourceAddressMask", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_SourceAddressMask, set_DHCPv6ServerPool_SourceAddressMask, NULL, NULL, BBFDM_BOTH},
//{"SourceAddressExclude", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_SourceAddressExclude, set_DHCPv6ServerPool_SourceAddressExclude, NULL, NULL, BBFDM_BOTH},
//{"IANAEnable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_IANAEnable, set_DHCPv6ServerPool_IANAEnable, NULL, NULL, BBFDM_BOTH},
//{"IANAManualPrefixes", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_IANAManualPrefixes, set_DHCPv6ServerPool_IANAManualPrefixes, NULL, NULL, BBFDM_BOTH},
//{"IANAPrefixes", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_IANAPrefixes, NULL, NULL, NULL, BBFDM_BOTH},
//{"IAPDEnable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPool_IAPDEnable, set_DHCPv6ServerPool_IAPDEnable, NULL, NULL, BBFDM_BOTH},
//{"IAPDManualPrefixes", &DMWRITE, DMT_STRING, get_DHCPv6ServerPool_IAPDManualPrefixes, set_DHCPv6ServerPool_IAPDManualPrefixes, NULL, NULL, BBFDM_BOTH},
//{"IAPDPrefixes", &DMREAD, DMT_STRING, get_DHCPv6ServerPool_IAPDPrefixes, NULL, NULL, NULL, BBFDM_BOTH},
//{"IAPDAddLength", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPool_IAPDAddLength, set_DHCPv6ServerPool_IAPDAddLength, NULL, NULL, BBFDM_BOTH},
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPool_ClientNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPool_OptionNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}. *** */
DMOBJ tDHCPv6ServerPoolClientObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"IPv6Address", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientIPv6AddressInst, NULL, NULL, NULL, NULL, tDHCPv6ServerPoolClientIPv6AddressParams, NULL, BBFDM_BOTH},
{"IPv6Prefix", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientIPv6PrefixInst, NULL, NULL, NULL, NULL, tDHCPv6ServerPoolClientIPv6PrefixParams, NULL, BBFDM_BOTH},
//{"Option", &DMREAD, NULL, NULL, NULL, browseDHCPv6ServerPoolClientOptionInst, NULL, NULL, NULL, NULL, tDHCPv6ServerPoolClientOptionParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv6ServerPoolClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolClient_Alias, set_DHCPv6ServerPoolClient_Alias, NULL, NULL, BBFDM_BOTH},
//{"SourceAddress", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClient_SourceAddress, NULL, NULL, NULL, BBFDM_BOTH},
//{"Active", &DMREAD, DMT_BOOL, get_DHCPv6ServerPoolClient_Active, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6AddressNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_IPv6AddressNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"IPv6PrefixNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_IPv6PrefixNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"OptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClient_OptionNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Address.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientIPv6AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"IPAddress", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClientIPv6Address_IPAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"PreferredLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Address_PreferredLifetime, NULL, NULL, NULL, BBFDM_BOTH},
{"ValidLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Address_ValidLifetime, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.IPv6Prefix.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientIPv6PrefixParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Prefix", &DMREAD, DMT_STRING, get_DHCPv6ServerPoolClientIPv6Prefix_Prefix, NULL, NULL, NULL, BBFDM_BOTH},
{"PreferredLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Prefix_PreferredLifetime, NULL, NULL, NULL, BBFDM_BOTH},
{"ValidLifetime", &DMREAD, DMT_TIME, get_DHCPv6ServerPoolClientIPv6Prefix_ValidLifetime, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Client.{i}.Option.{i}. *** */
DMLEAF tDHCPv6ServerPoolClientOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Tag", &DMREAD, DMT_UNINT, get_DHCPv6ServerPoolClientOption_Tag, NULL, NULL, NULL, BBFDM_BOTH},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv6ServerPoolClientOption_Value, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv6.Server.Pool.{i}.Option.{i}. *** */
DMLEAF tDHCPv6ServerPoolOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv6ServerPoolOption_Enable, set_DHCPv6ServerPoolOption_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolOption_Alias, set_DHCPv6ServerPoolOption_Alias, NULL, NULL, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv6ServerPoolOption_Tag, set_DHCPv6ServerPoolOption_Tag, NULL, NULL, BBFDM_BOTH},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv6ServerPoolOption_Value, set_DHCPv6ServerPoolOption_Value, NULL, NULL, BBFDM_BOTH},
//{"PassthroughClient", &DMWRITE, DMT_STRING, get_DHCPv6ServerPoolOption_PassthroughClient, set_DHCPv6ServerPoolOption_PassthroughClient, NULL, NULL, BBFDM_BOTH},
{0}
};
