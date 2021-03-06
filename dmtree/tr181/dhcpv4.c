/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Anis Ellouze <anis.ellouze@pivasoftware.com>
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#include "dmentry.h"
#include "dhcpv4.h"


struct dhcp_lease {
	uint64_t ts;
	char hwaddr[20];
	char ipaddr[16];
	struct list_head list;
};

struct dhcp_args {
	struct uci_section *dhcp_sec;
	char *interface;
	struct list_head leases;
	unsigned n_leases;
};

struct dhcp_static_args {
	struct uci_section *dhcpsection;
};

struct client_args {
	const struct dhcp_lease *lease;
};

struct dhcp_client_args {
	struct uci_section *dhcp_client_conf;
	struct uci_section *dhcp_client_dm;
	struct uci_section *macclassifier;
	struct uci_section *vendorclassidclassifier;
	struct uci_section *userclassclassifier;
	char *ip;
	char *mask;
};

struct dhcp_client_option_args {
	struct uci_section *opt_sect;
	struct uci_section *client_sect;
	char *option_tag;
	char *value;
};

/**************************************************************************
* LINKER
***************************************************************************/
static int get_dhcp_client_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	const struct client_args *args = data;

	*linker = (char *)args->lease->hwaddr;
	return 0;
}

/*************************************************************
* INIT
**************************************************************/
static inline void init_dhcp_args(struct dhcp_args *args, struct uci_section *s, char *interface)
{
	args->interface = interface;
	args->dhcp_sec = s;
	INIT_LIST_HEAD(&args->leases);
	args->n_leases = 0;
}

static inline void init_args_dhcp_host(struct dhcp_static_args *args, struct uci_section *s)
{
	args->dhcpsection = s;
}

static inline void init_dhcp_client_args(struct client_args *args, const struct dhcp_lease *lease)
{
	args->lease = lease;
}

/*************************************************************
* Other functions
**************************************************************/
struct uci_section* exist_other_section_same_order(struct uci_section *dmmap_sect, char * package, char* sect_type, char *order)
{
	struct uci_section *s;
	uci_path_foreach_option_eq(bbfdm, package, sect_type, "order", order, s) {
		if (strcmp(section_name(s), section_name(dmmap_sect)) != 0) {
			return s;
		}
	}
	return NULL;
}

int set_section_order(char *package, char *dmpackage, char* sect_type, struct uci_section *dmmap_sect, struct uci_section *conf, int set_force, char* order)
{
	char *v = NULL, *sect_name, *incrorder;
	struct uci_section *s, *dm;

	dmuci_get_value_by_section_string(dmmap_sect, "order", &v);
	if (strlen(v) > 0 && strcmp(v, order) == 0)
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

	if (set_force == 1 && strcmp(order, "1") == 0 && s != NULL) {
		dmuci_set_value_by_section(s, "force", "1");
	}

	if ((dm = exist_other_section_same_order(dmmap_sect, dmpackage, sect_type, order)) != NULL) {
		dmuci_get_value_by_section_string(dm, "section_name", &sect_name);
		get_config_section_of_dmmap_section(package, sect_type, sect_name, &s);
		dmasprintf(&incrorder, "%d", atoi(order)+1);
		if (s != NULL && strcmp(order, "1") == 0) {
			dmuci_set_value_by_section(s, "force", "");
		}
		set_section_order(package, dmpackage, sect_type, dm, s, set_force, incrorder);
	}
	return 0;

}

/*******************ADD-DEL OBJECT*********************/
static int add_dhcp_server(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *value, *v;
	char *instance;
	struct uci_section *s = NULL, *dmmap_dhcp = NULL;

	check_create_dmmap_package("dmmap_dhcp");
	instance = get_last_instance_bbfdm("dmmap_dhcp", "dhcp", "dhcp_instance");
	dmuci_add_section("dhcp", "dhcp", &s, &value);
	dmuci_set_value_by_section(s, "start", "100");
	dmuci_set_value_by_section(s, "leasetime", "12h");
	dmuci_set_value_by_section(s, "limit", "150");

	dmuci_add_section_bbfdm("dmmap_dhcp", "dhcp", &dmmap_dhcp, &v);
	dmuci_set_value_by_section(dmmap_dhcp, "section_name", section_name(s));
	*instancepara = update_instance_bbfdm(dmmap_dhcp, instance, "dhcp_instance");
	return 0;
}

static int delete_dhcp_server(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;

	switch (del_action) {
	case DEL_INST:
		if(is_section_unnamed(section_name(((struct dhcp_args *)data)->dhcp_sec))){
			LIST_HEAD(dup_list);
			delete_sections_save_next_sections("dmmap_dhcp", "dhcp", "dhcp_instance", section_name(((struct dhcp_args *)data)->dhcp_sec), atoi(instance), &dup_list);
			update_dmmap_sections(&dup_list, "dhcp_instance", "dmmap_dhcp", "dhcp");
			dmuci_delete_by_section_unnamed(((struct dhcp_args *)data)->dhcp_sec, NULL, NULL);
		} else {
			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(((struct dhcp_args *)data)->dhcp_sec, NULL, NULL);
		}

		break;
	case DEL_ALL:
		uci_foreach_sections("dhcp", "dhcp", s) {
			if (found != 0){
				get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(s), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			ss = s;
			found++;
		}
		if (ss != NULL){
			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(ss), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(ss, NULL, NULL);
		}
		break;
	}
	return 0;
}

static int add_dhcp_staticaddress(char *refparam, struct dmctx *ctx, void *data, char **instancepara)
{
	char *value, *v, *instance;
	struct uci_section *s = NULL, *dmmap_dhcp_host= NULL;

	check_create_dmmap_package("dmmap_dhcp");
	instance = get_last_instance_lev2_bbfdm("dhcp", "host", "dmmap_dhcp", "ldhcpinstance", "dhcp", ((struct dhcp_args *)data)->interface);
	dmuci_add_section("dhcp", "host", &s, &value);
	dmuci_set_value_by_section(s, "dhcp", ((struct dhcp_args *)data)->interface);


	dmuci_add_section_bbfdm("dmmap_dhcp", "host", &dmmap_dhcp_host, &v);
	dmuci_set_value_by_section(dmmap_dhcp_host, "section_name", section_name(s));
	*instancepara = update_instance_bbfdm(dmmap_dhcp_host, instance, "ldhcpinstance");
	return 0;
}

static int delete_dhcp_staticaddress(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	struct dhcp_static_args *dhcpargs = (struct dhcp_static_args *)data;
	
	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name(dhcpargs->dhcpsection))) {
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_dhcp", "host", "ldhcpinstance", section_name(dhcpargs->dhcpsection), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "ldhcpinstance", "dmmap_dhcp", "host");
				dmuci_delete_by_section_unnamed(dhcpargs->dhcpsection, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name(dhcpargs->dhcpsection), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(dhcpargs->dhcpsection, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_option_eq("dhcp", "host", "dhcp", ((struct dhcp_args *)data)->interface, s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4Client(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s, *dmmap_sect;
	char *wan_eth, *value, *wanname, *instancepara, *v;

	check_create_dmmap_package("dmmap_dhcp_client");
	instancepara = get_last_instance_bbfdm("dmmap_dhcp_client", "interface", "bbf_dhcpv4client_instance");
	dmuci_get_option_value_string("ports", "WAN", "ifname", &wan_eth);
	dmasprintf(&wanname, "%s.1", wan_eth);
	dmuci_add_section("network", "interface", &s, &value);
	dmuci_set_value_by_section(s, "proto", "dhcp");
	dmuci_set_value_by_section(s, "ifname", wanname);
	dmuci_set_value_by_section(s, "type", "anywan");
	dmuci_add_section_bbfdm("dmmap_dhcp_client", "interface", &dmmap_sect, &v);
	dmuci_set_value_by_section(dmmap_sect, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_sect, instancepara, "bbf_dhcpv4client_instance");
	return 0;
}

static int delObjDHCPv4Client(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)data;
	struct uci_section *s, *dmmap_section, *stmp;
	json_object *res, *jobj;

	char *v;
	char *type, *ipv4addr = "", *ipv6addr = "", *proto, *mask4;

	switch (del_action) {
		case DEL_INST:
			if (dhcp_client_args->dhcp_client_conf != NULL) {
				dmuci_set_value_by_section(dhcp_client_args->dhcp_client_conf, "proto", "static");
				if (strlen(dhcp_client_args->ip) == 0) {
					dmasprintf(&ipv4addr, "%s.%s.%s.%s", instance, instance, instance, instance);
					dmasprintf(&mask4, "%s", "255.255.255.0");
				} else {
					dmasprintf(&ipv4addr, "%s", dhcp_client_args->ip);
					dmasprintf(&mask4, "%s", dhcp_client_args->mask);
				}
				dmuci_set_value_by_section(dhcp_client_args->dhcp_client_conf, "ipaddr", ipv4addr);
				dmuci_set_value_by_section(dhcp_client_args->dhcp_client_conf, "netmask", mask4);
			}
			dmuci_delete_by_section_unnamed_bbfdm(dhcp_client_args->dhcp_client_dm, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("network", "interface", s) {
				dmuci_get_value_by_section_string(s, "type", &type);
				if (strcmp(type, "alias") == 0 || strcmp(section_name(s), "loopback") == 0)
					continue;
				dmuci_get_value_by_section_string(s, "ipaddr", &ipv4addr);
				dmuci_get_value_by_section_string(s, "netmask", &mask4);
				if (ipv4addr[0] == '\0') {
					dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
					if (res) {
						jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
						ipv4addr = dmjson_get_value(jobj, 1, "address");
						mask4= dmjson_get_value(jobj, 1, "mask");
					}
				}
				dmuci_get_value_by_section_string(s, "ip6addr", &ipv6addr);
				if (ipv6addr[0] == '\0') {
					dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(s), String}}, 1, &res);
					if (res) {
						jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
						ipv6addr = dmjson_get_value(jobj, 1, "address");
					}
				}
				dmuci_get_value_by_section_string(s, "proto", &proto);
				if (ipv4addr[0] == '\0' && ipv6addr[0] == '\0' && strcmp(proto, "dhcp") != 0 && strcmp(proto, "dhcpv6") != 0 && strcmp(type, "bridge") != 0)
					continue;

				dmuci_set_value_by_section(s, "proto", "static");

				get_dmmap_section_of_config_section("dmmap_dhcp_client", "interface", section_name(s), &dmmap_section);
				if (strlen(ipv4addr) == 0) {
					if(dmmap_section != NULL)
						dmuci_get_value_by_section_string(dmmap_section, "bbf_dhcpv4client_instance", &v);
					else
						dmasprintf(&v, "%d", 0);

					dmasprintf(&ipv4addr, "%s.%s.%s.%s", v, v, v, v);
					dmasprintf(&mask4, "%s", "255.255.255.0");
				}
				dmuci_set_value_by_section(s, "ipaddr", ipv4addr);
				dmuci_set_value_by_section(s, "netmask", mask4);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
			}
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_client", "interface", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ClientSentOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)data;
	struct uci_section *dmmap_sect;
	char *value, *instancepara;

	check_create_dmmap_package("dmmap_dhcp_client");
	instancepara = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_dhcp_client", "send_option", "bbf_dhcpv4_sentopt_instance", "section_name", section_name(dhcp_client_args->dhcp_client_conf));
	dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dmmap_sect, &value);
	if(dhcp_client_args->dhcp_client_conf != NULL)
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(dhcp_client_args->dhcp_client_conf));
	DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_tag", "0");
	*instance = update_instance_bbfdm(dmmap_sect, instancepara, "bbf_dhcpv4_sentopt_instance");
	return 0;
}

static int delObjDHCPv4ClientSentOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s, *stmp;
	char *list= NULL, *opt_value= NULL;

	switch (del_action) {
		case DEL_INST:
			if(strcmp(((struct dhcp_client_option_args*) data)->option_tag, "0") != 0)
			{
				dmasprintf(&opt_value, "%s:%s", ((struct dhcp_client_option_args*) data)->option_tag, ((struct dhcp_client_option_args*) data)->value);
				dmuci_get_value_by_section_string(((struct dhcp_client_option_args*) data)->client_sect, "sendopts", &list);
				if(list != NULL){
					remove_elt_from_str_list(&list, opt_value);
					dmuci_set_value_by_section(((struct dhcp_client_option_args*) data)->client_sect, "sendopts", list);
				}
			}
			dmuci_delete_by_section_unnamed_bbfdm(((struct dhcp_client_option_args*) data)->opt_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dhcp_client_args*) data)->dhcp_client_conf, "sendopts", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_client", "send_option", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ClientReqOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)data;
	struct uci_section *dmmap_sect;
	char *value, *instancepara;

	check_create_dmmap_package("dmmap_dhcp_client");
	instancepara = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_dhcp_client", "req_option", "bbf_dhcpv4_sentopt_instance", "section_name", section_name(dhcp_client_args->dhcp_client_conf));
	dmuci_add_section_bbfdm("dmmap_dhcp_client", "req_option", &dmmap_sect, &value);
	if(dhcp_client_args->dhcp_client_conf != NULL)
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(dhcp_client_args->dhcp_client_conf));
	DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_tag", "0");
	*instance = update_instance_bbfdm(dmmap_sect, instancepara, "bbf_dhcpv4_sentopt_instance");
	return 0;
}

static int delObjDHCPv4ClientReqOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s, *stmp;
	char *list = NULL;

	switch (del_action) {
		case DEL_INST:
			if (strcmp(((struct dhcp_client_option_args*) data)->option_tag, "0") != 0) {
				dmuci_get_value_by_section_string(((struct dhcp_client_option_args*) data)->client_sect, "reqopts", &list);
				if (list != NULL) {
					remove_elt_from_str_list(&list, ((struct dhcp_client_option_args*) data)->option_tag);
					dmuci_set_value_by_section(((struct dhcp_client_option_args*) data)->client_sect, "reqopts", list);
				}
			}
			dmuci_delete_by_section_unnamed_bbfdm(((struct dhcp_client_option_args*) data)->opt_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dhcp_client_args*) data)->dhcp_client_conf, "reqopts", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp_client", "req_option", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct dhcp_args *dhcp_arg = (struct dhcp_args*)data;
	struct uci_section *dmmap_sect;
	char *value, *instancepara;

	check_create_dmmap_package("dmmap_dhcp");
	instancepara = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_dhcp", "servpool_option", "bbf_dhcpv4_servpool_option_instance", "section_name", section_name(dhcp_arg->dhcp_sec));
	dmuci_add_section_bbfdm("dmmap_dhcp", "servpool_option", &dmmap_sect, &value);
	if(dhcp_arg->dhcp_sec != NULL)
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(dhcp_arg->dhcp_sec));
	DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_tag", "0");
	*instance = update_instance_bbfdm(dmmap_sect, instancepara, "bbf_dhcpv4_servpool_option_instance");
	return 0;
}

static int delObjDHCPv4ServerPoolOption(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s, *stmp;
	char *opt_value = NULL;
	struct uci_list *dhcp_options_list = NULL;

	switch (del_action) {
		case DEL_INST:
			if (strcmp(((struct dhcp_client_option_args*) data)->option_tag, "0") != 0) {
				dmasprintf(&opt_value, "%s,%s", ((struct dhcp_client_option_args*) data)->option_tag, ((struct dhcp_client_option_args*) data)->value);
				dmuci_get_value_by_section_list(((struct dhcp_client_option_args*) data)->client_sect, "dhcp_option", &dhcp_options_list);
				if (dhcp_options_list != NULL) {
					dmuci_del_list_value_by_section(((struct dhcp_client_option_args*) data)->client_sect, "dhcp_option", opt_value);
				}
			}
			dmuci_delete_by_section_unnamed_bbfdm(((struct dhcp_client_option_args*) data)->opt_sect, NULL, NULL);
			break;
		case DEL_ALL:
			dmuci_set_value_by_section(((struct dhcp_args*) data)->dhcp_sec, "dhcp_option", "");
			uci_path_foreach_sections_safe(bbfdm, "dmmap_dhcp", "servpool_option", stmp, s) {
				dmuci_delete_by_section_unnamed_bbfdm(s, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjDHCPv4RelayForwarding(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s, *dmmap_sect;
	char *value, *instancepara, *v;

	check_create_dmmap_package("dmmap_dhcp_relay");
	instancepara = get_last_instance_bbfdm("dmmap_dhcp_relay", "interface", "bbf_dhcpv4relay_instance");
	dmuci_add_section("network", "interface", &s, &value);
	dmuci_set_value_by_section(s, "proto", "relay");
	dmuci_add_section_bbfdm("dmmap_dhcp_relay", "interface", &dmmap_sect, &v);
	dmuci_set_value_by_section(dmmap_sect, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap_sect, instancepara, "bbf_dhcpv4relay_instance");
	return 0;
}

static int delObjDHCPv4RelayForwarding(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dhcp_client_args *dhcp_relay_args = (struct dhcp_client_args*)data;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	char *proto = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name(dhcp_relay_args->dhcp_client_conf))) {
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_dhcp_relay", "interface", "bbf_dhcpv4relay_instance", section_name(dhcp_relay_args->dhcp_client_conf), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "bbf_dhcpv4relay_instance", "dmmap_dhcp_relay", "interface");
				dmuci_delete_by_section_unnamed(dhcp_relay_args->dhcp_client_conf, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_dhcp_relay", "interface", section_name(dhcp_relay_args->dhcp_client_conf), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(dhcp_relay_args->dhcp_client_conf, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("network", "interface", s) {
				if (found != 0) {
					dmuci_get_value_by_section_string(ss, "proto", &proto);
					if (strcmp(proto, "relay") == 0) {
						get_dmmap_section_of_config_section("dmmap_dhcp_relay", "interface", section_name(ss), &dmmap_section);
						if (dmmap_section != NULL)
							dmuci_delete_by_section(dmmap_section, NULL, NULL);
						dmuci_delete_by_section(ss, NULL, NULL);
					}
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				dmuci_get_value_by_section_string(ss, "proto", &proto);
				if (strcmp(proto, "relay") == 0) {
					get_dmmap_section_of_config_section("dmmap_dhcp_relay", "interface", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
			}
			break;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
/*#Device.DHCPv4.Server.Pool.{i}.Alias!UCI:dmmap_dhcp/dhcp,@i-1/dhcp_alias*/
static int get_server_pool_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_sect);
	dmuci_get_value_by_section_string(dmmap_sect, "dhcp_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_server_pool_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_sect);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "dhcp_alias", value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.DNSServers!UBUS:network.interface/status/interface,@Name/dns-server*/
static int get_dns_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
	if (res) {
		*value = dmjson_get_value_array_all(res, DELIMITOR, 1, "dns-server");
	} else
		*value = "";
	if ((*value)[0] == '\0') {
		dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "dns", value);
		*value = dmstrdup(*value); // MEM WILL BE FREED IN DMMEMCLEAN
		char *p = *value;
		while (*p) {
			if (*p == ' ' && p != *value && *(p-1) != ',')
				*p++ = ',';
			else
				p++;
		}
	}
	if ((*value)[0] == '\0') {
		dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", value);
	}
	return 0;
}

static int set_dns_server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dup, *p;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 4, -1, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dup = dmstrdup(value);
			p = dup;
			while (*p) {
				if (*p == ',')
					*p++ = ' ';
				else
					p++;
			}
			dmuci_set_value("network", ((struct dhcp_args *)data)->interface, "dns", dup);
			dmfree(dup);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.Status!UCI:dhcp/interface,@i-1/ignore*/
static int get_dhcp_status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *v = NULL;
	uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
		dmuci_get_value_by_section_string(s, "ignore", &v);
		*value = (v && *v == '1') ? "Disabled" : "Enabled";
		return 0;
	}
	*value = "Error_Misconfigured";
	return 0;
}

static int get_dhcp_sever_pool_order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_sect = NULL;

	get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_sect);
	if (dmmap_sect)
		dmuci_get_value_by_section_string(dmmap_sect, "order", value);
	return 0;
}

static int set_dhcp_sever_pool_order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_sect = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcp", "dhcp", section_name(((struct dhcp_args *)data)->dhcp_sec), &dmmap_sect);
			if (dmmap_sect)
				set_section_order("dhcp", "dmmap_dhcp", "dhcp", dmmap_sect, ((struct dhcp_args *)data)->dhcp_sec, 1, value);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddressNumberOfEntries!UCI:dhcp/host/*/
static int get_static_address_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int i = 0;

	uci_foreach_sections("dhcp", "host", s) {
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_option_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e;
	int i= 0;

	dmuci_get_value_by_section_list(((struct dhcp_args *)data)->dhcp_sec, "dhcp_option", &dhcp_options_list);
	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {
			i++;
		}
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_clients_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct dhcp_args *dhcp = data;

	dmasprintf(value, "%u", dhcp->n_leases);
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.Enable!UCI:dhcp/interface,@i-1/ignore*/
static int get_dhcp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;

	uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
		dmuci_get_value_by_section_string(s, "ignore", value);
		*value = ((*value)[0] == '1') ? "0" : "1";
		return 0;
	}
	*value = "0";
	return 0;
}

static int set_dhcp_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
			uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
				dmuci_set_value_by_section(s, "ignore", b ? "0" : "1");
				break;
			}
			return 0;
	}
	return 0;
}

enum enum_lanip_interval_address {
	LANIP_INTERVAL_START,
	LANIP_INTERVAL_END
};

static int get_dhcp_interval_address(struct dmctx *ctx, void *data, char *instance, char **value, int option)
{
	json_object *res, *jobj;
	char bufipstart[16], bufipend[16], *ipaddr = "" , *mask = "", *start , *limit;
	struct uci_section *s = NULL;

	*value = "";
	uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
		dmuci_get_value_by_section_string(s, "start", &start);
		if (option == LANIP_INTERVAL_END)
			dmuci_get_value_by_section_string(s, "limit", &limit);
		break;
	}
	if (s == NULL) {
		return 0;
	}
	dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", &ipaddr);
	if (ipaddr[0] == '\0') {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
		if (res) {
			jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
			ipaddr = dmjson_get_value(jobj, 1, "address");			
		}
	}
	if (ipaddr[0] == '\0') {
		return 0;
	}
	dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "netmask", &mask);
	if (mask[0] == '\0') {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
		if (res) {
			jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
			mask = dmjson_get_value(jobj, 1, "mask");
			if (mask[0] == '\0') {
				return 0;
			}
			mask = cidr2netmask(atoi(mask));
		}
	}
	if (mask[0] == '\0') {
		mask = "255.255.255.0";
	}
	if (option == LANIP_INTERVAL_START) {
		ipcalc(ipaddr, mask, start, NULL, bufipstart, NULL);
		*value = dmstrdup(bufipstart); // MEM WILL BE FREED IN DMMEMCLEAN
	} else {
		ipcalc(ipaddr, mask, start, limit, bufipstart, bufipend);
		*value = dmstrdup(bufipend); // MEM WILL BE FREED IN DMMEMCLEAN
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.MinAddress!UCI:dhcp/interface,@i-1/start*/
static int get_dhcp_interval_address_min(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_dhcp_interval_address(ctx, data, instance, value, LANIP_INTERVAL_START);
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.MaxAddress!UCI:dhcp/interface,@i-1/limit*/
static int get_dhcp_interval_address_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	get_dhcp_interval_address(ctx, data, instance, value, LANIP_INTERVAL_END);
	return 0;
}

static int set_dhcp_address_min(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res, *jobj;
	char *ipaddr = "", *mask = "", buf[16];
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", &ipaddr);
			if (ipaddr[0] == '\0') {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
				if (res) {
					jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
					ipaddr = dmjson_get_value(jobj, 1, "address");					
				}
			}
			if (ipaddr[0] == '\0')
				return 0;

			dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "netmask", &mask);
			if (mask[0] == '\0') {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
				if (res) {
					jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
					mask = dmjson_get_value(jobj, 1, "mask");
					if (mask[0] == '\0')
						return 0;
					mask = cidr2netmask(atoi(mask));
				}
			}
			if (mask[0] == '\0')
				mask = "255.255.255.0";

			ipcalc_rev_start(ipaddr, mask, value, buf);
			uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
				dmuci_set_value_by_section(s, "start", buf);
				break;
			}

			return 0;
	}
	return 0;
}

static int set_dhcp_address_max(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res, *jobj;
	char *ipaddr = "", *mask = "", *start, buf[16];
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
				dmuci_get_value_by_section_string(s, "start", &start);
				break;
			}
			if (!s) return 0;

			dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", &ipaddr);
			if (ipaddr[0] == '\0') {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
				if (res) {
					jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
					ipaddr = dmjson_get_value(jobj, 1, "address");									}
			}
			if (ipaddr[0] == '\0')
				return 0;

			dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "netmask", &mask);
			if (mask[0] == '\0') {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
				if (res) {
					jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
					mask = dmjson_get_value(jobj, 1, "mask");
					if (mask[0] == '\0')
						return 0;
					mask = cidr2netmask(atoi(mask));
				}
			}
			if (mask[0] == '\0')
				mask = "255.255.255.0";

			ipcalc_rev_end(ipaddr, mask, start, value, buf);
			dmuci_set_value_by_section(s, "limit", buf);
			return 0;
	}
	return 0;
}


static int get_dhcp_reserved_addresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char val[512] = {0}, *p;
	struct uci_section *s = NULL;
	char *min, *max, *ip;
	unsigned int n_min, n_max, n_ip;
	*value = "";

	get_dhcp_interval_address(ctx, data, instance, &min, LANIP_INTERVAL_START);
	get_dhcp_interval_address(ctx, data, instance, &max, LANIP_INTERVAL_END);
	if (min[0] == '\0' || max[0] == '\0')
		return 0;
	n_min = inet_network(min);
	n_max = inet_network(max);
	p = val;
	uci_foreach_sections("dhcp", "host", s) {
		dmuci_get_value_by_section_string(s, "ip", &ip);
		if (ip[0] == '\0')
			continue;
		n_ip = inet_network(ip);
		if (n_ip >= n_min && n_ip <= n_max) {
			if (val[0] != '\0')
				dmstrappendchr(p, ',');
			dmstrappendstr(p, ip);
		}
	}
	dmstrappendend(p);
	*value = dmstrdup(val); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int set_dhcp_reserved_addresses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dhcp_section = NULL;
	char *min, *max, *val, *local_value, *pch, *spch = NULL;
	unsigned int n_min, n_max, n_ip, ipexist= 0;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 32, -1, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dhcp_interval_address(ctx, data, instance, &min, LANIP_INTERVAL_START);
			get_dhcp_interval_address(ctx, data, instance, &max, LANIP_INTERVAL_END);
			n_min = inet_network(min);
			n_max = inet_network(max);
			local_value = dmstrdup(value);

			for (pch = strtok_r(local_value, ",", &spch);
				pch != NULL;
				pch = strtok_r(NULL, ",", &spch)) {
				uci_foreach_option_eq("dhcp", "host", "ip", pch, s) {
					ipexist = 1;
				}
				if(ipexist)
					continue;
				n_ip = inet_network(pch);

				if (n_ip < n_min || n_ip > n_max)
					continue;

				dmuci_add_section_and_rename("dhcp", "host", &dhcp_section, &val);
				dmuci_set_value_by_section(dhcp_section, "dhcp", ((struct dhcp_args *)data)->interface);
				dmuci_set_value_by_section(dhcp_section, "ip", pch);
			}
			dmfree(local_value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.SubnetMask!UCI:dhcp/interface,@i-1/netmask*/
static int get_dhcp_subnetmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mask;
	json_object *res, *jobj;
	struct uci_section *s = NULL;
	char *val;
	*value = "";

	uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
		dmuci_get_value_by_section_string(s, "netmask", value);
		break;
	}
	if (s == NULL || (*value)[0] == '\0')
	dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "netmask", value);
	if ((*value)[0] == '\0') {
		dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", ((struct dhcp_args *)data)->interface, String}}, 1, &res);
		DM_ASSERT(res, *value = "");
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		mask = dmjson_get_value(jobj, 1, "mask");
		int i_mask = atoi(mask);
		val = cidr2netmask(i_mask);
		*value = dmstrdup(val);// MEM WILL BE FREED IN DMMEMCLEAN
	}
	return 0;
}

static int set_dhcp_subnetmask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
				dmuci_set_value_by_section(s, "netmask", value);
				return 0;
			}
			return 0;
	}
	return 0;
}

static int get_dhcp_iprouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "gateway", value);
	if ((*value)[0] == '\0') {
		dmuci_get_option_value_string("network", ((struct dhcp_args *)data)->interface, "ipaddr", value);
	}
	return 0;
}

static int set_dhcp_iprouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, 4, -1, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value("network", ((struct dhcp_args *)data)->interface, "gateway", value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.LeaseTime!UCI:dhcp/interface,@i-1/leasetime*/
static int get_dhcp_leasetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int mtime = 0;
	char *ltime = "", *pch, *spch = NULL, *ltime_ini, *tmp, *tmp_ini;
	struct uci_section *s = NULL;

	uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
		dmuci_get_value_by_section_string(s, "leasetime", &ltime);
		break;
	}
	if (ltime[0] == '\0') {
		*value = "-1";
		return 0;
	}
	ltime = dmstrdup(ltime);
	ltime_ini = dmstrdup(ltime);
	tmp = ltime;
	tmp_ini = ltime_ini;
	pch = strtok_r(ltime, "h", &spch);
	if (strcmp(pch, ltime_ini) != 0) {
		mtime = 3600 * atoi(pch);
		if(spch[0] != '\0') {
			ltime += strlen(pch)+1;
			ltime_ini += strlen(pch)+1;
			pch = strtok_r(ltime, "m", &spch);
			if (strcmp(pch, ltime_ini) != 0) {
				mtime += 60 * atoi(pch);
				if(spch[0] !='\0') {
					ltime += strlen(pch)+1;
					ltime_ini += strlen(pch)+1;
					pch = strtok_r(ltime, "s", &spch);
					if (strcmp(pch, ltime_ini) != 0) {
						mtime += atoi(pch);
					}
				}
			} else {
				pch = strtok_r(ltime, "s", &spch);
				if (strcmp(pch, ltime_ini) != 0)
					mtime +=  atoi(pch);
			}
		}
	} else {
		pch = strtok_r(ltime, "m", &spch);
		if (strcmp(pch, ltime_ini) != 0) {
			mtime += 60 * atoi(pch);
			if(spch[0] !='\0') {
				ltime += strlen(pch)+1;
				ltime_ini += strlen(pch)+1;
				pch = strtok_r(ltime, "s", &spch);
				if (strcmp(pch, ltime_ini) != 0) {
					mtime += atoi(pch);
				}
			}
		} else {
			pch = strtok_r(ltime, "s", &spch);
			if (strcmp(pch, ltime_ini) != 0)
				mtime +=  atoi(pch);
		}
	}
	dmfree(tmp);
	dmfree(tmp_ini);

	dmasprintf(value, "%d", mtime); // MEM WILL BE FREED IN DMMEMCLEAN
	return 0;
}

static int set_dhcp_leasetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char buf[32];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
				int val = atoi(value);
				snprintf(buf, sizeof(buf), "%ds", val);
				dmuci_set_value_by_section(s, "leasetime",  buf);
				break;
			}
			return 0;
	}
	return 0;
}

static int get_dhcp_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;
	linker = dmstrdup(((struct dhcp_args *)data)->interface);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value); // MEM WILL BE FREED IN DMMEMCLEAN
	if (*value == NULL)
		*value = "";
	dmfree(linker);
	return 0;
}

static int set_dhcp_interface_linker_parameter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker) {
				dmuci_set_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "interface", linker);
				dmfree(linker);
			}
			return 0;
	}
	return 0;
}

static int get_dhcp_domainname(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *str;
	struct uci_list *val;
	struct uci_element *e = NULL;
	struct uci_section *s = NULL;
	*value = "";

	uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
		dmuci_get_value_by_section_list(s, "dhcp_option", &val);
		if (val) {
			uci_foreach_element(val, e) {
				if ((str = strstr(e->name, "15,"))) {
					*value = dmstrdup(str + sizeof("15,") - 1); //MEM WILL BE FREED IN DMMEMCLEAN
					return 0;
				}
			}
		}
	}
	return 0;
}

static int set_dhcp_domainname(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_list *val;
	struct uci_section *s = NULL;
	struct uci_element *e = NULL, *tmp;
	char *option = "dhcp_option", buf[64];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			uci_foreach_option_eq("dhcp", "dhcp", "interface", ((struct dhcp_args *)data)->interface, s) {
				dmuci_get_value_by_section_list(s, option, &val);
				if (val) {
					uci_foreach_element_safe(val, e, tmp) {
						if (strstr(tmp->name, "15,")) {
							dmuci_del_list_value_by_section(s, "dhcp_option", tmp->name);
						}
					}
				}
				break;
			}
			goto end;
	}
end:
	snprintf(buf, sizeof(buf), "15,%s", value);
	dmuci_add_list_value_by_section(((struct dhcp_args *)data)->dhcp_sec, "dhcp_option", buf);
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Alias!UCI:dmmap_dhcp/host,@i-1/ldhcpalias*/
static int get_dhcp_static_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;
	get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name(((struct dhcp_static_args *)data)->dhcpsection), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "ldhcpalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_dhcp_static_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_dhcp", "host", section_name(((struct dhcp_static_args *)data)->dhcpsection), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "ldhcpalias", value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Chaddr!UCI:dhcp/host,@i-1/mac*/
static int get_dhcp_staticaddress_chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *chaddr;
	
	dmuci_get_value_by_section_string(((struct dhcp_static_args *)data)->dhcpsection, "mac", &chaddr);
	if (strcmp(chaddr, DHCPSTATICADDRESS_DISABLED_CHADDR) == 0)
		dmuci_get_value_by_section_string(((struct dhcp_static_args *)data)->dhcpsection, "mac_orig", value);
	else 
		*value = chaddr;
	return 0;
}

static int set_dhcp_staticaddress_chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{	
	char *chaddr;
		
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dhcp_static_args *)data)->dhcpsection, "mac", &chaddr);
			if (strcmp(chaddr, DHCPSTATICADDRESS_DISABLED_CHADDR) == 0)
				dmuci_set_value_by_section(((struct dhcp_static_args *)data)->dhcpsection, "mac_orig", value);
			else
				dmuci_set_value_by_section(((struct dhcp_static_args *)data)->dhcpsection, "mac", value);
			return 0;
	}
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.Yiaddr!UCI:dhcp/host,@i-1/ip*/
static int get_dhcp_staticaddress_yiaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_static_args *)data)->dhcpsection, "ip", value);
	return 0;
}

static int set_dhcp_staticaddress_yiaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;
			return 0;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcp_static_args *)data)->dhcpsection, "ip", value);
			return 0;
	}
	return 0;
}

static int get_dhcp_client_chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct client_args *args = data;

	*value = (char *)args->lease->hwaddr;
	return 0;
}

static int get_dhcp_client_active(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int get_dhcp_client_ipv4address_leasetime(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct client_args *args = data;

	return dm_time_format(args->lease->ts, value);
}

static int get_dhcp_client_ipv4address_ip_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	const struct client_args *args = data;

	*value = (char *)args->lease->ipaddr;
	return 0;
}

static int get_DHCPv4_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s, *dmmap_sect;
	int nbre_confs = 0, nbre_dmmaps = 0;

	uci_foreach_option_eq("network", "interface", "proto", "dhcp", s) {
		nbre_confs++;
	}
	uci_path_foreach_sections(bbfdm, "dmmap_dhcp_client", "interface", dmmap_sect) {
		nbre_dmmaps++;
	}
	if (nbre_dmmaps == 0 || nbre_dmmaps < nbre_confs)
		dmasprintf(value, "%d", nbre_confs);
	else
		dmasprintf(value, "%d", nbre_dmmaps);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;

	if(((struct dhcp_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "0";
		return 0;
	}

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", &v);

	if (v == NULL || strlen(v) == 0 || strcmp(v, "1") != 0)
		*value = "1";
	else
		*value = "0";

	return 0;
}

static int set_DHCPv4Client_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", b ? "0" : "1");
			return 0;
	}
	return 0;
}

static int get_DHCPv4Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_dm, "bbf_dhcpv4client_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4Client_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->dhcp_client_dm, "bbf_dhcpv4client_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct dhcp_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "";
		return 0;
	}
	char *linker = dmstrdup(section_name(((struct dhcp_client_args *)data)->dhcp_client_conf));
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

static int set_DHCPv4Client_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *linker = NULL, *newvalue = NULL, *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;

			if(strlen(value) == 0 || strcmp(value, "") == 0)
				return FAULT_9007;

			if (value[strlen(value)-1]!='.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else
				adm_entry_get_linker_value(ctx, value, &linker);
			uci_path_foreach_sections(bbfdm, "dmmap_dhcp_client", "interface", s) {
				dmuci_get_value_by_section_string(s, "section_name", &v);
				if(strcmp(v, linker) == 0)
					return FAULT_9007;
			}
			uci_foreach_sections("network", "interface", s) {
				if(strcmp(section_name(s), linker) == 0){
					dmuci_get_value_by_section_string(s, "proto", &v);
					if(strcmp(v, "dhcp") != 0)
						return FAULT_9007;
				}
			}
			break;
		case VALUESET:
			if (value[strlen(value)-1]!='.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else
				adm_entry_get_linker_value(ctx, value, &linker);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_args *)data)->dhcp_client_dm, "section_name", linker);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Client.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4Client_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;
	if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "Error_Misconfigured";
		return 0;
	}

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", &v);
	if (v == NULL || strlen(v) == 0 || strcmp(v, "1") != 0)
		*value = "Enabled";
	else
		*value = "Disabled";

	return 0;
}

/*#Device.DHCPv4.Client.{i}.DHCPStatus!UBUS:network.interface/status/interface,@Name/ipv4-address[@i-1].address*/
static int get_DHCPv4Client_DHCPStatus(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ipaddr = "";
	json_object *res, *jobj;

	if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL)
		return 0;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dhcp_client_args *)data)->dhcp_client_conf), String}}, 1, &res);
	if (res) {
		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		ipaddr = dmjson_get_value(jobj, 1, "address");
	}

	if (ipaddr[0] == '\0')
		*value = "Requesting";
	else
		*value = "Bound";

	return 0;
}

static int get_DHCPv4Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "false";
	return 0;
}

static int set_DHCPv4Client_Renew(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	json_object *res;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL && strcasecmp(value, "true") != 0)
				return 0;

			dmubus_call("network.interface", "renew", UBUS_ARGS{{"interface", section_name(((struct dhcp_client_args *)data)->dhcp_client_conf), String}}, 1, &res);
			break;
	}
	return 0;
}

static int get_DHCPv4Client_IPAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_args *)data)->ip);
	return 0;
}

static int get_DHCPv4Client_SubnetMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_args *)data)->mask);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.IPRouters!UBUS:network.interface/status/interface,@Name/route[@i-1].target*/
static int get_DHCPv4Client_IPRouters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v, buf[256] = "";
	json_object *jobj = NULL, *res;
	int i = 0;

	if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL)
		return 0;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dhcp_client_args *)data)->dhcp_client_conf), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	while (1) {
		jobj = dmjson_select_obj_in_array_idx(res, i, 1, "route");
		i++;

		if (jobj == NULL)
			break;

		v = dmjson_get_value(jobj, 1, "target");
		if (*v == '\0')
			continue;
		if (strcmp(v, "0.0.0.0") == 0)
			continue;
		if (buf[0] != '\0') {
			strcat(buf, ",");
		} else
			strcat(buf, v);
	}
	*value = dmstrdup(buf);

	return 0;
}

/*#Device.DHCPv4.Client.{i}.DNSServers!UBUS:network.interface/status/interface,@Name/dns-server*/
static int get_DHCPv4Client_DNSServers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL)
		return 0;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dhcp_client_args *)data)->dhcp_client_conf), String}}, 1, &res);
	DM_ASSERT(res, *value = "");
	*value = dmjson_get_value_array_all(res, DELIMITOR, 1, "dns-server");
	return 0;
}

/*#Device.DHCPv4.Client.{i}.LeaseTimeRemaining!UBUS:network.interface/status/interface,@Name/data.leasetime*/
static int get_DHCPv4Client_LeaseTimeRemaining(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res;

	if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL)
		return 0;

	dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(((struct dhcp_client_args *)data)->dhcp_client_conf), String}}, 1, &res);
	if (!res) {
		*value = "";
		return 0;
	}
	*value = dmjson_get_value(res, 2, "data", "leasetime");
	return 0;
}

/*#Device.DHCPv4.Client.{i}.SentOptionNumberOfEntries!UCI:network/interface,@i-1/sendopts*/
static int get_DHCPv4Client_SentOptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;
	size_t length;

	if (((struct dhcp_client_args *)data)->dhcp_client_conf != NULL)
		dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "sendopts", &v);
	if (v == NULL) {
		*value = "0";
		return 0;
	}
	strsplit(v, " ", &length);
	dmasprintf(value, "%d", length);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.ReqOptionNumberOfEntries!UCI:network/interface,@i-1/reqopts*/
static int get_DHCPv4Client_ReqOptionNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;
	size_t length;

	if (((struct dhcp_client_args *)data)->dhcp_client_conf != NULL)
		dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "reqopts", &v);
	if (v == NULL) {
		*value = "0";
		return 0;
	}
	strsplit(v, " ", &length);
	dmasprintf(value, "%d", length);
	return 0;
}

static int get_DHCPv4ClientSentOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v, *opttagvalue = NULL;

	if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0) {
		*value = "0";
		return 0;
	}
	dmasprintf(&opttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
	if (is_elt_exit_in_str_list(v, opttagvalue))
		*value = "1";
	else
		*value = "0";

	return 0;
}

static int set_DHCPv4ClientSentOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *v, *opttagvalue= NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
			if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0)
				return 0;
			dmasprintf(&opttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			if (b) {
				if (!is_elt_exit_in_str_list(v, opttagvalue)) {
					add_elt_to_str_list(&v, opttagvalue);
					dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", v);
				}
			} else {
				remove_elt_from_str_list(&v, opttagvalue);
				dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", v);
			}
			break;
	}
	return 0;
}

static int get_DHCPv4ClientSentOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_sentopt_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ClientSentOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_sentopt_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientSentOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ClientSentOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *pch, *spch = NULL, *list, *v, *opttagvalue, **sendopts, *oldopttagvalue;
	size_t length;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
			if (v == NULL)
				return 0;
			list = dmstrdup(v);
			for (pch = strtok_r(list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
				sendopts = strsplit(pch, ":", &length);
				if (strcmp(sendopts[0], value) == 0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
			dmasprintf(&oldopttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			if (v != NULL && strlen(v) > 0)
				remove_elt_from_str_list(&v, oldopttagvalue);
			dmasprintf(&opttagvalue, "%s:%s", value, ((struct dhcp_client_option_args *)data)->value && strlen(((struct dhcp_client_option_args *)data)->value)>0 ? ((struct dhcp_client_option_args *)data)->value:"0");
			add_elt_to_str_list(&v, opttagvalue);
			dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_option_args *)data)->opt_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientSentOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->value);
	return 0;
}

static int set_DHCPv4ClientSentOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *v, *opttagvalue, *oldopttagvalue;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"0","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", &v);
			dmasprintf(&oldopttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			remove_elt_from_str_list(&v, oldopttagvalue);
			dmasprintf(&opttagvalue, "%s:%s", ((struct dhcp_client_option_args *)data)->option_tag, value);
			add_elt_to_str_list(&v, opttagvalue);
			dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "sendopts", v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_option_args *)data)->opt_sect, "option_value", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientReqOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v;

	if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0) {
		*value = "0";
		return 0;
	}
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &v);
	if (is_elt_exit_in_str_list(v, ((struct dhcp_client_option_args *)data)->option_tag))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_DHCPv4ClientReqOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &v);
			if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0)
				return 0;
			if (b) {
				if (!is_elt_exit_in_str_list(v, ((struct dhcp_client_option_args *)data)->option_tag)) {
					add_elt_to_str_list(&v,  ((struct dhcp_client_option_args *)data)->option_tag);
					dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", v);
				}
			} else {
				remove_elt_from_str_list(&v, ((struct dhcp_client_option_args *)data)->option_tag);
				dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", v);
			}
			break;
	}
	return 0;
}

static int get_DHCPv4ClientReqOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_reqtopt_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ClientReqOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_reqtopt_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ClientReqOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ClientReqOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *pch, *spch, *list, *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &v);
			if (v == NULL)
				return 0;
			list = dmstrdup(v);
			for (pch = strtok_r(list, " ", &spch); pch != NULL; pch = strtok_r(NULL, " ", &spch)) {
				if(strcmp(pch, value) == 0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", &v);
			if (v != NULL && strlen(v) > 0)
				remove_elt_from_str_list(&v, ((struct dhcp_client_option_args *)data)->option_tag);
			add_elt_to_str_list(&v, value);
			dmuci_set_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "reqopts", v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_option_args *)data)->opt_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *dhcp_option_list;
	struct uci_element *e;
	char **buf;
	size_t length;

	if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0) {
		*value = "0";
		return 0;
	}
	dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
	if (dhcp_option_list != NULL) {
		uci_foreach_element(dhcp_option_list, e) {
			buf = strsplit(e->name, ",", &length);
			if (strcmp(buf[0], ((struct dhcp_client_option_args *)data)->option_tag) == 0) {
				*value = "1";
				return 0;
			}
		}
	}
	*value = "0";
	return 0;
}

static int set_DHCPv4ServerPoolOption_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
			if (strcmp(((struct dhcp_client_option_args *)data)->option_tag, "0") == 0)
				return 0;
			dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmasprintf(&opt_value, "%s,%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			if (dhcp_option_list != NULL) {
				uci_foreach_element(dhcp_option_list, e) {
					buf = strsplit(e->name, ",", &length);
					if (strcmp(buf[0], ((struct dhcp_client_option_args *)data)->option_tag) == 0) {
						test = true;
						if (!b)
							dmuci_del_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", opt_value);
						break;
					}
				}
			}
			if(!test && b)
				dmuci_add_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", opt_value);
	}
	return 0;
}

static int get_DHCPv4Server_PoolNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int i= 0;

	uci_foreach_sections("dhcp", "dhcp", s) {
		i++;
	}
	dmasprintf(value, "%d", i);
	return 0;
}

static int get_DHCPv4ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_servpool_option_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4ServerPoolOption_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_option_args *)data)->opt_sect, "bbf_dhcpv4_servpool_option_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->option_tag);
	return 0;
}

static int set_DHCPv4ServerPoolOption_Tag(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *opttagvalue, **option, *oldopttagvalue;
	size_t length;
	struct uci_list *dhcp_option_list = NULL;
	struct uci_element *e;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1","254"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			if (dhcp_option_list == NULL)
				return 0;
			uci_foreach_element(dhcp_option_list, e) {
				option = strsplit(e->name, ",", &length);
				if (strcmp(option[0], value)==0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmasprintf(&oldopttagvalue, "%s,%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			dmasprintf(&opttagvalue, "%s,%s", value, ((struct dhcp_client_option_args *)data)->value);
			dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmuci_del_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", oldopttagvalue);
			dmuci_add_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", opttagvalue);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_option_args *)data)->opt_sect, "option_tag", value);
			break;
	}
	return 0;
}

static int get_DHCPv4ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct dhcp_client_option_args *)data)->value);
	return 0;
}

static int set_DHCPv4ServerPoolOption_Value(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *opttagvalue, **option, *oldopttagvalue;
	size_t length;
	struct uci_list *dhcp_option_list = NULL;
	struct uci_element *e;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{"0","255"}}, 1))
				return FAULT_9007;

			dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			if (dhcp_option_list == NULL)
				return 0;
			uci_foreach_element(dhcp_option_list, e) {
				option = strsplit(e->name, ",", &length);
				if (strcmp(option[0], value) == 0)
					return FAULT_9007;
			}
			break;
		case VALUESET:
			dmasprintf(&oldopttagvalue, "%s,%s", ((struct dhcp_client_option_args *)data)->option_tag, ((struct dhcp_client_option_args *)data)->value);
			dmasprintf(&opttagvalue, "%s,%s", ((struct dhcp_client_option_args *)data)->option_tag, value);
			dmuci_get_value_by_section_list(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", &dhcp_option_list);
			dmuci_del_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", oldopttagvalue);
			dmuci_add_list_value_by_section(((struct dhcp_client_option_args *)data)->client_sect, "dhcp_option", opttagvalue);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_option_args *)data)->opt_sect, "option_value", value);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.Enable!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4RelayForwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;

	if(((struct dhcp_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "0";
		return 0;
	}

	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", &v);
	if (v == NULL || strlen(v) == 0 || strcmp(v, "1") != 0)
		*value = "1";
	else
		*value = "0";

	return 0;
}

static int set_DHCPv4RelayForwarding_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", b ? "0" : "1");
			break;
	}
	return 0;
}

static int get_DHCPv4RelayForwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_dm, "bbf_dhcpv4relay_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_DHCPv4RelayForwarding_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(((struct dhcp_client_args *)data)->dhcp_client_dm, "bbf_dhcpv4relay_alias", value);
			break;
	}
	return 0;
}

static int get_DHCPv4RelayForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL) {
		*value = "";
		return 0;
	}
	char *linker = dmstrdup(section_name(((struct dhcp_client_args *)data)->dhcp_client_conf));
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim), linker, value);
	return 0;
}

static int set_DHCPv4RelayForwarding_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *linker = NULL, *newvalue = NULL, *v;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;

			if (strlen(value) == 0 || strcmp(value, "") == 0)
				return FAULT_9007;

			if (value[strlen(value)-1] != '.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else
				adm_entry_get_linker_value(ctx, value, &linker);
			if (linker == NULL)
				return FAULT_9007;
			uci_path_foreach_sections(bbfdm, "dmmap_dhcp_relay", "interface", s) {
				dmuci_get_value_by_section_string(s, "section_name", &v);
				if (strcmp(v, linker) == 0)
					return FAULT_9007;
			}
			uci_foreach_sections("network", "interface", s) {
				if (strcmp(section_name(s), linker) == 0) {
					dmuci_get_value_by_section_string(s, "proto", &v);
					if(strcmp(v, "relay") != 0)
						return FAULT_9007;
				}
			}
			break;
		case VALUESET:
			if (value[strlen(value)-1]!='.') {
				dmasprintf(&newvalue, "%s.", value);
				adm_entry_get_linker_value(ctx, newvalue, &linker);
			} else
				adm_entry_get_linker_value(ctx, value, &linker);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, ((struct dhcp_client_args *)data)->dhcp_client_dm, "section_name", linker);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.VendorClassID!UCI:network/interface,@i-1/vendorclass*/
static int get_DHCPv4RelayForwarding_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct dhcp_client_args *)data)->vendorclassidclassifier)
		dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->vendorclassidclassifier, "vendorclass", value);
	return 0;
}

static int set_DHCPv4RelayForwarding_VendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 255, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if(((struct dhcp_client_args *)data)->vendorclassidclassifier)
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->vendorclassidclassifier, "vendorclass", value);
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.Chaddr!UCI:network/interface,@i-1/mac*/
static int get_DHCPv4RelayForwarding_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mac, **macarray, *res = NULL, *tmp = "";
	size_t length;
	int i;

	if (((struct dhcp_client_args *)data)->macclassifier == NULL) {
		*value = "";
		return 0;
	}
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->macclassifier, "mac", &mac);
	macarray = strsplit(mac, ":", &length);
	res = (char*)dmcalloc(18, sizeof(char));
	tmp = res;
	for (i = 0; i < 6; i++) {
		if (strcmp(macarray[i], "*") == 0) {
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

static int set_DHCPv4RelayForwarding_Chaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.ChaddrMask!UCI:network/interface,@i-1/mac*/
static int get_DHCPv4RelayForwarding_ChaddrMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *mac, **macarray, *res = NULL, *tmp = "";
	size_t length;
	int i;

	if (((struct dhcp_client_args *)data)->macclassifier == NULL) {
		*value= "";
		return 0;
	}
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->macclassifier, "mac", &mac);
	macarray = strsplit(mac, ":", &length);
	res = (char*)dmcalloc(18, sizeof(char));
	tmp = res;
	for (i = 0; i < 6; i++) {
		if (strcmp(macarray[i], "*") == 0) {
			sprintf(tmp, "%s", "00");
		} else {
			sprintf(tmp, "%s", "FF");
		}
		tmp += 2;

		if (i < 5)  {
			sprintf(tmp, "%s", ":");
			tmp++;
		}
	}
	dmasprintf(value, "%s", res);
	return 0;
}

static int set_DHCPv4RelayForwarding_ChaddrMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			break;
	}
	return 0;
}

static int get_DHCPv4RelayForwarding_ChaddrExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "true";
	return 0;
}

static int set_DHCPv4RelayForwarding_ChaddrExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.Status!UCI:network/interface,@i-1/disabled*/
static int get_DHCPv4RelayForwarding_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *v = NULL;

	if (((struct dhcp_client_args *)data)->dhcp_client_conf == NULL) {
		*value= "Error_Misconfigured";
		return 0;
	}
	dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->dhcp_client_conf, "disabled", &v);
	if (v == NULL || strlen(v) == 0 || strcmp(v, "1") != 0)
		*value= "Enabled";
	else
		*value= "Disabled";

	return 0;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.UserClassID!UCI:network/interface,@i-1/userclass*/
static int get_DHCPv4RelayForwarding_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	if(((struct dhcp_client_args *)data)->userclassclassifier)
		dmuci_get_value_by_section_string(((struct dhcp_client_args *)data)->userclassclassifier, "userclass", value);
	return 0;
}

static int set_DHCPv4RelayForwarding_UserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if(((struct dhcp_client_args *)data)->userclassclassifier)
				dmuci_set_value_by_section(((struct dhcp_client_args *)data)->userclassclassifier, "userclass", value);
			break;
	}
	return 0;
}

static int get_DHCPv4Relay_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*relayd";
	if (check_file(path))
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_DHCPv4Relay_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmcmd("/etc/init.d/relayd", 1, b ? "enable" : "disable");
			break;
	}
	return 0;
}

static int get_DHCPv4Relay_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *path = "/etc/rc.d/*relayd";
	if (check_file(path))
		*value = "Enabled";
	else
		*value = "Disabled";
	return 0;
}

static int get_DHCPv4Relay_ForwardingNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s, *dmmap_sect;
	int nbre_confs = 0, nbre_dmmaps = 0;

	uci_foreach_option_eq("network", "interface", "proto", "relay", s) {
		nbre_confs++;
	}
	uci_path_foreach_sections(bbfdm, "dmmap_dhcp_relay", "interface", dmmap_sect) {
		nbre_dmmaps++;
	}
	if (nbre_dmmaps == 0 || nbre_dmmaps < nbre_confs)
		dmasprintf(value, "%d", nbre_confs);
	else
		dmasprintf(value, "%d", nbre_dmmaps);
	return 0;
}

static void dhcp_leases_load(struct list_head *head)
{
	FILE *f = fopen(DHCP_LEASES_FILE, "r");
	char line[128];

	if (f == NULL)
		return;

	while (fgets(line, sizeof(line) - 1, f)) {
		struct dhcp_lease *lease;

		if (line[0] == '\n')
			continue;

		lease = dmcalloc(1, sizeof(*lease));
		if (lease == NULL)
			break;

		sscanf(line, "%" PRId64 "%19s %15s",
			&lease->ts, lease->hwaddr, lease->ipaddr);

		list_add_tail(&lease->list, head);
	}
	fclose(f);
}

static int interface_get_ipv4(const char *iface, uint32_t *addr, unsigned *bits)
{
	json_object *res;
	const char *addr_str = NULL;
	int addr_cidr = -1;

	dmubus_call("network.interface", "status", UBUS_ARGS {{"interface", iface, String}}, 1, &res);
	if (res) {
		json_object *jobj;

		jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
		if (jobj == NULL)
			return -1;

		json_object_object_foreach(jobj, key, val) {
			if (!strcmp(key, "address"))
				addr_str = json_object_get_string(val);
			else if (!strcmp(key, "mask"))
				addr_cidr = json_object_get_int(val);
		}
	}

	if (addr_str == NULL || addr_cidr == -1)
		return -1;

	if (inet_pton(AF_INET, addr_str, addr) != 1)
		return -1;

	*bits = addr_cidr;
	return 0;
}

static void dhcp_leases_assign_to_interface(struct dhcp_args *dhcp,
					struct list_head *src,
					const char *iface)
{
	struct dhcp_lease *lease, *tmp;
	unsigned iface_addr;
	unsigned iface_cidr;
	unsigned iface_net;
	unsigned iface_bits;

	if (interface_get_ipv4(iface, &iface_addr, &iface_cidr))
		return;

	iface_bits = 32 - iface_cidr;
	iface_net = ntohl(iface_addr) >> iface_bits;

	list_for_each_entry_safe(lease, tmp, src, list) {
		unsigned addr, net;

		inet_pton(AF_INET, lease->ipaddr, &addr);
		net = ntohl(addr) >> iface_bits;

		if (net == iface_net) {
			list_move_tail(&lease->list, &dhcp->leases);
			dhcp->n_leases += 1;
		}
	}
}

/*************************************************************
* ENTRY METHOD
**************************************************************/
/*#Device.DHCPv4.Server.Pool.{i}.!UCI:dhcp/dhcp/dmmap_dhcp*/
static int browseDhcpInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *interface, *idhcp = NULL, *idhcp_last = NULL, *v;
	struct dhcp_args curr_dhcp_args = {0};
	struct dmmap_dup *p;
	LIST_HEAD(leases);
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("dhcp", "dhcp", "dmmap_dhcp", &dup_list);

	if (!list_empty(&dup_list))
		dhcp_leases_load(&leases);

	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "interface", &interface);
		init_dhcp_args(&curr_dhcp_args, p->config_section, interface);

		dhcp_leases_assign_to_interface(&curr_dhcp_args, &leases, interface);

		idhcp = handle_update_instance(1, dmctx, &idhcp_last, update_instance_alias_bbfdm, 3, p->dmmap_section, "dhcp_instance", "dhcp_alias");
		dmuci_get_value_by_section_string(p->dmmap_section, "order", &v);
		if (v == NULL || strlen(v) == 0)
			set_section_order("dhcp", "dmmap_dhcp", "dhcp", p->dmmap_section, p->config_section, 0, idhcp);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_args, idhcp) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*#Device.DHCPv4.Server.Pool.{i}.StaticAddress.{i}.!UCI:dhcp/host/dmmap_dhcp*/
static int browseDhcpStaticInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *idhcp = NULL, *idhcp_last = NULL;
	struct dhcp_static_args curr_dhcp_staticargs = {0};
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("dhcp", "host", "dmmap_dhcp", "dhcp", ((struct dhcp_args *)prev_data)->interface, &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		idhcp = handle_update_instance(2, dmctx, &idhcp_last, update_instance_alias_bbfdm, 3, p->dmmap_section, "ldhcpinstance", "ldhcpalias");
		init_args_dhcp_host(&curr_dhcp_staticargs, p->config_section);
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&curr_dhcp_staticargs, idhcp) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int browseDhcpClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	const struct dhcp_args *dhcp = prev_data;
	const struct dhcp_lease *lease;
	int id = 0;

	list_for_each_entry(lease, &dhcp->leases, list) {
		struct client_args client_args;
		char *idx, *idx_last = NULL;

		init_dhcp_client_args(&client_args, lease);
		idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, ++id);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&client_args, idx) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDhcpClientIPv4Inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *idx, *idx_last = NULL;

	idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, 1);
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, idx);
	return 0;
}

/*#Device.DHCPv4.Client.{i}.!UCI:network/interface/dmmap_dhcp_client*/
static int browseDHCPv4ClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *instance, *instnbr = NULL;
	struct dmmap_dup *p;
	char *type, *ipv4addr = "", *ipv6addr = "", *proto, *inst, *mask4 = NULL;
	json_object *res, *jobj;
	struct dhcp_client_args dhcp_client_arg = {0};
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq_no_delete("network", "interface", "dmmap_dhcp_client", "proto", "dhcp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if (p->config_section != NULL) {
			dmuci_get_value_by_section_string(p->config_section, "type", &type);
			if (strcmp(type, "alias") == 0 || strcmp(section_name(p->config_section), "loopback") == 0)
				continue;

			dmuci_get_value_by_section_string(p->config_section, "ipaddr", &ipv4addr);
			dmuci_get_value_by_section_string(p->config_section, "netmask", &mask4);
			if (ipv4addr[0] == '\0') {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(p->config_section), String}}, 1, &res);
				if (res) {
					jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
					ipv4addr = dmjson_get_value(jobj, 1, "address");
					mask4= dmjson_get_value(jobj, 1, "mask");
				}
			}

			dmuci_get_value_by_section_string(p->config_section, "ip6addr", &ipv6addr);
			if (ipv6addr[0] == '\0') {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(p->config_section), String}}, 1, &res);
				if (res) {
					jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
					ipv6addr = dmjson_get_value(jobj, 1, "address");
				}
			}

			dmuci_get_value_by_section_string(p->config_section, "proto", &proto);
			dmuci_get_value_by_section_string(p->config_section, "ip_int_instance", &inst);

			if (ipv4addr[0] == '\0' && ipv6addr[0] == '\0' && strcmp(proto, "dhcp") != 0 && strcmp(proto, "dhcpv6") != 0 && strcmp(inst, "") == 0 && strcmp(type, "bridge") != 0) {
				p->config_section=NULL;
				DMUCI_SET_VALUE_BY_SECTION(bbfdm, p->dmmap_section, "section_name", "");
			}
		}

		if (ipv4addr == NULL || strlen(ipv4addr) == 0)
			dhcp_client_arg.ip = dmstrdup("");
		else
			dhcp_client_arg.ip = dmstrdup(ipv4addr);
		if (mask4 == NULL || strlen(mask4) == 0)
			dhcp_client_arg.mask = dmstrdup("");
		else
			dhcp_client_arg.mask = dmstrdup(mask4);

		dhcp_client_arg.dhcp_client_conf = p->config_section;
		dhcp_client_arg.dhcp_client_dm= p->dmmap_section;

		instance = handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, (void *)p->dmmap_section, "bbf_dhcpv4client_instance", "bbf_dhcpv4client_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &dhcp_client_arg, instance) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv4ClientSentOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)prev_data;
	struct uci_section *dmmap_sect;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};
	char *instance, *instnbr = NULL, *v1, *v2, **sentopts = NULL, **buf = NULL, *tmp, *optionvalue, *v = NULL;
	size_t length = 0, lgh2;
	int i, j;

	if (dhcp_client_args->dhcp_client_conf != NULL)
		dmuci_get_value_by_section_string(dhcp_client_args->dhcp_client_conf, "sendopts", &v);

	if (v) sentopts = strsplit(v, " ", &length);
	check_create_dmmap_package("dmmap_dhcp_client");
	for (i = 0; i < length; i++) {
		if (sentopts[i]) buf = strsplit(sentopts[i], ":", &lgh2);
		if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcp_client", "send_option", section_name(dhcp_client_args->dhcp_client_conf), "option_tag", buf[0])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_dhcp_client", "send_option", &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_tag", buf[0]);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(dhcp_client_args->dhcp_client_conf));
		}
		optionvalue = dmstrdup(buf[1]);
		if (lgh2 > 2) {
			for (j = 2; j < lgh2; j++) {
				tmp = dmstrdup(optionvalue);
				dmfree(optionvalue);
				optionvalue = NULL;
				dmasprintf(&optionvalue, "%s:%s", tmp, buf[j]);
				dmfree(tmp);
				tmp = NULL;
			}
		}
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_value", optionvalue);
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp_client", "send_option", "section_name", dhcp_client_args->dhcp_client_conf?section_name(dhcp_client_args->dhcp_client_conf):"", dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &v1);
		dmuci_get_value_by_section_string(dmmap_sect, "option_value", &v2);
		dhcp_client_opt_args.client_sect= dhcp_client_args->dhcp_client_conf;
		dhcp_client_opt_args.option_tag= dmstrdup(v1);
		dhcp_client_opt_args.value= dmstrdup(v2);
		dhcp_client_opt_args.opt_sect= dmmap_sect;

		instance = handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, dmmap_sect, "bbf_dhcpv4_sentopt_instance", "bbf_dhcpv4_sentopt_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &dhcp_client_opt_args, instance) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv4ClientReqOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dhcp_client_args *dhcp_client_args = (struct dhcp_client_args*)prev_data;
	struct uci_section *dmmap_sect;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};
	char *instance, *instnbr = NULL, *v1, **reqtopts = NULL, *v = NULL;
	size_t length = 0;
	int i;

	if (dhcp_client_args->dhcp_client_conf != NULL)
		dmuci_get_value_by_section_string(dhcp_client_args->dhcp_client_conf, "reqopts", &v);
	if (v) reqtopts = strsplit(v, " ", &length);
	check_create_dmmap_package("dmmap_dhcp_client");
	for (i = 0; i < length; i++) {
		if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcp_client", "req_option", section_name(dhcp_client_args->dhcp_client_conf), "option_tag", reqtopts[i])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_dhcp_client", "req_option", &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_tag", reqtopts[i]);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(dhcp_client_args->dhcp_client_conf));
		}
	}

	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp_client", "req_option", "section_name", dhcp_client_args->dhcp_client_conf?section_name(dhcp_client_args->dhcp_client_conf):"", dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &v1);
		dhcp_client_opt_args.client_sect = dhcp_client_args->dhcp_client_conf;
		dhcp_client_opt_args.option_tag = dmstrdup(v1);
		dhcp_client_opt_args.value = dmstrdup("");
		dhcp_client_opt_args.opt_sect = dmmap_sect;

		instance = handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, dmmap_sect, "bbf_dhcpv4_reqtopt_instance", "bbf_dhcpv4_reqtopt_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &dhcp_client_opt_args, instance) == DM_STOP)
			break;
	}
	return 0;
}

static int browseDHCPv4ServerPoolOptionInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_list *dhcp_options_list = NULL;
	struct uci_element *e;
	struct dhcp_args *curr_dhcp_args = (struct dhcp_args*)prev_data;
	struct uci_section *dmmap_sect;
	char **tagvalue = NULL, *instance, *instnbr = NULL, *optionvalue = NULL, *tmp, *v1, *v2, *v;
	size_t length;
	int j;
	struct dhcp_client_option_args dhcp_client_opt_args = {0};

	dmuci_get_value_by_section_list(curr_dhcp_args->dhcp_sec, "dhcp_option", &dhcp_options_list);
	if (dhcp_options_list != NULL) {
		uci_foreach_element(dhcp_options_list, e) {
			tagvalue = strsplit(e->name, ",", &length);
			if ((dmmap_sect = get_dup_section_in_dmmap_eq("dmmap_dhcp", "servpool_option", section_name(curr_dhcp_args->dhcp_sec), "option_tag", tagvalue[0])) == NULL) {
				dmuci_add_section_bbfdm("dmmap_dhcp", "servpool_option", &dmmap_sect, &v);
				DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_tag", tagvalue[0]);
				DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "section_name", section_name(curr_dhcp_args->dhcp_sec));
			}
			optionvalue = dmstrdup(tagvalue[1]);
			if (length > 2) {
				for (j = 2; j < length; j++) {
					tmp = dmstrdup(optionvalue);
					dmfree(optionvalue);
					optionvalue = NULL;
					dmasprintf(&optionvalue, "%s,%s", tmp, tagvalue[j]);
					dmfree(tmp);
					tmp = NULL;
				}
			}
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "option_value", optionvalue);
		}
	}
	uci_path_foreach_option_eq(bbfdm, "dmmap_dhcp", "servpool_option", "section_name", section_name(curr_dhcp_args->dhcp_sec), dmmap_sect) {
		dmuci_get_value_by_section_string(dmmap_sect, "option_tag", &v1);
		dmuci_get_value_by_section_string(dmmap_sect, "option_value", &v2);
		dhcp_client_opt_args.client_sect = curr_dhcp_args->dhcp_sec;
		dhcp_client_opt_args.option_tag = dmstrdup(v1);
		dhcp_client_opt_args.value = dmstrdup(v2);
		dhcp_client_opt_args.opt_sect = dmmap_sect;
		instance = handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, dmmap_sect, "bbf_dhcpv4_servpool_option_instance", "bbf_dhcpv4_servpool_option_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &dhcp_client_opt_args, instance) == DM_STOP)
			break;
	}
	return 0;
}

static char *get_dhcp_network_from_relay_list(char *net_list)
{
	struct uci_section *s;
	char **net_list_arr, *v;
	int i;
	size_t length;

	net_list_arr = strsplit(net_list, " ", &length);
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &v);
		for (i = 0; i < length; i++) {
			if (strcmp(net_list_arr[i], section_name(s)) == 0 && strcmp(v, "dhcp") == 0)
				return net_list_arr[i];
		}
	}
	return "";
}

struct uci_section* get_dhcp_classifier(char *classifier_name, char *network)
{
	struct uci_section* s = NULL;
	char *v;

	uci_foreach_sections("dhcp", classifier_name, s) {
		dmuci_get_value_by_section_string(s, "networkid", &v);
		if (strcmp(v, network) == 0)
			return s;
	}
	return NULL;
}

/*#Device.DHCPv4.Relay.Forwarding.{i}.!UCI:network/interface/dmmap_dhcp_relay*/
static int browseDHCPv4RelayForwardingInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *instance, *instnbr = NULL, *v, *dhcp_network = NULL;
	struct dmmap_dup *p;
	char *type, *ipv4addr = "", *ipv6addr = "", *proto, *inst, *mask4 = NULL;
	json_object *res, *jobj;
	struct dhcp_client_args dhcp_relay_arg = {0};
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_eq_no_delete("network", "interface", "dmmap_dhcp_relay", "proto", "relay", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if (p->config_section != NULL) {
			dmuci_get_value_by_section_string(p->config_section, "type", &type);
			if (strcmp(type, "alias") == 0 || strcmp(section_name(p->config_section), "loopback") == 0)
				continue;

			dmuci_get_value_by_section_string(p->config_section, "ipaddr", &ipv4addr);
			dmuci_get_value_by_section_string(p->config_section, "netmask", &mask4);
			if (ipv4addr[0] == '\0') {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(p->config_section), String}}, 1, &res);
				if (res) {
					jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv4-address");
					ipv4addr = dmjson_get_value(jobj, 1, "address");
					mask4= dmjson_get_value(jobj, 1, "mask");
				}
			}

			dmuci_get_value_by_section_string(p->config_section, "ip6addr", &ipv6addr);
			if (ipv6addr[0] == '\0') {
				dmubus_call("network.interface", "status", UBUS_ARGS{{"interface", section_name(p->config_section), String}}, 1, &res);
				if (res) {
					jobj = dmjson_select_obj_in_array_idx(res, 0, 1, "ipv6-address");
					ipv6addr = dmjson_get_value(jobj, 1, "address");
				}
			}

			dmuci_get_value_by_section_string(p->config_section, "proto", &proto);
			dmuci_get_value_by_section_string(p->config_section, "ip_int_instance", &inst);
			if (ipv4addr[0] == '\0' && ipv6addr[0] == '\0' && strcmp(inst, "") == 0 && strcmp(type, "bridge") != 0 && strcmp(proto, "relay") != 0) {
				p->config_section = NULL;
				DMUCI_SET_VALUE_BY_SECTION(bbfdm, p->dmmap_section, "section_name", "");
			}
		}

		if (ipv4addr == NULL || strlen(ipv4addr) == 0)
			dhcp_relay_arg.ip = dmstrdup("");
		else
			dhcp_relay_arg.ip = dmstrdup(ipv4addr);
		if (mask4 == NULL || strlen(mask4) == 0)
			dhcp_relay_arg.mask = dmstrdup("");
		else
			dhcp_relay_arg.mask = dmstrdup(mask4);
		if (p->config_section != NULL)
			dmuci_get_value_by_section_string(p->config_section, "network", &v);
		else
			v = dmstrdup("");

		dhcp_network = get_dhcp_network_from_relay_list(v);
		if (dhcp_network && strlen(dhcp_network) > 0) {
			dhcp_relay_arg.macclassifier = get_dhcp_classifier("mac", dhcp_network);
			dhcp_relay_arg.vendorclassidclassifier = get_dhcp_classifier("vendorclass", dhcp_network);
			dhcp_relay_arg.userclassclassifier = get_dhcp_classifier("userclass", dhcp_network);
		} else {
			dhcp_relay_arg.macclassifier = NULL;
			dhcp_relay_arg.vendorclassidclassifier = NULL;
			dhcp_relay_arg.userclassclassifier = NULL;
		}
		dhcp_relay_arg.dhcp_client_conf = p->config_section;

		dhcp_relay_arg.dhcp_client_dm= p->dmmap_section;
		instance = handle_update_instance(1, dmctx, &instnbr, update_instance_alias_bbfdm, 3, (void *)p->dmmap_section, "bbf_dhcpv4relay_instance", "bbf_dhcpv4relay_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, &dhcp_relay_arg, instance) == DM_STOP)
			break;
	}
	return 0;
}

/*** DHCPv4. ***/
DMOBJ tDHCPv4Obj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Client", &DMWRITE, addObjDHCPv4Client, delObjDHCPv4Client, NULL, browseDHCPv4ClientInst, NULL, NULL, NULL, tDHCPv4ClientObj, tDHCPv4ClientParams, NULL, BBFDM_BOTH},
{"Server", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDHCPv4ServerObj, tDHCPv4ServerParams, NULL, BBFDM_BOTH},
{"Relay", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tDHCPv4RelayObj, tDHCPv4RelayParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv4Params[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4_ClientNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Client.{i}. *** */
DMOBJ tDHCPv4ClientObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"SentOption", &DMWRITE, addObjDHCPv4ClientSentOption, delObjDHCPv4ClientSentOption, NULL, browseDHCPv4ClientSentOptionInst, NULL, NULL, NULL, NULL, tDHCPv4ClientSentOptionParams, NULL, BBFDM_BOTH},
{"ReqOption", &DMWRITE, addObjDHCPv4ClientReqOption, delObjDHCPv4ClientReqOption, NULL, browseDHCPv4ClientReqOptionInst, NULL, NULL, NULL, NULL, tDHCPv4ClientReqOptionParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv4ClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4Client_Enable, set_DHCPv4Client_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4Client_Alias, set_DHCPv4Client_Alias, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv4Client_Interface, set_DHCPv4Client_Interface, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv4Client_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"DHCPStatus", &DMREAD, DMT_STRING, get_DHCPv4Client_DHCPStatus, NULL, NULL, NULL, BBFDM_BOTH},
{"Renew", &DMWRITE, DMT_BOOL, get_DHCPv4Client_Renew, set_DHCPv4Client_Renew, NULL, NULL, BBFDM_BOTH},
{"IPAddress", &DMREAD, DMT_STRING, get_DHCPv4Client_IPAddress, NULL, NULL, NULL, BBFDM_BOTH},
{"SubnetMask", &DMREAD, DMT_STRING, get_DHCPv4Client_SubnetMask, NULL, NULL, NULL, BBFDM_BOTH},
{"IPRouters", &DMREAD, DMT_STRING, get_DHCPv4Client_IPRouters, NULL, NULL, NULL, BBFDM_BOTH},
{"DNSServers", &DMREAD, DMT_STRING, get_DHCPv4Client_DNSServers, NULL, NULL, NULL, BBFDM_BOTH},
{"LeaseTimeRemaining", &DMREAD, DMT_INT, get_DHCPv4Client_LeaseTimeRemaining, NULL, NULL, NULL, BBFDM_BOTH},
//{"DHCPServer", &DMREAD, DMT_STRING, get_DHCPv4Client_DHCPServer, NULL, NULL, NULL, BBFDM_BOTH},
//{"PassthroughEnable", &DMWRITE, DMT_BOOL, get_DHCPv4Client_PassthroughEnable, set_DHCPv4Client_PassthroughEnable, NULL, NULL, BBFDM_BOTH},
//{"PassthroughDHCPPool", &DMWRITE, DMT_STRING, get_DHCPv4Client_PassthroughDHCPPool, set_DHCPv4Client_PassthroughDHCPPool, NULL, NULL, BBFDM_BOTH},
{"SentOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Client_SentOptionNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"ReqOptionNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Client_ReqOptionNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Client.{i}.SentOption.{i}. *** */
DMLEAF tDHCPv4ClientSentOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ClientSentOption_Enable, set_DHCPv4ClientSentOption_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ClientSentOption_Alias, set_DHCPv4ClientSentOption_Alias, NULL, NULL, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ClientSentOption_Tag, set_DHCPv4ClientSentOption_Tag, NULL, NULL, BBFDM_BOTH},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv4ClientSentOption_Value, set_DHCPv4ClientSentOption_Value, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Client.{i}.ReqOption.{i}. *** */
DMLEAF tDHCPv4ClientReqOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ClientReqOption_Enable, set_DHCPv4ClientReqOption_Enable, NULL, NULL, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_DHCPv4ClientReqOption_Order, set_DHCPv4ClientReqOption_Order, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ClientReqOption_Alias, set_DHCPv4ClientReqOption_Alias, NULL, NULL, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ClientReqOption_Tag, set_DHCPv4ClientReqOption_Tag, NULL, NULL, BBFDM_BOTH},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv4ClientReqOption_Value, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv4ServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4Server_Enable, set_DHCPv4Server_Enable, NULL, NULL, BBFDM_BOTH},
{"PoolNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Server_PoolNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** DHCPv4.Server. ***/
DMOBJ tDHCPv4ServerObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Pool", &DMWRITE, add_dhcp_server, delete_dhcp_server, NULL, browseDhcpInst, NULL, NULL, NULL, tDHCPv4ServerPoolObj, tDHCPv4ServerPoolParams, NULL, BBFDM_BOTH},
{0}
};

/*** DHCPv4.Server.Pool.{i}. ***/
DMOBJ tDHCPv4ServerPoolObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"StaticAddress", &DMWRITE, add_dhcp_staticaddress, delete_dhcp_staticaddress, NULL, browseDhcpStaticInst, NULL, NULL, NULL, NULL, tDHCPv4ServerPoolStaticAddressParams, NULL, BBFDM_BOTH},
{"Option", &DMWRITE, addObjDHCPv4ServerPoolOption, delObjDHCPv4ServerPoolOption, NULL, browseDHCPv4ServerPoolOptionInst, NULL, NULL, NULL, NULL, tDHCPv4ServerPoolOptionParams, NULL, BBFDM_BOTH},
{"Client", &DMREAD, NULL, NULL, NULL, browseDhcpClientInst, NULL, NULL, NULL, tDHCPv4ServerPoolClientObj, tDHCPv4ServerPoolClientParams, get_dhcp_client_linker},
{0}
};

/*** DHCPv4.Server.Pool.{i}.Client.{i}. ***/
DMOBJ tDHCPv4ServerPoolClientObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"IPv4Address", &DMREAD, NULL, NULL, NULL, browseDhcpClientIPv4Inst, NULL, NULL, NULL, NULL, tDHCPv4ServerPoolClientIPv4AddressParams, NULL, BBFDM_BOTH},
//{"Option", &DMREAD, NULL, NULL, NULL, browseDHCPv4ServerPoolClientOptionInst, NULL, NULL, NULL, NULL, tDHCPv4ServerPoolClientOptionParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv4ServerPoolParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING,  get_server_pool_alias, set_server_pool_alias, NULL, NULL, BBFDM_BOTH},
{"DNSServers", &DMWRITE, DMT_STRING,  get_dns_server, set_dns_server, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING,  get_dhcp_status, NULL, NULL, NULL, BBFDM_BOTH},
{"Order", &DMWRITE, DMT_UNINT, get_dhcp_sever_pool_order, set_dhcp_sever_pool_order, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL,  get_dhcp_enable, set_dhcp_enable, NULL, NULL, BBFDM_BOTH},
{"MinAddress", &DMWRITE, DMT_STRING, get_dhcp_interval_address_min, set_dhcp_address_min, NULL, NULL, BBFDM_BOTH},
{"MaxAddress", &DMWRITE, DMT_STRING,get_dhcp_interval_address_max, set_dhcp_address_max, NULL, NULL, BBFDM_BOTH},
{"ReservedAddresses", &DMWRITE, DMT_STRING, get_dhcp_reserved_addresses, set_dhcp_reserved_addresses, NULL, NULL, BBFDM_BOTH},
{"SubnetMask", &DMWRITE, DMT_STRING,get_dhcp_subnetmask, set_dhcp_subnetmask, NULL, NULL, BBFDM_BOTH},
{"IPRouters", &DMWRITE, DMT_STRING, get_dhcp_iprouters, set_dhcp_iprouters, NULL, NULL, BBFDM_BOTH},
{"LeaseTime", &DMWRITE, DMT_INT, get_dhcp_leasetime, set_dhcp_leasetime, NULL, NULL, BBFDM_BOTH},
{"DomainName", &DMWRITE, DMT_STRING, get_dhcp_domainname, set_dhcp_domainname, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_dhcp_interface, set_dhcp_interface_linker_parameter, NULL, NULL, BBFDM_BOTH},
{"StaticAddressNumberOfEntries", &DMWRITE, DMT_UNINT, get_static_address_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"OptionNumberOfEntries", &DMWRITE, DMT_UNINT, get_option_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"ClientNumberOfEntries", &DMWRITE, DMT_UNINT, get_clients_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** DHCPv4.Server.Pool.{i}.StaticAddress.{i}. ***/
DMLEAF tDHCPv4ServerPoolStaticAddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_dhcp_static_alias, set_dhcp_static_alias, NULL, NULL, BBFDM_BOTH},
{"Chaddr", &DMWRITE, DMT_STRING,  get_dhcp_staticaddress_chaddr, set_dhcp_staticaddress_chaddr, NULL, NULL, BBFDM_BOTH},
{"Yiaddr", &DMWRITE, DMT_STRING,  get_dhcp_staticaddress_yiaddr, set_dhcp_staticaddress_yiaddr, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** DHCPv4.Server.Pool.{i}.Client.{i}. ***/
DMLEAF tDHCPv4ServerPoolClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Chaddr", &DMREAD, DMT_STRING,  get_dhcp_client_chaddr, NULL, NULL, NULL, BBFDM_BOTH},
{"Active", &DMREAD, DMT_BOOL,  get_dhcp_client_active, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*** DHCPv4.Server.Pool.{i}.Client.{i}.IPv4Address.{i}. ***/
DMLEAF tDHCPv4ServerPoolClientIPv4AddressParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"LeaseTimeRemaining", &DMREAD, DMT_TIME,  get_dhcp_client_ipv4address_leasetime, NULL, NULL, NULL, BBFDM_BOTH},
{"IPAddress", &DMREAD, DMT_STRING,  get_dhcp_client_ipv4address_ip_address, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Option.{i}. *** */
DMLEAF tDHCPv4ServerPoolOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4ServerPoolOption_Enable, set_DHCPv4ServerPoolOption_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4ServerPoolOption_Alias, set_DHCPv4ServerPoolOption_Alias, NULL, NULL, BBFDM_BOTH},
{"Tag", &DMWRITE, DMT_UNINT, get_DHCPv4ServerPoolOption_Tag, set_DHCPv4ServerPoolOption_Tag, NULL, NULL, BBFDM_BOTH},
{"Value", &DMWRITE, DMT_HEXBIN, get_DHCPv4ServerPoolOption_Value, set_DHCPv4ServerPoolOption_Value, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Server.Pool.{i}.Client.{i}.Option.{i}. *** */
DMLEAF tDHCPv4ServerPoolClientOptionParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Tag", &DMREAD, DMT_UNINT, get_DHCPv4ServerPoolClientOption_Tag, NULL, NULL, NULL, BBFDM_BOTH},
//{"Value", &DMREAD, DMT_HEXBIN, get_DHCPv4ServerPoolClientOption_Value, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DHCPv4.Relay. *** */
DMOBJ tDHCPv4RelayObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Forwarding", &DMWRITE, addObjDHCPv4RelayForwarding, delObjDHCPv4RelayForwarding, NULL, browseDHCPv4RelayForwardingInst, NULL, NULL, NULL, NULL, tDHCPv4RelayForwardingParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDHCPv4RelayParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4Relay_Enable, set_DHCPv4Relay_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv4Relay_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"ForwardingNumberOfEntries", &DMREAD, DMT_UNINT, get_DHCPv4Relay_ForwardingNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
/* *** Device.DHCPv4.Relay.Forwarding.{i}. *** */
DMLEAF tDHCPv4RelayForwardingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_Enable, set_DHCPv4RelayForwarding_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DHCPv4RelayForwarding_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_Alias, set_DHCPv4RelayForwarding_Alias, NULL, NULL, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_DHCPv4RelayForwarding_Order, set_DHCPv4RelayForwarding_Order, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_Interface, set_DHCPv4RelayForwarding_Interface, NULL, NULL, BBFDM_BOTH},
{"VendorClassID", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_VendorClassID, set_DHCPv4RelayForwarding_VendorClassID, NULL, NULL, BBFDM_BOTH},
//{"VendorClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_VendorClassIDExclude, set_DHCPv4RelayForwarding_VendorClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"VendorClassIDMode", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_VendorClassIDMode, set_DHCPv4RelayForwarding_VendorClassIDMode, NULL, NULL, BBFDM_BOTH},
//{"ClientID", &DMWRITE, DMT_HEXBIN, get_DHCPv4RelayForwarding_ClientID, set_DHCPv4RelayForwarding_ClientID, NULL, NULL, BBFDM_BOTH},
//{"ClientIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_ClientIDExclude, set_DHCPv4RelayForwarding_ClientIDExclude, NULL, NULL, BBFDM_BOTH},
{"UserClassID", &DMWRITE, DMT_HEXBIN, get_DHCPv4RelayForwarding_UserClassID, set_DHCPv4RelayForwarding_UserClassID, NULL, NULL, BBFDM_BOTH},
//{"UserClassIDExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_UserClassIDExclude, set_DHCPv4RelayForwarding_UserClassIDExclude, NULL, NULL, BBFDM_BOTH},
{"Chaddr", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_Chaddr, set_DHCPv4RelayForwarding_Chaddr, NULL, NULL, BBFDM_BOTH},
{"ChaddrMask", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_ChaddrMask, set_DHCPv4RelayForwarding_ChaddrMask, NULL, NULL, BBFDM_BOTH},
{"ChaddrExclude", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_ChaddrExclude, set_DHCPv4RelayForwarding_ChaddrExclude, NULL, NULL, BBFDM_BOTH},
//{"LocallyServed", &DMWRITE, DMT_BOOL, get_DHCPv4RelayForwarding_LocallyServed, set_DHCPv4RelayForwarding_LocallyServed, NULL, NULL, BBFDM_BOTH},
//{"DHCPServerIPAddress", &DMWRITE, DMT_STRING, get_DHCPv4RelayForwarding_DHCPServerIPAddress, set_DHCPv4RelayForwarding_DHCPServerIPAddress, NULL, NULL, BBFDM_BOTH},
{0}
};
