/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Rahul Thakur <rahul.thakur@iopsys.eu>
 *
 */
#include "dmentry.h"
#include "x_iopsys_eu_igmp.h"

static int add_igmp_proxy_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v, *s_name;
	struct uci_section  *dmmap = NULL, *s = NULL;
	char i_no[16];

	check_create_dmmap_package("dmmap_mcast");
	inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "proxy", "proxy_instance",
						"proto", "igmp");
	snprintf(i_no, sizeof(i_no), "%d", inst ? atoi(inst)+1 : 1);

	dmasprintf(&s_name, "igmp_proxy_%s", i_no);

	dmuci_add_section("mcast", "proxy", &s, &value);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "proto", "igmp");
	dmuci_set_value_by_section(s, "version", "2");
	dmuci_set_value_by_section(s, "robustness", "2");
	dmuci_set_value_by_section(s, "aggregation", "0");

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "proto", "igmp");
	*instance = update_instance_bbfdm(dmmap, inst, "proxy_instance");

	return 0;
}

static int del_igmp_proxy_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			// first delete all filter child nodes related to this object
			del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_filter",
				"section_name", section_name((struct uci_section *)data));
			// Now delete all interface child nodes related to this object
			del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_interface",
				"section_name", section_name((struct uci_section *)data));

			// Now delete the proxy node
			get_dmmap_section_of_config_section("dmmap_mcast", "proxy", section_name((struct uci_section *)data), &dmmap_section);

			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq("mcast", "proxy", "proto", "igmp", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_mcast", "proxy", section_name(s), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_mcast", "proxy", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}

			break;
	}
	return 0;
}

static int browse_igmp_proxy_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("mcast", "proxy", "dmmap_mcast", "proto", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "proxy_instance", "proxy_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int add_igmp_snooping_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v, *s_name;
	struct uci_section  *dmmap = NULL, *s = NULL;
	char i_no[16];

	check_create_dmmap_package("dmmap_mcast");
	inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "snooping",
					"snooping_instance", "proto", "igmp");
	snprintf(i_no, sizeof(i_no), "%d", inst ? atoi(inst)+1 : 1);

	dmasprintf(&s_name, "igmp_snoop_%s", i_no);

	dmuci_add_section("mcast", "snooping", &s, &value);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "proto", "igmp");
	dmuci_set_value_by_section(s, "version", "2");
	dmuci_set_value_by_section(s, "robustness", "2");
	dmuci_set_value_by_section(s, "aggregation", "0");

	dmuci_add_section_bbfdm("dmmap_mcast", "snooping", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	dmuci_set_value_by_section(dmmap, "proto", "igmp");
	*instance = update_instance_bbfdm(dmmap, inst, "snooping_instance");

	return 0;
}

static int del_igmp_snooping_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			// first delete all filter child nodes related to this object
			del_dmmap_sec_with_opt_eq("dmmap_mcast", "snooping_filter",
				"section_name", section_name((struct uci_section *)data));
			// Now delete all interface child nodes related to this object
			del_dmmap_sec_with_opt_eq("dmmap_mcast", "snooping_interface",
				"section_name", section_name((struct uci_section *)data));
			get_dmmap_section_of_config_section("dmmap_mcast", "snooping", section_name((struct uci_section *)data), &dmmap_section);

			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);

			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_option_eq("mcast", "snooping", "proto", "igmp", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_mcast", "snooping", section_name(s), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_mcast", "snooping", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}

			break;
	}
	return 0;
}

static int browse_igmp_snooping_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_cont("mcast", "snooping", "dmmap_mcast", "proto", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "snooping_instance", "snooping_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int get_igmps_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("mcast", "snooping", "proto", "igmp", s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_igmpp_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_option_eq("mcast", "proxy", "proto", "igmp", s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int browse_igmps_cgrp_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

#if 0
static int browse_igmpp_cgrp_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}
#endif

static int add_igmps_filter_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *last_inst, *v;
	struct uci_section *dmmap_igmps_filter = NULL;

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "snooping_filter", "filter_instance",
					"section_name", section_name((struct uci_section *)data));

	dmuci_add_section_bbfdm("dmmap_mcast", "snooping_filter", &dmmap_igmps_filter, &v);
	dmuci_set_value_by_section(dmmap_igmps_filter, "section_name",
				section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_igmps_filter, "enable", "0");
	*instance = update_instance_bbfdm(dmmap_igmps_filter, last_inst, "filter_instance");

	return 0;
}

static int del_igmps_filter_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *d_sec = NULL;
	char *f_inst, *ip_addr;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
					"section_name", section_name((struct uci_section *)data), d_sec) {
				dmuci_get_value_by_section_string(d_sec, "filter_instance", &f_inst);

				if (strcmp(instance, f_inst) == 0) {
					dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
					dmuci_delete_by_section(d_sec, NULL, NULL);
					found = 1;
				}

				if (found) {
					dmuci_del_list_value_by_section((struct uci_section *)data,
							"filter", ip_addr);
					break;
				}
			}

			break;
		case DEL_ALL:
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
					"section_name", section_name((struct uci_section *)data), d_sec) {
				dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
				if (ip_addr[0] != '\0') {
					dmuci_del_list_value_by_section((struct uci_section *)data,
							"filter", ip_addr);
				}
			}

			del_dmmap_sec_with_opt_eq("dmmap_mcast", "snooping_filter",
				"section_name", section_name((struct uci_section *)data));
			break;
	}

	return 0;
}

static int browse_igmps_filter_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL, *inst_last = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_filter("mcast", "snooping", prev_data, "dmmap_mcast",
			"snooping_filter", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if (!p->config_section)
			break;

		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3,
				p->dmmap_section, "filter_instance", "filter_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;

	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int get_igmps_filter_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter", "section_name",
				section_name((struct uci_section *)data), s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_igmps_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *f_sec;
	char *f_inst, *f_enable;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
			"section_name", section_name((struct uci_section *)data), f_sec) {
		dmuci_get_value_by_section_string(f_sec, "filter_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(f_sec, "enable", &f_enable);
			break;
		}
	}

	if (strcmp(f_enable, "1") == 0) {
		*value = "true";
	} else {
		*value = "false";
	}

	return 0;
}


static int set_igmps_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *f_sec;
	char *f_inst, *ip_addr;
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
					"section_name", section_name((struct uci_section *)data), f_sec) {
				dmuci_get_value_by_section_string(f_sec, "filter_instance", &f_inst);
				if (strcmp(instance, f_inst) == 0) {
					dmuci_get_value_by_section_string(f_sec, "ipaddr", &ip_addr);
					dmuci_set_value_by_section(f_sec, "enable", (b) ? "1" : "0");
					if (ip_addr[0] != '\0') {
						sync_dmmap_bool_to_uci_list((struct uci_section *)data,
								"filter", ip_addr, b);
					}
					break;
				}
			}
			break;
	}

	return 0;
}

static int get_igmps_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec;
	char *f_inst, *ip_addr;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "filter_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
			break;
		}
	}

	if (ip_addr[0] == '\0') {
		*value = "";
	} else {
		*value = dmstrdup(ip_addr);
	}

	return 0;
}

static int set_igmps_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *s_inst, *up;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;

			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "snooping_filter",
					"section_name", section_name((struct uci_section *)data), s) {
				dmuci_get_value_by_section_string(s, "filter_instance", &s_inst);
				if (strcmp(s_inst, instance) == 0) {
					dmuci_set_value_by_section(s, "ipaddr", value);
					dmuci_get_value_by_section_string(s, "enable", &up);
					string_to_bool(up, &b);
					sync_dmmap_bool_to_uci_list((struct uci_section *)data,
							"filter", value, b);
					break;
				}
			}

			break;
	}

	return 0;
}

static int get_igmp_snooping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", &val);

	if (strcmp(val, "1") == 0)
		*value = "true";
	else
		*value = "false";

	return 0;
}

static int set_igmp_snooping_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enable", (b) ? "1" : "0");
			break;
	}

	return 0;
}

static int get_igmp_snooping_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "version", &val);

	if (strcmp(val, "2") == 0)
		*value = "V2";
	else
		*value = "V3";

	return 0;
}

static int set_igmp_snooping_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char val[4];

	switch (action) {
		case VALUECHECK:
			if ((strcmp("V2", value) != 0) && (strcmp("V3", value) != 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcmp(value, "V2") == 0)
				strcpy(val, "2");
			else
				strcpy(val, "3");

			dmuci_set_value_by_section((struct uci_section *)data, "version", val);
			break;
	}

	return 0;
}

static int get_igmp_snooping_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "robustness", value);
	return 0;
}

static int set_igmp_snooping_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "robustness", value);
			break;
	}

	return 0;
}

static int get_igmp_snooping_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "aggregation", &val);

	if (strcmp(val, "1") == 0)
		*value = "true";
	else
		*value = "false";

	return 0;
}

static int set_igmp_snooping_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "aggregation", (b) ? "1" : "0");
			break;
	}

	return 0;
}

static int get_igmp_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char val[16] = {0}, sec_name[16] = {0}; // taking 16 here is same as that is size of linux names usually supported
	char *val1;

	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &val1);

	// The value is linux interface name so it would be br-wan for example, but the network
	// section would be wan, so extract wan from br-wan
	char *tok, *end;

	strncpy(val, val1, sizeof(val) - 1);
	tok = strtok_r(val, "-", &end);
	if ((tok == NULL) || (end == NULL)) {
		return 0;
	}

	if (strcmp(tok, "br") != 0) {
		return 0;
	}

	strncpy(sec_name, end, sizeof(sec_name) - 1);
	// In the dmmap_network file, the details related to the instance id etc. associated with this bridge
	// is stored, we now switch our focus to it to extract the necessary information.
	struct uci_section *dmmap_section, *port;
	char *br_inst, *mg, linker[64] = "";

	get_dmmap_section_of_config_section("dmmap_network", "interface", sec_name, &dmmap_section);
	if (dmmap_section != NULL) {
		dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &br_inst);
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, port) {
			dmuci_get_value_by_section_string(port, "management", &mg);
			if (strcmp(mg, "1") == 0) {
				snprintf(linker, sizeof(linker), "br_%s:%s+", br_inst, section_name(port));
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot,
							dm_delim, dm_delim, dm_delim), linker, value);
				break;
			}
		}
	}

	if (*value == NULL)
		*value = "";

	return 0;
}

static int set_igmp_snooping_interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char ifname[16];
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string_list(value, -1, -1, 1024, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:

			if (get_igmp_snooping_interface_val(value, ifname, sizeof(ifname)) != 0)
				return -1;

			dmuci_set_value_by_section((struct uci_section *)data, "interface", ifname);
			break;
	}

	return 0;
}

static int add_igmpp_interface_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	// This section works but commented for now as it is tested not much yet.
	char *last_inst, *v;
	struct uci_section *dmmap_igmpp_interface = NULL;

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "proxy_interface", "iface_instance",
					"section_name", section_name((struct uci_section *)data));

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy_interface", &dmmap_igmpp_interface, &v);
	dmuci_set_value_by_section(dmmap_igmpp_interface, "section_name",
				section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_igmpp_interface, "upstream", "0");

	*instance = update_instance_bbfdm(dmmap_igmpp_interface, last_inst, "iface_instance");
	return 0;
}

static int del_igmpp_interface_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *d_sec = NULL;
	char *f_inst, *if_name, *upstream;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
					"section_name", section_name((struct uci_section *)data), d_sec) {
				dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);

				if (strcmp(instance, f_inst) == 0) {
					dmuci_get_value_by_section_string(d_sec, "ifname", &if_name);
					dmuci_get_value_by_section_string(d_sec, "upstream", &upstream);
					dmuci_delete_by_section(d_sec, NULL, NULL);
					found = 1;
				}

				if (found) {
					if (strcmp(upstream, "1") == 0) {
						dmuci_del_list_value_by_section((struct uci_section *)data,
								"upstream_interface", if_name);
					} else {
						dmuci_del_list_value_by_section((struct uci_section *)data,
								"downstream_interface", if_name);
					}
					break;
				}
			}

			break;
		case DEL_ALL:
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
					"section_name", section_name((struct uci_section *)data), d_sec) {
				dmuci_get_value_by_section_string(d_sec, "ifname", &if_name);
				dmuci_get_value_by_section_string(d_sec, "upstream", &upstream);
				if (if_name[0] != '\0') {
					if (strcmp(upstream, "1") == 0) {
						dmuci_del_list_value_by_section((struct uci_section *)data,
								"upstream_interface", if_name);
					} else {
						dmuci_del_list_value_by_section((struct uci_section *)data,
								"downstream_interface", if_name);
					}
				}
			}

			del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_interface",
				"section_name", section_name((struct uci_section *)data));
			break;
	}

	return 0;
}

static int browse_igmpp_interface_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL, *inst_last = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_mcast_iface("mcast", "proxy", prev_data,
			"dmmap_mcast", "proxy_interface", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if (!p->config_section)
			break;

		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3,
				p->dmmap_section, "iface_instance", "iface_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;

	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int add_igmpp_filter_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *last_inst, *v;
	struct uci_section *dmmap_igmpp_filter = NULL;

	last_inst = get_last_instance_lev2_bbfdm_dmmap_opt("dmmap_mcast", "proxy_filter", "filter_instance",
			"section_name", section_name((struct uci_section *)data));

	dmuci_add_section_bbfdm("dmmap_mcast", "proxy_filter", &dmmap_igmpp_filter, &v);
	dmuci_set_value_by_section(dmmap_igmpp_filter, "section_name",
			section_name((struct uci_section *)data));
	dmuci_set_value_by_section(dmmap_igmpp_filter, "enable", "0");

	*instance = update_instance_bbfdm(dmmap_igmpp_filter, last_inst, "filter_instance");

	return 0;
}

static int del_igmpp_filter_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *d_sec = NULL;
	char *f_inst, *ip_addr;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
					"section_name", section_name((struct uci_section *)data), d_sec) {
				dmuci_get_value_by_section_string(d_sec, "filter_instance", &f_inst);

				if (strcmp(instance, f_inst) == 0) {
					dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
					dmuci_delete_by_section(d_sec, NULL, NULL);
					found = 1;
				}

				if (found) {
					dmuci_del_list_value_by_section((struct uci_section *)data,
							"filter", ip_addr);
					break;
				}
			}

			break;
		case DEL_ALL:
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
					"section_name", section_name((struct uci_section *)data), d_sec) {
				dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
				if (ip_addr[0] != '\0')
					dmuci_del_list_value_by_section((struct uci_section *)data,
							"filter", ip_addr);
			}

			del_dmmap_sec_with_opt_eq("dmmap_mcast", "proxy_filter", "section_name",
					section_name((struct uci_section *)data));

			break;
	}

	return 0;
}

static int browse_igmpp_filter_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct dmmap_dup *p = NULL;
	char *inst = NULL, *inst_last = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap_filter("mcast", "proxy", prev_data, "dmmap_mcast",
			"proxy_filter", "igmp", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		if (!p->config_section)
			break;

		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3,
				p->dmmap_section, "filter_instance", "filter_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;

	}

	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int get_igmpp_interface_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface", "section_name",
			section_name((struct uci_section *)data), s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_igmpp_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *f_sec;
	char *f_inst, *f_enable;
	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
			"section_name", section_name((struct uci_section *)data), f_sec) {
		dmuci_get_value_by_section_string(f_sec, "filter_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(f_sec, "enable", &f_enable);
			break;
		}
	}

	if (strcmp(f_enable, "1") == 0) {
		*value = "true";
	} else {
		*value = "false";
	}

	return 0;
}

static int set_igmpp_filter_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *f_sec;
	char *f_inst, *ip_addr;
	bool b;
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
					"section_name", section_name((struct uci_section *)data), f_sec) {
				dmuci_get_value_by_section_string(f_sec, "filter_instance", &f_inst);
				if (strcmp(instance, f_inst) == 0) {
					dmuci_get_value_by_section_string(f_sec, "ipaddr", &ip_addr);
					dmuci_set_value_by_section(f_sec, "enable", (b) ? "1" : "0");
					sync_dmmap_bool_to_uci_list((struct uci_section *)data,
							"filter", ip_addr, b);
					break;
				}
			}
			break;
	}

	return 0;
}

static int get_igmpp_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec;
	char *f_inst, *ip_addr;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "filter_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "ipaddr", &ip_addr);
			break;
		}
	}

	if (ip_addr[0] == '\0') {
		*value = "";
	} else {
		*value = dmstrdup(ip_addr);
	}

	return 0;
}

static int set_igmpp_filter_address(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;
	char *s_inst, *up;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 15, NULL, 0, IPv4Address, 1))
				return FAULT_9007;

			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter",
					"section_name", section_name((struct uci_section *)data), s) {
				dmuci_get_value_by_section_string(s, "filter_instance", &s_inst);
				if (strcmp(s_inst, instance) == 0) {
					dmuci_set_value_by_section(s, "ipaddr", value);
					dmuci_get_value_by_section_string(s, "enable", &up);
					string_to_bool(up, &b);
					sync_dmmap_bool_to_uci_list((struct uci_section *)data,
							"filter", value, b);
					break;
				}

			}

			break;
	}

	return 0;
}

static int browse_igmps_cgrp_assoc_dev_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

static int browse_igmpp_cgrp_assoc_dev_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

static int browse_igmps_cgrp_stats_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}

static int browse_igmpp_cgrp_stats_inst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//ToDo
	return 0;
}
static int get_igmps_cgrp_gaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_gaddr(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_assoc_dev_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_assoc_dev_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_adev_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_adev_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_rsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_rsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_rrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_rrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_qsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_qsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_qrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_qrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_lsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_lsent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmps_cgrp_stats_lrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmpp_cgrp_stats_lrcvd(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int get_igmp_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", &val);

	if (strcmp(val, "1") == 0)
		*value = "true";
	else
		*value = "false";

	return 0;
}
static int set_igmp_proxy_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enable", (b) ? "1" : "0");
			break;
	}

	return 0;
}

static int get_igmp_proxy_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "version", &val);

	if (strcmp(val, "2") == 0)
		*value = "V2";
	else
		*value = "V3";

	return 0;
}

static int set_igmp_proxy_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char val[4];

	switch (action) {
		case VALUECHECK:
			if ((strcmp("V2", value) != 0) && (strcmp("V3", value) != 0))
				return FAULT_9007;
			break;
		case VALUESET:
			if (strcmp(value, "V2") == 0)
				strcpy(val, "2");
			else
				strcpy(val, "3");

			dmuci_set_value_by_section((struct uci_section *)data, "version", val);
			break;
	}

	return 0;
}

static int get_igmp_proxy_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "robustness", value);
	return 0;
}

static int get_igmpp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "query_interval", value);
	return 0;
}

static int get_igmpp_q_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "query_response_interval", value);
	return 0;
}

static int get_igmpp_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "last_member_query_interval", value);
	return 0;
}

static int set_igmpp_query_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "query_interval", value);
			break;
	}

	return 0;
}

static int set_igmpp_q_response_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "query_response_interval", value);
			break;
	}

	return 0;
}

static int set_igmpp_last_mq_interval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "last_member_query_interval", value);
			break;
	}

	return 0;
}

static int set_igmp_proxy_robustness(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "robustness", value);
			break;
	}

	return 0;
}

static int get_igmp_proxy_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "aggregation", &val);

	if (strcmp(val, "1") == 0)
		*value = "true";
	else
		*value = "false";

	return 0;
}

static int get_igmp_proxy_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *val;
	dmuci_get_value_by_section_string((struct uci_section *)data, "fast_leave", &val);

	if (strcmp(val, "1") == 0)
		*value = "true";
	else
		*value = "false";

	return 0;
}

static int set_igmp_proxy_fast_leave(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "fast_leave", (b) ? "1" : "0");
			break;
	}

	return 0;
}

static int set_igmp_proxy_aggregation(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "aggregation", (b) ? "1" : "0");
			break;
	}

	return 0;
}

static int get_igmpp_filter_no_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_filter", "section_name",
			section_name((struct uci_section *)data), s) {
		cnt++;
	}

	dmasprintf(value, "%d", cnt);
	return 0;
}

#if 0
static int get_igmpp_interface_snooping(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//ToDo
	return 0;
}

static int set_igmpp_interface_snooping(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	//ToDo
	return 0;
}
#endif

static int set_igmpp_interface_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker, *interface_linker = NULL;
	char ifname[16];
	char *up, *f_inst, *if_type;
	struct uci_section *d_sec, *s;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			// First check if this is a bridge type interface
			if (get_igmp_snooping_interface_val(value, ifname, sizeof(ifname)) == 0) {
				interface_linker = dmstrdup(ifname);
			} else {
				adm_entry_get_linker_value(ctx, value, &linker);
				uci_foreach_sections("network", "interface", s) {
					if(strcmp(section_name(s), linker) != 0) {
						continue;
					}
					dmuci_get_value_by_section_string(s, "type", &if_type);
					if (strcmp(if_type, "bridge") == 0)
						dmasprintf(&interface_linker, "br-%s", linker);
					else
						dmuci_get_value_by_section_string(s, "ifname", &interface_linker);
					break;
				}
			}
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
					"section_name", section_name((struct uci_section *)data), d_sec) {
				dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
				if (strcmp(instance, f_inst) == 0) {
					dmuci_set_value_by_section(d_sec, "ifname", interface_linker);
					dmuci_get_value_by_section_string(d_sec, "upstream", &up);
					string_to_bool(up, &b);
					sync_dmmap_bool_to_uci_list((struct uci_section *)data,
							"downstream_interface", interface_linker, !b);

					// Now update the proxy_interface list
					sync_dmmap_bool_to_uci_list((struct uci_section *)data,
							"upstream_interface", interface_linker, b);
					break;
				}
			}

			break;
	}

	return 0;
}

static int get_igmpp_interface_iface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec, *s;
	char *ifname, *f_inst;
	char sec_name[16] = {0};
	int found = 0;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "ifname", &ifname);
			found = 1;
			break;
		}
	}

	if ((found == 0) || (ifname[0] == '\0')) {
		*value = "";
		return 0;
	}

	// Check if this is bridge type interface
	if (strstr(ifname, "br-")) {
		// Interface is bridge type, convert to network uci file section name
		char val[16] = {0};
		strncpy(val, ifname, sizeof(val) - 1);
		char *tok, *end;
		tok = strtok_r(val, "-", &end);
		if (strcmp(tok, "br") == 0) {
			strncpy(sec_name, end, sizeof(sec_name) - 1);
		} else {
			goto end;
		}

		char *proto;
		uci_foreach_sections("network", "interface", s) {
			if(strcmp(section_name(s), sec_name) != 0)
				continue;

			dmuci_get_value_by_section_string(s, "proto", &proto);
			if (proto[0] != '\0') {
				// It is a L3 bridge, get the linker accordingly
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c",
					dmroot, dm_delim, dm_delim, dm_delim), sec_name, value);
			} else {
				// It is a L2 bridge, get the linker accordingly
				struct uci_section *dmmap_section, *port;
				char *br_inst, *mg, linker[64] = "";

				get_dmmap_section_of_config_section("dmmap_network", "interface", sec_name,
						&dmmap_section);
				if (dmmap_section != NULL) {
					dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &br_inst);
					uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port",
							"bridge_port", "bridge_key", br_inst, port) {
						dmuci_get_value_by_section_string(port, "mg_port", &mg);
						if (strcmp(mg, "true") == 0)
							snprintf(linker, sizeof(linker), "%s+", section_name(port));
						else
							continue;

						adm_entry_get_linker_param(ctx, dm_print_path("%s%cBridging%cBridge%c", dmroot,
									dm_delim, dm_delim, dm_delim), linker, value);
						break;
					}
				}
			}
			break;
		}
	} else {
		char *device_name, *tmp_linker = NULL;
		// it is a L3 interface, get the section name from device name to construct the linker
		uci_foreach_sections("network", "interface", s) {
			dmuci_get_value_by_section_string(s, "ifname", &device_name);
			if (strcmp(device_name, ifname) == 0) {
				tmp_linker = dmstrdup(section_name(s));
				break;
			}
		}

		if (tmp_linker == NULL)
			goto end;

		adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim,
					dm_delim, dm_delim), tmp_linker, value);
	}

end:
	if (*value == NULL)
		*value = "";

	return 0;
}

static int set_igmpp_interface_upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *f_inst, *ifname;
	struct uci_section *d_sec;
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
					"section_name", section_name((struct uci_section *)data), d_sec) {
				dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
				if (strcmp(instance, f_inst) == 0) {
					dmuci_get_value_by_section_string(d_sec, "ifname", &ifname);
					dmuci_set_value_by_section(d_sec, "upstream", (b) ? "1" : "0");

					sync_dmmap_bool_to_uci_list((struct uci_section *)data,
							"downstream_interface", ifname, !b);
					sync_dmmap_bool_to_uci_list((struct uci_section *)data,
							"upstream_interface", ifname, b);
					break;
				}
			}

			break;
	}
	return 0;
}

static int get_igmpp_interface_upstream(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *d_sec;
	char *f_inst, *up;

	uci_path_foreach_option_eq(bbfdm, "dmmap_mcast", "proxy_interface",
			"section_name", section_name((struct uci_section *)data), d_sec) {
		dmuci_get_value_by_section_string(d_sec, "iface_instance", &f_inst);
		if (strcmp(instance, f_inst) == 0) {
			dmuci_get_value_by_section_string(d_sec, "upstream", &up);
			break;
		}
	}

	if (strcmp(up, "1") == 0) {
		*value = "true";
	} else {
		*value = "false";
	}

	return 0;
}

/* ***Device.X_IOPSYS_EU_IGMP. *** */
DMOBJ X_IOPSYS_EU_IGMPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Snooping", &DMWRITE, add_igmp_snooping_obj, del_igmp_snooping_obj, NULL, browse_igmp_snooping_inst, NULL, NULL, NULL, X_IOPSYS_EU_IGMPSnoopingObj, X_IOPSYS_EU_IGMPSnoopingParams, NULL, BBFDM_BOTH},
{"Proxy", &DMWRITE, add_igmp_proxy_obj, del_igmp_proxy_obj, NULL, browse_igmp_proxy_inst, NULL, NULL, NULL, X_IOPSYS_EU_IGMPProxyObj, X_IOPSYS_EU_IGMPProxyParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_IGMPParams[] = {
{"SnoopingNumberOfEntries", &DMREAD, DMT_UNINT, get_igmps_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"ProxyNumberOfEntries", &DMREAD, DMT_UNINT, get_igmpp_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ X_IOPSYS_EU_IGMPSnoopingObj[] = {
{"ClientGroup", &DMREAD, NULL, NULL, NULL, browse_igmps_cgrp_inst, NULL, NULL, NULL, IGMPSnoopingCLientGroupObj, IGMPSnoopingClientGroupParams, NULL, BBFDM_BOTH},
{"Filter", &DMWRITE, add_igmps_filter_obj, del_igmps_filter_obj, NULL, browse_igmps_filter_inst, NULL, NULL, NULL, NULL, IGMPSnoopingFilterParams, NULL, BBFDM_BOTH},
{0}
};

DMOBJ IGMPSnoopingCLientGroupObj[] = {
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_igmps_cgrp_assoc_dev_inst, NULL, NULL, NULL, NULL, IGMPSnoopingClientGroupAssociatedDeviceParams, NULL, BBFDM_BOTH},
{"ClientGroupStats", &DMREAD, NULL, NULL, NULL, browse_igmps_cgrp_stats_inst, NULL, NULL, NULL, NULL, IGMPSnoopingClientGroupStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPSnoopingClientGroupParams[] = {
{"GroupAddress", &DMREAD, DMT_STRING, get_igmps_cgrp_gaddr, NULL, NULL, NULL, BBFDM_BOTH},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_igmps_cgrp_assoc_dev_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPSnoopingFilterParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_igmps_filter_enable, set_igmps_filter_enable, NULL, NULL, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_igmps_filter_address, set_igmps_filter_address, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPSnoopingClientGroupAssociatedDeviceParams[] = {
{"Interface", &DMREAD, DMT_STRING, get_igmps_cgrp_adev_iface, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPSnoopingClientGroupStatsParams[] = {
{"ReportsSent", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_rsent, NULL, NULL, NULL, BBFDM_BOTH},
{"ReportsReceived", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_rrcvd, NULL, NULL, NULL, BBFDM_BOTH},
{"QueriesSent", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_qsent, NULL, NULL, NULL, BBFDM_BOTH},
{"QueriesReceived", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_qrcvd, NULL, NULL, NULL, BBFDM_BOTH},
{"LeavesSent", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_lsent, NULL, NULL, NULL, BBFDM_BOTH},
{"LeavesReceived", &DMREAD, DMT_UNINT, get_igmps_cgrp_stats_lrcvd, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_IGMPSnoopingParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_igmp_snooping_enable, set_igmp_snooping_enable, NULL, NULL, BBFDM_BOTH},
{"Version", &DMWRITE, DMT_STRING, get_igmp_snooping_version, set_igmp_snooping_version, NULL, NULL, BBFDM_BOTH},
{"Robustness", &DMWRITE, DMT_UNINT, get_igmp_snooping_robustness, set_igmp_snooping_robustness, NULL, NULL, BBFDM_BOTH},
{"Aggregation", &DMWRITE, DMT_BOOL, get_igmp_snooping_aggregation, set_igmp_snooping_aggregation, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_igmp_snooping_interface, set_igmp_snooping_interface, NULL, NULL, BBFDM_BOTH},
{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_igmps_filter_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
//{"ClientGroupNumberOfEntries", &DMREAD, DMT_UNINT, get_igmpp_cgrps_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMOBJ X_IOPSYS_EU_IGMPProxyObj[] = {
{"Interface", &DMWRITE, add_igmpp_interface_obj, del_igmpp_interface_obj, NULL, browse_igmpp_interface_inst, NULL, NULL, NULL, NULL, IGMPProxyInterfaceParams, NULL, BBFDM_BOTH},
//{"ClientGroup", &DMREAD, NULL, NULL, NULL, browse_igmpp_cgrp_inst, NULL, NULL, NULL, IGMPProxyCLientGroupObj, IGMPProxyClientGroupParams, NULL, BBFDM_BOTH},
{"Filter", &DMWRITE, add_igmpp_filter_obj, del_igmpp_filter_obj, NULL, browse_igmpp_filter_inst, NULL, NULL, NULL, NULL, IGMPProxyFilterParams, NULL, BBFDM_BOTH},
{0}
};

DMOBJ IGMPProxyCLientGroupObj[] = {
{"AssociatedDevice", &DMREAD, NULL, NULL, NULL, browse_igmpp_cgrp_assoc_dev_inst, NULL, NULL, NULL, NULL, IGMPProxyClientGroupAssociatedDeviceParams, NULL, BBFDM_BOTH},
{"ClientGroupStats", &DMREAD, NULL, NULL, NULL, browse_igmpp_cgrp_stats_inst, NULL, NULL, NULL, NULL, IGMPProxyClientGroupStatsParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyClientGroupParams[] = {
{"GroupAddress", &DMREAD, DMT_STRING, get_igmpp_cgrp_gaddr, NULL, NULL, NULL, BBFDM_BOTH},
{"AssociatedDeviceNumberOfEntries", &DMREAD, DMT_UNINT, get_igmpp_cgrp_assoc_dev_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyFilterParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_igmpp_filter_enable, set_igmpp_filter_enable, NULL, NULL, BBFDM_BOTH},
{"IPAddress", &DMWRITE, DMT_STRING, get_igmpp_filter_address, set_igmpp_filter_address, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyClientGroupAssociatedDeviceParams[] = {
{"Interface", &DMREAD, DMT_STRING, get_igmpp_cgrp_adev_iface, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyClientGroupStatsParams[] = {
{"ReportsSent", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_rsent, NULL, NULL, NULL, BBFDM_BOTH},
{"ReportsReceived", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_rrcvd, NULL, NULL, NULL, BBFDM_BOTH},
{"QueriesSent", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_qsent, NULL, NULL, NULL, BBFDM_BOTH},
{"QueriesReceived", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_qrcvd, NULL, NULL, NULL, BBFDM_BOTH},
{"LeavesSent", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_lsent, NULL, NULL, NULL, BBFDM_BOTH},
{"LeavesReceived", &DMREAD, DMT_UNINT, get_igmpp_cgrp_stats_lrcvd, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF IGMPProxyInterfaceParams[] = {
{"Interface", &DMWRITE, DMT_STRING, get_igmpp_interface_iface, set_igmpp_interface_iface, NULL, NULL, BBFDM_BOTH},
{"Upstream", &DMWRITE, DMT_BOOL, get_igmpp_interface_upstream, set_igmpp_interface_upstream, NULL, NULL, BBFDM_BOTH},
//{"Snooping", &DMWRITE, DMT_STRING, get_igmpp_interface_snooping, set_igmpp_interface_snooping, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF X_IOPSYS_EU_IGMPProxyParams[] = {
{"Enable", &DMWRITE, DMT_BOOL, get_igmp_proxy_enable, set_igmp_proxy_enable, NULL, NULL, BBFDM_BOTH},
{"Version", &DMWRITE, DMT_STRING, get_igmp_proxy_version, set_igmp_proxy_version, NULL, NULL, BBFDM_BOTH},
{"QueryInterval",&DMWRITE, DMT_UNINT, get_igmpp_query_interval, set_igmpp_query_interval, NULL, NULL, BBFDM_BOTH},
{"QueryResponseInterval",&DMWRITE, DMT_UNINT, get_igmpp_q_response_interval, set_igmpp_q_response_interval, NULL, NULL, BBFDM_BOTH},
{"LastMemberQueryInterval",&DMWRITE, DMT_UNINT, get_igmpp_last_mq_interval, set_igmpp_last_mq_interval, NULL, NULL, BBFDM_BOTH},
{"ImmediateLeave", &DMWRITE, DMT_BOOL, get_igmp_proxy_fast_leave, set_igmp_proxy_fast_leave, NULL, NULL, BBFDM_BOTH},
{"Robustness", &DMWRITE, DMT_UNINT, get_igmp_proxy_robustness, set_igmp_proxy_robustness, NULL, NULL, BBFDM_BOTH},
{"Aggregation", &DMWRITE, DMT_BOOL, get_igmp_proxy_aggregation, set_igmp_proxy_aggregation, NULL, NULL, BBFDM_BOTH},
{"FilterNumberOfEntries", &DMREAD, DMT_UNINT, get_igmpp_filter_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{"InterfaceNumberOfEntries", &DMREAD, DMT_UNINT, get_igmpp_interface_no_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
