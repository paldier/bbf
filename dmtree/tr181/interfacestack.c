/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dmentry.h"
#include "interfacestack.h"

struct interfacestack_data {
	char *lowerlayer;
	char *higherlayer;
	char *loweralias;
	char *higheralias;
};

/*************************************************************
* ENTRY METHOD
**************************************************************/
static char *get_instance_by_section(int mode, char *dmmap_config, char *section, struct uci_section *s, char *instance_option, char *alias_option)
{
	struct uci_section *dmmap_section;
	char *instance = "";

	get_dmmap_section_of_config_section(dmmap_config, section, section_name(s), &dmmap_section);

	if (mode == INSTANCE_MODE_NUMBER)
		dmuci_get_value_by_section_string(dmmap_section, instance_option, &instance);
	else
		dmuci_get_value_by_section_string(dmmap_section, alias_option, &instance);

	return instance;
}

static char *get_alias_by_section(char *dmmap_config, char *section, struct uci_section *s, char *alias_option)
{
	struct uci_section *dmmap_section;
	char *alias = "";

	get_dmmap_section_of_config_section(dmmap_config, section, section_name(s), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, alias_option, &alias);
	return alias;
}

static struct uci_section *create_dmmap_interface_stack_section(char *curr_inst)
{
	struct uci_section *s = NULL;
	char *name;

	check_create_dmmap_package("dmmap_interface_stack");
	uci_path_foreach_option_eq(bbfdm, "dmmap_interface_stack", "interface_stack", "interface_stack_instance", curr_inst, s) {
		return s;
	}
	if (!s) {
		dmuci_add_section_bbfdm("dmmap_interface_stack", "interface_stack", &s, &name);
		dmuci_set_value_by_section_bbfdm(s, "interface_stack_instance", curr_inst);
	}
	return s;
}

int browseInterfaceStackInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct interfacestack_data intf_stack_data = {0};
	struct uci_section *s = NULL, *dmmap_s = NULL;
	char *layer_inst = "", *loweralias = "", *higheralias = "";
	char *intf_stack_inst = NULL, *intf_stack_last = NULL;
	char buf_lowerlayer[128] = {0};
	char buf_higherlayer[128] = {0};
	char buf_higheralias[64] = {0};
	char buf_loweralias[64] = {0};
	char buf_instance[16] = {0};
	int instance = 0;

	/* Higher layers are Device.IP.Interface.{i}. */
	uci_foreach_sections("network", "interface", s) {
		char *proto;
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (strcmp(section_name(s), "loopback") == 0 || *proto == '\0')
			continue;

		// The higher layer is Device.IP.Interface.{i}.
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", s, "ip_int_instance", "ip_int_alias");
		if (*layer_inst == '\0')
			continue;
		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.IP.Interface.%s.", layer_inst);

		higheralias = get_alias_by_section("dmmap_network", "interface", s, "ip_int_alias");
		if (*higheralias == '\0')
			snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", higheralias);

		if (strstr(proto, "ppp")) {
			// The lower layer is Device.PPP.Interface.{i}.
			layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", s, "ppp_int_instance", "ppp_int_alias");
			if (*layer_inst == '\0')
				continue;
			snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "Device.PPP.Interface.%s.", layer_inst);
			loweralias = get_alias_by_section("dmmap_network", "interface", s, "ppp_int_alias");
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
		} else {
			// The lower layer is Device.Ethernet.VLANTermination.{i}.
			char *value = NULL;
			int found = 0;
			char *device = get_device(section_name(s));
			if (device[0] != '\0') {
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cVLANTermination%c", dmroot, dm_delim, dm_delim, dm_delim), device, &value);
				loweralias = get_alias_by_section("dmmap_network", "device", s, "vlan_term_alias");
				layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", s, "vlan_term_instance", "vlan_term_alias");
				if (value != NULL)
					found = 1;
			}

			if (device[0] != '\0' && found == 0) {
				// The lower layer is Device.Ethernet.Link.{i}.
				char linker[32] = {0};
				strncpy(linker, device, sizeof(linker) - 1);
				char *vid = strchr(linker, '.');
				if (vid) *vid = '\0';
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &value);
				loweralias = get_alias_by_section("dmmap", "link", s, "link_alias");
				layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "link", s, "link_instance", "link_alias");
				if (value == NULL)
					value = "";
			}

			snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", value);
			if (*loweralias == '\0')
				snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", layer_inst);
			else
				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
		}

		// fill interface stack data
		intf_stack_data.higherlayer = buf_higherlayer;
		intf_stack_data.lowerlayer = buf_lowerlayer;
		intf_stack_data.higheralias = buf_higheralias;
		intf_stack_data.loweralias = buf_loweralias;

		// create dmmap section
		snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
		dmmap_s = create_dmmap_interface_stack_section(buf_instance);

		// link instance to interface stack data
		intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
			goto end;
	}

	/* Higher layers are Device.PPP.Interface.{i}. */
	uci_foreach_sections("network", "interface", s) {
		char *proto;
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (!strstr(proto, "ppp"))
			continue;

		// The higher layer is Device.PPP.Interface.{i}.
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", s, "ppp_int_instance", "ppp_int_alias");
		if (*layer_inst == '\0')
			continue;
		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.PPP.Interface.%s.", layer_inst);

		higheralias = get_alias_by_section("dmmap_network", "interface", s, "ppp_int_alias");
		if (*higheralias == '\0')
			snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", higheralias);

		char *value = NULL;
		int found = 0;
		// The lower layer is Device.Ethernet.VLANTermination.{i}.
		char *device = get_device(section_name(s));
		if (device[0] != '\0') {
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cVLANTermination%c", dmroot, dm_delim, dm_delim, dm_delim), device, &value);
			loweralias = get_alias_by_section("dmmap_network", "device", s, "vlan_term_alias");
			layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", s, "vlan_term_instance", "vlan_term_alias");
			if (value != NULL)
				found = 1;
		}

		if (device[0] != '\0' && found == 0) {
			// The lower layer is Device.Ethernet.Link.{i}.
			char linker[32] = {0};
			strncpy(linker, device, sizeof(linker) - 1);
			char *vid = strchr(linker, '.');
			if (vid) *vid = '\0';
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &value);
			loweralias = get_alias_by_section("dmmap", "link", s, "link_alias");
			layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "link", s, "link_instance", "link_alias");
			if (value == NULL)
				value = "";
		}

		snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", value);
		if (*loweralias == '\0')
			snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

		// fill interface stack data
		intf_stack_data.higherlayer = buf_higherlayer;
		intf_stack_data.lowerlayer = buf_lowerlayer;
		intf_stack_data.higheralias = buf_higheralias;
		intf_stack_data.loweralias = buf_loweralias;

		// create dmmap section
		snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
		dmmap_s = create_dmmap_interface_stack_section(buf_instance);

		// link instance to interface stack data
		intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
			goto end;
	}

	/* Higher layers are Device.Ethernet.VLANTermination.{i}. */
	uci_foreach_sections("network", "device", s) {
		char *type, *name, *value = NULL;
		dmuci_get_value_by_section_string(s, "type", &type);
		dmuci_get_value_by_section_string(s, "name", &name);
		if (strcmp(type, "untagged") == 0 || (*name != '\0' && !is_vlan_termination_section(name)))
			continue;

		// The higher layer is Device.Ethernet.VLANTermination.{i}.
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", s, "vlan_term_instance", "vlan_term_alias");
		if (*layer_inst == '\0')
			continue;

		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.Ethernet.VLANTermination.%s.", layer_inst);

		higheralias = get_alias_by_section("dmmap_network", "device", s, "vlan_term_alias");
		if (*higheralias == '\0')
			snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", higheralias);

		// The lower layer is Device.Ethernet.Link.{i}.
		char *vid = strchr(name, '.');
		if (vid) *vid = '\0';
		adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), name, &value);
		if (value == NULL)
			value = "";

		struct uci_section *link_s = NULL;
		get_dmmap_section_of_config_section_eq("dmmap", "link", "device", name, &link_s);
		dmuci_get_value_by_section_string(link_s, "link_instance", &layer_inst);
		dmuci_get_value_by_section_string(link_s, "link_alias", &loweralias);

		snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", value);
		if (*loweralias == '\0')
			snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

		// fill interface stack data
		intf_stack_data.higherlayer = buf_higherlayer;
		intf_stack_data.lowerlayer = buf_lowerlayer;
		intf_stack_data.higheralias = buf_higheralias;
		intf_stack_data.loweralias = buf_loweralias;

		// create dmmap section
		snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
		dmmap_s = create_dmmap_interface_stack_section(buf_instance);

		// link instance to interface stack data
		intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
			goto end;
	}

	/* Higher layers are Device.Ethernet.Link.{i}. */
	uci_path_foreach_sections(bbfdm, DMMAP, "link", s) {

		// The higher layer is Device.Ethernet.Link.{i}.
		dmuci_get_value_by_section_string(s, "link_instance", &layer_inst);
		if (*layer_inst == '\0')
			continue;

		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.Ethernet.Link.%s.", layer_inst);

		dmuci_get_value_by_section_string(s, "link_alias", &higheralias);
		if (*higheralias == '\0')
			snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", higheralias);


		char *linker, *value = NULL;
		dmuci_get_value_by_section_string(s, "device", &linker);
		char *bridge = strstr(linker, "br-");
		if (bridge) {
			// The lower layer is Device.Bridging.Bridge.{i}.Port.{i}.
			char *int_name;
			dmuci_get_value_by_section_string(s, "section_name", &int_name);
			struct uci_section *dmmap_section, *port;
			get_dmmap_section_of_config_section("dmmap_network", "interface", int_name, &dmmap_section);
			if (dmmap_section != NULL) {
				char *br_inst, *mg;
				dmuci_get_value_by_section_string(dmmap_section, "bridge_instance", &br_inst);
				uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, port) {
					dmuci_get_value_by_section_string(port, "management", &mg);
					if (strcmp(mg, "1") == 0) {
						char *device, linker[512] = "";
						dmuci_get_value_by_section_string(port, "device", &device);
						snprintf(linker, sizeof(linker), "br_%s:%s+%s", br_inst, section_name(port), device);
						adm_entry_get_linker_param(dmctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &value);
						break;
					}
				}
			}
		} else {
			// The lower layer is Device.Ethernet.Interface.{i}.
			char *vid = strchr(linker, '.');
			if (vid) *vid = '\0';
			char *macvlan = strchr(linker, '_');
			if (macvlan) *macvlan = '\0';
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &value);
		}

		if (value == NULL)
			value = "";

		snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", value);
		if (*loweralias == '\0')
			snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

		// fill interface stack data
		intf_stack_data.higherlayer = buf_higherlayer;
		intf_stack_data.lowerlayer = buf_lowerlayer;
		intf_stack_data.higheralias = buf_higheralias;
		intf_stack_data.loweralias = buf_loweralias;

		// create dmmap section
		snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
		dmmap_s = create_dmmap_interface_stack_section(buf_instance);

		// link instance to interface stack data
		intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
			goto end;
	}

	/* Higher layers are Device.Bridging.Bridge.{i}.Port.{i}.*/
	uci_foreach_sections("network", "interface", s) {
		char *type;
		dmuci_get_value_by_section_string(s, "type", &type);
		if (strcmp(type, "bridge") != 0)
			continue;

		char *br_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", s, "bridge_instance", "bridge_alias");
		if (*br_inst == '\0')
			continue;

		// The higher layer is Device.Bridging.Bridge.{i}.Port.{i}.
		char *bridge_port_inst, *mg_value = NULL,*value = NULL;
		char buf_mngr[64] = {0};
		struct uci_section *port = NULL;
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, port) {
			char *mg;
			dmuci_get_value_by_section_string(port, "management", &mg);
			if (strcmp(mg, "1") == 0) {
				char *device, linker[512] = {0};
				dmuci_get_value_by_section_string(port, "device", &device);
				snprintf(linker, sizeof(linker), "br_%s:%s+%s", br_inst, section_name(port), device);
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &mg_value);
				dmuci_get_value_by_section_string(port, "bridge_port_alias", &higheralias);
				dmuci_get_value_by_section_string(port, "bridge_port_instance", &bridge_port_inst);
				if (*higheralias == '\0')
					snprintf(buf_mngr, sizeof(buf_mngr), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_mngr, sizeof(buf_mngr), "%s", higheralias);

				if (mg_value == NULL)
					mg_value = "";
				break;
			}
		}

		struct uci_section *sd = NULL;
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "br_inst", br_inst, sd) {
			char *mg;
			dmuci_get_value_by_section_string(sd, "management", &mg);
			if (strcmp(mg, "1") == 0)
				continue;

			char *vb = NULL, *device, linker[512] = {0};
			dmuci_get_value_by_section_string(sd, "device", &device);

			// The lower layer is Device.Bridging.Bridge.{i}.Port.{i}.
			snprintf(linker, sizeof(linker), "br_%s:%s+%s", br_inst, section_name(sd), device);
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &vb);

			if (vb == NULL)
				vb = "";

			dmuci_get_value_by_section_string(sd, "bridge_port_alias", &loweralias);
			bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_bridge_port", "bridge_port", sd, "bridge_port_instance", "bridge_port_alias");
			if (*loweralias == '\0')
				snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
			else
				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

			// fill interface stack data
			intf_stack_data.higherlayer = mg_value;
			intf_stack_data.lowerlayer = vb;
			intf_stack_data.higheralias = buf_mngr;
			intf_stack_data.loweralias = buf_loweralias;

			// create dmmap section
			snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
			dmmap_s = create_dmmap_interface_stack_section(buf_instance);

			// link instance to interface stack data
			intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
				goto end;

			if (*loweralias == '\0')
				snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", bridge_port_inst);
			else
				snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", loweralias);

			char package[32] = {0};
			int found = 0;
			// The lower layer is Device.Ethernet.Interface.{i}.
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), device, &value);

			if (value != NULL) {
				strncpy(package, "ports", sizeof(package) - 1);
				struct uci_section *port_s = NULL;
				uci_foreach_option_eq("ports", "ethport", "ifname", device, port_s) {
					loweralias = get_alias_by_section("dmmap_ports", "ethport", port_s, "eth_port_alias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_ports", "ethport", port_s, "eth_port_instance", "eth_port_alias");
					break;
				}
				found = 1;
			}

			// The lower layer is Device.WiFi.SSID.{i}.
			if (!found && value == NULL)
				adm_entry_get_linker_param(dmctx,dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), device, &value);

			if (!found && value != NULL) {
				strncpy(package, "wireless", sizeof(package) - 1);
				struct uci_section *wl_s = NULL;
				uci_foreach_option_eq("wireless", "wifi-iface", "ifname", device, wl_s) {
					loweralias = get_alias_by_section("dmmap_wireless", "wifi-iface", wl_s, "ssidalias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_wireless", "wifi-iface", wl_s, "ssidinstance", "ssidalias");
					break;
				}
				found = 1;
			}

			// The lower layer is Device.ATM.Link.{i}.
			if (!found && value == NULL) {
				char *tag = strchr(device, '.');
				if (tag) *tag = '\0';
				adm_entry_get_linker_param(dmctx,dm_print_path("%s%cATM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), device, &value);
			}

			if (!found && value != NULL) {
				strncpy(package, "dsl:atm", sizeof(package) - 1);
				struct uci_section *dsl_s = NULL;
				uci_foreach_option_eq("dsl", "atm-device", "device", device, dsl_s) {
					loweralias = get_alias_by_section("dmmap_dsl", "atm-device", dsl_s, "atmlinkalias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_dsl", "atm-device", dsl_s, "atmlinkinstance", "atmlinkalias");
					break;
				}
				found = 1;
			}

			// The lower layer is Device.PTM.Link.{i}.
			if (!found && value == NULL) {
				char *tag = strchr(device, '.');
				if (tag) *tag = '\0';
				adm_entry_get_linker_param(dmctx,dm_print_path("%s%cPTM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), device, &value);
			}

			if (!found && value != NULL) {
				strncpy(package, "dsl:ptm", sizeof(package) - 1);
				struct uci_section *dsl_s = NULL;
				uci_foreach_option_eq("dsl", "ptm-device", "device", device, dsl_s) {
					loweralias = get_alias_by_section("dmmap_dsl", "ptm-device", dsl_s, "ptmlinkalias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_dsl", "ptm-device", dsl_s, "ptmlinkinstance", "ptmlinkalias");
					break;
				}
				found = 1;
			}

			// The lower layer is Device.Ethernet.Interface.{i}.
			if (!found && value == NULL) {
				char *tag = strchr(device, '.');
				if (tag) *tag = '\0';
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), device, &value);
			}

			if (!found && value != NULL) {
				strncpy(package, "ports", sizeof(package) - 1);
				struct uci_section *port_s = NULL;
				uci_foreach_option_eq("ports", "ethport", "ifname", device, port_s) {
					loweralias = get_alias_by_section("dmmap_ports", "ethport", port_s, "eth_port_alias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_ports", "ethport", port_s, "eth_port_instance", "eth_port_alias");
					break;
				}
			}

			if (*loweralias == '\0')
				snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
			else
				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

			if (value == NULL)
				value = "";

			// fill interface stack data
			intf_stack_data.higherlayer = vb;
			intf_stack_data.lowerlayer = value;
			intf_stack_data.higheralias = buf_higheralias;
			intf_stack_data.loweralias = buf_loweralias;

			// create dmmap section
			snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
			dmmap_s = create_dmmap_interface_stack_section(buf_instance);

			// link instance to interface stack data
			intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
				goto end;

			// The lower layer is Device.WiFi.Radio.{i}.
			if(strcmp(package, "wireless") == 0) {
				if (*loweralias == '\0')
					snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", loweralias);

				struct uci_section *wl_s = NULL;
				char *wl_device;
				uci_foreach_option_eq("wireless", "wifi-iface", "ifname", device, wl_s) {
					dmuci_get_value_by_section_string(wl_s, "device", &wl_device);
					break;
				}

				if (wl_device[0] != '\0') {
					adm_entry_get_linker_param(dmctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), wl_device, &vb);
					struct uci_section *ss = NULL;
					uci_foreach_sections("wireless", "wifi-device", ss) {
						if(strcmp(section_name(ss), device) == 0) {
							loweralias = get_alias_by_section("dmmap_wireless", "wifi-device", ss, "radioalias");
							bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_wireless", "wifi-device", ss, "radioinstance", "radioalias");
							break;
						}
					}
				}

				if (vb == NULL)
					vb = "";

				if (*loweralias == '\0')
					snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

				// fill interface stack data
				intf_stack_data.higherlayer = value;
				intf_stack_data.lowerlayer = vb;
				intf_stack_data.higheralias = buf_higheralias;
				intf_stack_data.loweralias = buf_loweralias;

				// create dmmap section
				snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
				dmmap_s = create_dmmap_interface_stack_section(buf_instance);

				// link instance to interface stack data
				intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
					goto end;
			}

			// The lower layer is Device.DSL.Channel.{i}.
			if(strcmp(package, "dsl:atm") == 0) {
				if (*loweralias == '\0')
					snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", loweralias);

				char *link_channel = "channel_0";
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cDSL%cChannel%c", dmroot, dm_delim, dm_delim, dm_delim), link_channel, &vb);
				if (vb == NULL)
					vb = "";

				struct uci_section *dsl_s = NULL;
				uci_path_foreach_sections(bbfdm, "dmmap", "dsl_channel", dsl_s) {
					dmuci_get_value_by_section_string(dsl_s, "dsl_channel_alias", &loweralias);
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "dsl_channel", dsl_s, "dsl_channel_instance", "dsl_channel_alias");
				}

				if (*loweralias == '\0')
					snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

				// fill interface stack data
				intf_stack_data.higherlayer = value;
				intf_stack_data.lowerlayer = vb;
				intf_stack_data.higheralias = buf_higheralias;
				intf_stack_data.loweralias = buf_loweralias;

				// create dmmap section
				snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
				dmmap_s = create_dmmap_interface_stack_section(buf_instance);

				// link instance to interface stack data
				intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
					goto end;

			}

			// The lower layer is Device.DSL.Line.{i}.
			if(strcmp(package, "dsl:ptm") == 0) {
				if (*loweralias == '\0')
					snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", loweralias);

				char *link_line = "line_0";
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cDSL%cLine%c", dmroot, dm_delim, dm_delim, dm_delim), link_line, &value);
				if (value == NULL)
					value = "";

				struct uci_section *dsl_s = NULL;
				uci_path_foreach_sections(bbfdm, "dmmap", "dsl_line", dsl_s) {
					dmuci_get_value_by_section_string(dsl_s, "dsl_line_alias", &loweralias);
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "dsl_line", dsl_s, "dsl_line_instance", "dsl_line_alias");
				}

				if (*loweralias == '\0')
					snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

				// fill interface stack data
				intf_stack_data.higherlayer = vb;
				intf_stack_data.lowerlayer = value;
				intf_stack_data.higheralias = buf_higheralias;
				intf_stack_data.loweralias = buf_loweralias;

				// create dmmap section
				snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
				dmmap_s = create_dmmap_interface_stack_section(buf_instance);

				// link instance to interface stack data
				intf_stack_inst = handle_update_instance(1, dmctx, &intf_stack_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&intf_stack_data, intf_stack_inst) == DM_STOP)
					goto end;
			}
		}
	}

end:
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
int get_Device_InterfaceStackNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_path_foreach_sections(bbfdm, "dmmap_interface_stack", "interface_stack", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_InterfaceStack_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	uci_path_foreach_option_eq(bbfdm, "dmmap_interface_stack", "interface_stack", "interface_stack_instance", instance, s) {
		dmuci_get_value_by_section_string(s, "interface_stack_alias", value);
		if ((*value)[0] == '\0')
			dmasprintf(value, "cpe-%s", instance);
	}
	return 0;
}

static int set_InterfaceStack_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			uci_path_foreach_option_eq(bbfdm, "dmmap_interface_stack", "interface_stack", "interface_stack_instance", instance, s)
				dmuci_set_value_by_section(s, "interface_stack_alias", value);
			break;
	}
	return 0;
}

static int get_InterfaceStack_HigherLayer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct interfacestack_data *)data)->higherlayer);
	return 0;
}

static int get_InterfaceStack_LowerLayer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct interfacestack_data *)data)->lowerlayer);
	return 0;
}

static int get_InterfaceStack_HigherAlias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct interfacestack_data *)data)->higheralias);
	return 0;
}

static int get_InterfaceStack_LowerAlias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(((struct interfacestack_data *)data)->loweralias);
	return 0;
}

/* *** Device.InterfaceStack.{i}. *** */
DMLEAF tInterfaceStackParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_InterfaceStack_Alias, set_InterfaceStack_Alias, NULL, NULL, BBFDM_BOTH},
{"HigherLayer", &DMREAD, DMT_STRING, get_InterfaceStack_HigherLayer, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerLayer", &DMREAD, DMT_STRING, get_InterfaceStack_LowerLayer, NULL, NULL, NULL, BBFDM_BOTH},
{"HigherAlias", &DMREAD, DMT_STRING, get_InterfaceStack_HigherAlias, NULL, NULL, NULL, BBFDM_BOTH},
{"LowerAlias", &DMREAD, DMT_STRING, get_InterfaceStack_LowerAlias, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
