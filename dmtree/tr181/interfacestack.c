/*
 * Copyright (C) 2019 iopsys Software Solutions AB
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
	char *instance;

	get_dmmap_section_of_config_section(dmmap_config, section, section_name(s), &dmmap_section);
	if (mode == INSTANCE_MODE_NUMBER) {
		dmuci_get_value_by_section_string(dmmap_section, instance_option, &instance);
	} else {
		dmuci_get_value_by_section_string(dmmap_section, alias_option, &instance);
	}
	return instance;
}

static char *get_alias_by_section(char *dmmap_config, char *section, struct uci_section *s, char *alias_option)
{
	struct uci_section *dmmap_section;
	char *alias;

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
	struct interfacestack_data ifdata = {0};
	struct uci_section *s = NULL, *port = NULL, *port_s = NULL, *ss = NULL, *dmmap_s = NULL;
	char *proto, *type, *pch, *layer_inst, *vb, *higheralias, *ifname, *br_inst, *mg, *value, *device, *name, *bridge_port_inst;
	char *loweralias = "", *v = "";
	char *interface_stack_int = NULL, *interface_stack_int_last = NULL, *wanifname, *mac;
	char buf_lowerlayer[128] = {0};
	char buf_higherlayer[128] = {0};
	char buf_higheralias[64] = {0};
	char buf_loweralias[64] = {0};
	char buf_instance[32] = {0};
	char linker[64] = {0};
	char buf_tmp[64] = {0};
	int instance = 0, found = 0;

	/* Higher layers are Device.IP.Interface.{i}. */
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (strcmp(section_name(s), "loopback") == 0 || *proto == '\0')
			continue;
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
			layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", s, "ppp_int_instance", "ppp_int_alias");
			if (*layer_inst == '\0')
				continue;
			snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "Device.PPP.Interface.%s.", layer_inst);
			loweralias = get_alias_by_section("dmmap_network", "interface", s, "ppp_int_alias");
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
		} else {
			device = get_device(section_name(s));
			if (device[0] != '\0') {
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cVLANTermination%c", dmroot, dm_delim, dm_delim, dm_delim), device, &v);
				loweralias = get_alias_by_section("dmmap_network", "device", s, "vlan_term_alias");
				layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", s, "vlan_term_instance", "vlan_term_alias");
				if (v != NULL)
					found = 1;
			}
			mac = get_macaddr(section_name(s));
			if (mac[0] != '\0' && found == 0) {
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), mac, &v);
				loweralias = get_alias_by_section("dmmap", "link", s, "link_alias");
				layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "link", s, "link_instance", "link_alias");
				if (v == NULL)
					v = "";
			}
			snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", v);
			if (*loweralias == '\0')
				snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", layer_inst);
			else
				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
		}
		ifdata.higherlayer = buf_higherlayer;
		ifdata.lowerlayer = buf_lowerlayer;
		ifdata.higheralias = buf_higheralias;
		ifdata.loweralias = buf_loweralias;
		snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
		dmmap_s = create_dmmap_interface_stack_section(buf_instance);
		interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
			goto end;
	}

	/* Higher layers are Device.PPP.Interface.{i}. */
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (!strstr(proto, "ppp"))
			continue;
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", s, "ppp_int_instance", "ppp_int_alias");
		if (*layer_inst == '\0')
			continue;
		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.PPP.Interface.%s.", layer_inst);
		higheralias = get_alias_by_section("dmmap_network", "interface", s, "ppp_int_alias");
		if (*higheralias == '\0')
			snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", higheralias);
		found = 0;
		device = get_device(section_name(s));
		if (device[0] != '\0') {
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cVLANTermination%c", dmroot, dm_delim, dm_delim, dm_delim), device, &v);
			loweralias = get_alias_by_section("dmmap_network", "device", s, "vlan_term_alias");
			layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", s, "vlan_term_instance", "vlan_term_alias");
			if (v != NULL)
				found = 1;
		}
		mac = get_macaddr(section_name(s));
		if (mac[0] != '\0' && found == 0) {
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), mac, &v);
			loweralias = get_alias_by_section("dmmap", "link", s, "link_alias");
			layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "link", s, "link_instance", "link_alias");
			if (v == NULL)
				v = "";
		}
		snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", v);
		if (*loweralias == '\0')
			snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
		ifdata.higherlayer = buf_higherlayer;
		ifdata.lowerlayer = buf_lowerlayer;
		ifdata.higheralias = buf_higheralias;
		ifdata.loweralias = buf_loweralias;
		snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
		dmmap_s = create_dmmap_interface_stack_section(buf_instance);
		interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
			goto end;
	}

	/* Higher layers are Device.Ethernet.VLANTermination.{i}. */
	uci_foreach_sections("network", "device", s) {
		dmuci_get_value_by_section_string(s, "type", &type);
		dmuci_get_value_by_section_string(s, "name", &name);
		if (strcmp(type, "untagged") == 0 || !is_vlan_termination_section(name))
			continue;
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "device", s, "vlan_term_instance", "vlan_term_alias");
		if (*layer_inst == '\0')
			continue;
		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.Ethernet.VLANTermination.%s.", layer_inst);
		higheralias = get_alias_by_section("dmmap_network", "device", s, "vlan_term_alias");
		if (*higheralias == '\0')
			snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", higheralias);
		char *macaddr = get_macaddr_from_device(name);
		if (macaddr[0] != '\0') {
			if (is_mac_exist(macaddr)) {
				pch = macaddr;
			} else {
				char intf_tag[64] = {0};
				dmuci_get_value_by_section_string(s, "ifname", &ifname);
				snprintf(intf_tag, sizeof(intf_tag), "%s.1", ifname);
				pch = get_macaddr_from_device(intf_tag);
			}
		}
		if (pch[0] != '\0') {
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), pch, &v);
			if (v == NULL)
				v = "";
		}
		uci_foreach_sections("network", "interface", ss) {
			mac = get_macaddr(section_name(ss));
			if (strcmp(pch, mac) == 0) {
				loweralias = get_alias_by_section("dmmap", "link", ss, "link_alias");
				layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "link", ss, "link_instance", "link_alias");
				break;
			}
		}
		snprintf(buf_lowerlayer, sizeof(buf_lowerlayer), "%s", v);
		if (*loweralias == '\0')
			snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
		ifdata.higherlayer = buf_higherlayer;
		ifdata.lowerlayer = buf_lowerlayer;
		ifdata.higheralias = buf_higheralias;
		ifdata.loweralias = buf_loweralias;
		snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
		dmmap_s = create_dmmap_interface_stack_section(buf_instance);
		interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
			goto end;
	}

	/* Higher layers are Device.Ethernet.Link.{i}. */
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "type", &type);
		dmuci_get_value_by_section_string(s, "proto", &proto);
		if (strcmp(section_name(s), "loopback") == 0 || *proto == '\0')
			continue;
		dmuci_get_value_by_section_string(s, "ifname", &ifname);
		if (*ifname == '\0' || *ifname == '@')
			continue;
		layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "link", s, "link_instance", "link_alias");
		if (*layer_inst == '\0')
			continue;
		snprintf(buf_higherlayer, sizeof(buf_higherlayer), "Device.Ethernet.Link.%s.", layer_inst);
		higheralias = get_alias_by_section("dmmap", "link", s, "link_alias");
		if (*higheralias == '\0')
			snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", higheralias);
		if (strcmp(type, "bridge") == 0) {
			br_inst = get_alias_by_section("dmmap_network", "interface", s, "bridge_instance");
			uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", br_inst, port) {
				dmuci_get_value_by_section_string(port, "mg_port", &mg);
				if (strcmp(mg, "true") == 0) {
					snprintf(linker, sizeof(linker), "br_%s:%s+", br_inst, section_name(port));
					adm_entry_get_linker_param(dmctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &v);
					dmuci_get_value_by_section_string(port, "bridge_port_alias", &loweralias);
					dmuci_get_value_by_section_string(port, "bridge_port_instance", &layer_inst);
					break;
				}
			}
		} else {
			uci_foreach_option_eq("ports", "ethport", "name", "WAN", port_s) {
				dmuci_get_value_by_section_string(port_s, "ifname", &wanifname);
				if(strstr(ifname, wanifname)) {
					adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), wanifname, &v);
					loweralias = get_alias_by_section("dmmap_ports", "ethport", port_s, "eth_port_alias");
					layer_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_ports", "ethport", port_s, "eth_port_instance", "eth_port_alias");
					break;
				}
			}
		}
		if (v == NULL)
			v = "";
		if (*loweralias == '\0')
			snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", layer_inst);
		else
			snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
		ifdata.higherlayer = buf_higherlayer;
		ifdata.lowerlayer = v;
		ifdata.higheralias = buf_higheralias;
		ifdata.loweralias = buf_loweralias;
		snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
		dmmap_s = create_dmmap_interface_stack_section(buf_instance);
		interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
			goto end;
	}

	/* Higher layers are Device.Bridging.Bridge.{i}.Port.{i}.*/
	uci_foreach_sections("network", "interface", s) {
		dmuci_get_value_by_section_string(s, "type", &type);
		if (strcmp(type, "bridge") != 0)
			continue;
		br_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_network", "interface", s, "bridge_instance", "bridge_alias");
		if (*br_inst == '\0')
			continue;
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", br_inst, port) {
			dmuci_get_value_by_section_string(port, "mg_port", &mg);
			if (strcmp(mg, "true") == 0) {
				snprintf(linker, sizeof(linker), "br_%s:%s+", br_inst, section_name(port));
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &pch);
				dmuci_get_value_by_section_string(port, "bridge_port_alias", &higheralias);
				dmuci_get_value_by_section_string(port, "bridge_port_instance", &bridge_port_inst);
				if (*higheralias == '\0')
					snprintf(buf_tmp, sizeof(buf_tmp), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_tmp, sizeof(buf_tmp), "%s", higheralias);
				if (pch == NULL)
					pch = "";
				break;
			}
		}

		struct uci_section *sd = NULL;
		uci_path_foreach_option_eq(bbfdm, "dmmap_bridge_port", "bridge_port", "bridge_key", br_inst, sd) {
			dmuci_get_value_by_section_string(sd, "mg_port", &mg);
			if (strcmp(mg, "true") == 0)
				continue;

			char *sectionname, *package, *section;
			dmuci_get_value_by_section_string(sd, "section_name", &sectionname);
			dmuci_get_value_by_section_string(sd, "package", &package);
			dmuci_get_value_by_section_string(sd, "section", &section);

			uci_foreach_sections(package, section, port_s) {
				if(strcmp(section_name(port_s), sectionname) == 0) {
					dmuci_get_value_by_section_string(port_s, "ifname", &ifname);
					dmuci_get_value_by_section_string(port_s, "name", &name);
					break;
				}
			}

			if(strcmp(package, "network") == 0 && strcmp(section, "device") == 0)
				snprintf(linker, sizeof(linker), "br_%s:%s+%s", br_inst, sectionname, name);
			else
				snprintf(linker, sizeof(linker), "br_%s:%s+%s", br_inst, sectionname, ifname);
			adm_entry_get_linker_param(dmctx, dm_print_path("%s%cBridging%cBridge%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &vb);
			if (vb == NULL)
				vb = "";
			dmuci_get_value_by_section_string(sd, "bridge_port_alias", &loweralias);
			bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_bridge_port", "bridge_port", sd, "bridge_port_instance", "bridge_port_alias");
			if (*loweralias == '\0')
				snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
			else
				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);

			ifdata.higherlayer = pch;
			ifdata.lowerlayer = vb;
			ifdata.higheralias = buf_tmp;
			ifdata.loweralias = buf_loweralias;
			snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
			dmmap_s = create_dmmap_interface_stack_section(buf_instance);
			interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
				goto end;

			if (*loweralias == '\0')
				snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", bridge_port_inst);
			else
				snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", loweralias);
			if(strcmp(package, "ports") == 0) {
				adm_entry_get_linker_param(dmctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, &v);
				loweralias = get_alias_by_section("dmmap_ports", "ethport", port_s, "eth_port_alias");
				bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_ports", "ethport", port_s, "eth_port_instance", "eth_port_alias");
			} else if(strcmp(package, "wireless") == 0) {
				adm_entry_get_linker_param(dmctx,dm_print_path("%s%cWiFi%cSSID%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, &v);
				loweralias = get_alias_by_section("dmmap_wireless", "wifi-iface", port_s, "ssidalias");
				bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_wireless", "wifi-iface", port_s, "ssidinstance", "ssidalias");
			}	else if(strcmp(package, "network") == 0) {
				if(strstr(ifname, "atm")) {
					adm_entry_get_linker_param(dmctx,dm_print_path("%s%cATM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, &v);
					uci_foreach_sections("dsl", "atm-device", ss) {
						if(strcmp(section_name(ss), ifname) == 0) {
							loweralias = get_alias_by_section("dmmap_dsl", "atm-device", ss, "atmlinkalias");
							bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_dsl", "atm-device", port_s, "atmlinkinstance", "atmlinkalias");
							break;
						}
					}
				} else if(strstr(ifname, "ptm")) {
					adm_entry_get_linker_param(dmctx,dm_print_path("%s%cPTM%cLink%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, &v);
					uci_foreach_sections("dsl", "ptm-device", ss) {
						if(strcmp(section_name(ss), ifname) == 0) {
							loweralias = get_alias_by_section("dmmap_dsl", "ptm-device", ss, "ptmlinkalias");
							bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_dsl", "ptm-device", port_s, "ptmlinkinstance", "ptmlinkalias");
							break;
						}
					}
				} else {
					snprintf(linker, sizeof(linker), "%s", ifname);
					adm_entry_get_linker_param(dmctx,dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &v);
					loweralias = get_alias_by_section("dmmap_ports", "ethport", port_s, "eth_port_alias");
					bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap_ports", "ethport", port_s, "eth_port_instance", "eth_port_alias");
				}
			}
			if (*loweralias == '\0')
				snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
			else
				snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
			if (v == NULL)
				v = "";
			ifdata.higherlayer = vb;
			ifdata.lowerlayer = v;
			ifdata.higheralias = buf_higheralias;
			ifdata.loweralias = buf_loweralias;
			snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
			dmmap_s = create_dmmap_interface_stack_section(buf_instance);
			interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
				goto end;

			if(strcmp(package, "wireless") == 0) {
				if (*loweralias == '\0')
					snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", bridge_port_inst);
				else
					snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", loweralias);
				uci_foreach_option_eq("wireless", "wifi-iface", "ifname", ifname, ss) {
					dmuci_get_value_by_section_string(ss, "device", &device);
				}
				if (device[0] != '\0') {
					adm_entry_get_linker_param(dmctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), device, &vb);
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
				ifdata.higherlayer = v;
				ifdata.lowerlayer = vb;
				ifdata.higheralias = buf_higheralias;
				ifdata.loweralias = buf_loweralias;
				snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
				dmmap_s = create_dmmap_interface_stack_section(buf_instance);
				interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
					goto end;
			}

			if(strcmp(package, "network") == 0) {
				if(strstr(ifname, "atm") || strstr(ifname, "ptm")) {
					if (*loweralias == '\0')
						snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", bridge_port_inst);
					else
						snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", loweralias);
					char *link_channel = "channel_0";
					adm_entry_get_linker_param(dmctx, dm_print_path("%s%cDSL%cChannel%c", dmroot, dm_delim, dm_delim, dm_delim), link_channel, &vb);
					if (vb == NULL)
						vb = "";
					uci_path_foreach_sections(bbfdm, "dmmap", "dsl_channel", ss) {
						dmuci_get_value_by_section_string(ss, "dsl_channel_alias", &loweralias);
						bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "dsl_channel", ss, "dsl_channel_instance", "dsl_channel_alias");
					}
					if (*loweralias == '\0')
						snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
					else
						snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
					ifdata.higherlayer = v;
					ifdata.lowerlayer = vb;
					ifdata.higheralias = buf_higheralias;
					ifdata.loweralias = buf_loweralias;
					snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
					dmmap_s = create_dmmap_interface_stack_section(buf_instance);
					interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
					if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
						goto end;

					if (*loweralias == '\0')
						snprintf(buf_higheralias, sizeof(buf_higheralias), "cpe-%s", bridge_port_inst);
					else
						snprintf(buf_higheralias, sizeof(buf_higheralias), "%s", loweralias);
					char *link_line = "line_0";
					adm_entry_get_linker_param(dmctx, dm_print_path("%s%cDSL%cLine%c", dmroot, dm_delim, dm_delim, dm_delim), link_line, &value);
					if (value == NULL)
						value = "";
					uci_path_foreach_sections(bbfdm, "dmmap", "dsl_line", ss) {
						dmuci_get_value_by_section_string(ss, "dsl_line_alias", &loweralias);
						bridge_port_inst = get_instance_by_section(dmctx->instance_mode, "dmmap", "dsl_line", ss, "dsl_line_instance", "dsl_line_alias");
					}
					if (*loweralias == '\0')
						snprintf(buf_loweralias, sizeof(buf_loweralias), "cpe-%s", bridge_port_inst);
					else
						snprintf(buf_loweralias, sizeof(buf_loweralias), "%s", loweralias);
					ifdata.higherlayer = vb;
					ifdata.lowerlayer = value;
					ifdata.higheralias = buf_higheralias;
					ifdata.loweralias = buf_loweralias;
					snprintf(buf_instance, sizeof(buf_instance), "%d", ++instance);
					dmmap_s = create_dmmap_interface_stack_section(buf_instance);
					interface_stack_int = handle_update_instance(1, dmctx, &interface_stack_int_last, update_instance_alias, 3, dmmap_s, "interface_stack_instance", "interface_stack_alias");
					if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&ifdata, interface_stack_int) == DM_STOP)
						goto end;
				}
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
			uci_path_foreach_option_eq(bbfdm, "dmmap_interface_stack", "interface_stack", "interface_stack_instance", instance, s) {
				dmuci_set_value_by_section(s, "interface_stack_alias", value);
			}
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
