/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#include "x_iopsys_eu_buttons.h"

int browseXIopsysEuButton(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *ibutton = NULL, *ibutton_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("buttons", "button", "dmmap_buttons", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		ibutton =  handle_update_instance(1, dmctx, &ibutton_last, update_instance_alias, 3, p->dmmap_section, "buttoninstance", "buttonalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, ibutton) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/************************************************************************************* 
**** function related to button ****
**************************************************************************************/

static int get_x_iopsys_eu_button_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmasprintf(value, "%s", section_name((struct uci_section *)data));
	return 0;
}

static int get_x_iopsys_eu_button_gpio(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_list *val;

	dmuci_get_value_by_section_list((struct uci_section *)data, "button", &val);
	if (val)
		*value = dmuci_list_to_string(val, " ");
	else
		*value = "";
	return 0;
}

static int get_x_iopsys_eu_button_hotplug(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "hotplug", value);
	return 0;
}

static int get_x_iopsys_eu_button_hotplug_long(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "hotplug_long", value);
	return 0;
}

static int get_x_iopsys_eu_button_minpress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "minpress", value);
	return 0;
}

static int set_x_iopsys_eu_button_minpress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "minpress", value);
			return 0;
	}
	return 0;
}

static int get_x_iopsys_eu_button_longpress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "longpress", value);
	return 0;
}

static int set_x_iopsys_eu_button_longpress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{

	switch (action) {
		case VALUECHECK:
			return 0;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "longpress", value);
			return 0;
	}
	return 0;
}


static int get_x_iopsys_eu_button_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmuci_get_value_by_section_fallback_def((struct uci_section *)data, "enable", "1");
	return 0;
}

static int set_x_iopsys_eu_button_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			return 0;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enable", b ? "1" : "0");
			return 0;
	}
	return 0;
}
////////////////////////SET AND GET ALIAS/////////////////////////////////
static int get_x_iopsys_eu_button_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_buttons", "button", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "buttonalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

static int set_x_iopsys_eu_button_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			return 0;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_buttons", "button", section_name((struct uci_section *)data), &dmmap_section);
			dmuci_set_value_by_section(dmmap_section, "buttonalias", value);
			return 0;
	}
	return 0;
}

/*** DMROOT.X_IOPSYS_EU_Buttons.{i}. ****/
DMLEAF X_IOPSYS_EU_ButtonParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_x_iopsys_eu_button_alias, set_x_iopsys_eu_button_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_x_iopsys_eu_button_enable, set_x_iopsys_eu_button_enable, NULL, NULL, BBFDM_BOTH},	
{"Name", &DMREAD, DMT_STRING, get_x_iopsys_eu_button_name, NULL, NULL, NULL, BBFDM_BOTH},
{"GPIOButton", &DMREAD, DMT_STRING, get_x_iopsys_eu_button_gpio, NULL, NULL, NULL, BBFDM_BOTH},
{"HotplugInterface", &DMREAD, DMT_STRING, get_x_iopsys_eu_button_hotplug, NULL, NULL, NULL, BBFDM_BOTH},
{"HotplugInterfaceForLongPress", &DMREAD, DMT_STRING, get_x_iopsys_eu_button_hotplug_long, NULL, NULL, NULL, BBFDM_BOTH},
{"MinPressTime", &DMWRITE, DMT_UNINT, get_x_iopsys_eu_button_minpress, set_x_iopsys_eu_button_minpress, NULL, NULL, BBFDM_BOTH},
{"LongPressTime", &DMWRITE, DMT_UNINT, get_x_iopsys_eu_button_longpress, set_x_iopsys_eu_button_longpress, NULL, NULL, BBFDM_BOTH},
{0}
};
