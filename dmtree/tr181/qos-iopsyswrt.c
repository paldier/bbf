/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Rohit Topno <r.topno@gxgroup.eu>
 */

#include "dmentry.h"
#include "qos.h"

/*************************************************************
 * ENTRY METHOD
*************************************************************/
int os_get_linker_qos_queue(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	*linker = "";
	return 0;
}
int os_browseQoSClassificationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL, *value = NULL;
	char *ret = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "classify", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "classify_instance", "classifyalias");
		//synchronizing option src_ip of uci classify section to src_mask/src_ip of dmmap's classify section
		dmuci_get_value_by_section_string(p->config_section, "src_ip", &value);
		//checking if src_ip is an ip-prefix or ip address and synchronizing accordingly
		ret = strstr(value, "/");
		if (ret)
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, p->dmmap_section, "src_mask", value);
		else
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, p->dmmap_section, "src_ip", value);

		//synchronizing option dest_ip of uci classify section to dest_mask/dest_ip of dmmap's classify section
		dmuci_get_value_by_section_string(p->config_section, "dest_ip", &value);
		//checking if src_ip is an ip-prefix or ip address and synchronizing accordingly
		ret = strstr(value, "/");
		if (ret)
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, p->dmmap_section, "dest_mask", value);
		else
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, p->dmmap_section, "dest_ip", value);

		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

#if 0
/*#Device.QoS.Classification.{i}.!UCI:qos/classify/dmmap_qos*/
int browseQoSClassificationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "classify", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "classificationinstance", "classificationalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int browseQoSAppInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

int browseQoSFlowInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

int browseQoSPolicerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif
/*#Device.QoS.Queue.{i}.!UCI:qos/queue/dmmap_qos*/
int os_browseQoSQueueInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "queue", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "queueinstance", "queuealias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int os_browseQoSQueueStatsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

int os_browseQoSShaperInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "shaper", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "shaperinstance", "shaperalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

/*************************************************************
 * ADD & DEL OBJ
*************************************************************/
int os_addObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v;
	struct uci_section *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_qos");
	inst = get_last_instance_bbfdm("dmmap_qos", "classify", "classify_instance");
	dmuci_add_section_and_rename("qos", "classify", &s, &value);
	//adding Classification object's parameter entries with default values
	dmuci_set_value_by_section(s, "enable", "0");

	dmuci_add_section_bbfdm("dmmap_qos", "classify", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap, inst, "classify_instance");
	return 0;
}

int os_delObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section= NULL;
	int found = 0;
	switch (del_action) {
	case DEL_INST:
		if (is_section_unnamed(section_name((struct uci_section *)data))){
			LIST_HEAD(dup_list);
			delete_sections_save_next_sections("dmmap_qos", "classify", "classify_instance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
			update_dmmap_sections(&dup_list, "classify_instance", "dmmap_qos", "classify");
			dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
		} else {
			get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
		}
		break;
	case DEL_ALL:
		uci_foreach_sections("qos", "classify", s) {
			if (found != 0){
				get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			ss = s;
			found++;
		}
		if (ss != NULL) {
			get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name(ss), &dmmap_section);
			if (dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section(ss, NULL, NULL);
		}
		break;
	}
	return 0;
}
#if 0
int addObjQoSApp(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

int delObjQoSApp(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

int addObjQoSFlow(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

int delObjQoSFlow(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

int addObjQoSPolicer(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

int delObjQoSPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}
#endif

int os_addObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v;
	struct uci_section  *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_qos");
	inst = get_last_instance_bbfdm("dmmap_qos", "queue", "queueinstance");
	dmuci_add_section("qos", "queue", &s, &value);
	dmuci_set_value_by_section(s, "enable", "false");
	dmuci_set_value_by_section(s, "weight", "0");
	dmuci_set_value_by_section(s, "precedence", "0");
	dmuci_set_value_by_section(s, "burst_size", "0");
	dmuci_set_value_by_section(s, "scheduling", "ST");
	dmuci_set_value_by_section(s, "rate", "0");
	dmuci_set_value_by_section(s, "traffic_class", "0");

	dmuci_add_section_bbfdm("dmmap_qos", "queue", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap, inst, "queueinstance");
	return 0;
}

int os_delObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section= NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name((struct uci_section *)data))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_qos", "queue", "queueinstance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "queueinstance", "dmmap_qos", "queue");
				dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name((struct uci_section *)data), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("qos", "queue", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

int os_addObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

int os_delObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	switch (del_action) {
		case DEL_INST:
			//TODO
			break;
		case DEL_ALL:
			//TODO
			break;
	}
	return 0;
}

int os_addObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v;
	struct uci_section  *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_qos");
	inst = get_last_instance_bbfdm("dmmap_qos", "shaper", "shaperinstance");
	dmuci_add_section("qos", "shaper", &s, &value);

	dmuci_set_value_by_section(s, "enable", "0");
	dmuci_set_value_by_section(s, "burst_size", "0");
	dmuci_set_value_by_section(s, "rate", "0");

	dmuci_add_section_bbfdm("dmmap_qos", "shaper", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap, inst, "shaperinstance");
	return 0;
}

int os_delObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section= NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name((struct uci_section *)data))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_qos", "shaper", "shaperinstance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "shaperinstance", "dmmap_qos", "shaper");
				dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name((struct uci_section *)data), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("qos", "shaper", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

/*************************************************************
 * GET & SET PARAM
*************************************************************/
int os_get_QoS_ClassificationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("qos", "classify", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

#if 0
int os_get_QoS_MaxClassificationEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.QoS.ClassificationNumberOfEntries!UCI:qos/classify,false/false*/
int os_get_QoS_ClassificationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("qos", "classify", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

int os_get_QoS_MaxAppEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoS_AppNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoS_MaxFlowEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoS_FlowNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoS_MaxPolicerEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoS_PolicerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoS_MaxQueueEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.QoS.QueueNumberOfEntries!UCI:qos/queue,false/false*/
int os_get_QoS_QueueNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("qos", "queue", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

int os_get_QoS_QueueStatsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

#if 0
int os_get_QoS_MaxShaperEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

int os_get_QoS_ShaperNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("qos", "shaper", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}
#if 0
int os_get_QoS_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoS_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoS_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoS_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoS_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoS_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoS_DefaultQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoS_DefaultQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoS_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoS_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoS_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoS_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoS_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoS_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoS_AvailableAppList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif
int os_get_QoSClassification_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	if(*value[0] == '\0')
		*value = "0";
	return 0;
}

int os_set_QoSClassification_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_boolean(value))
			return FAULT_9007;
		break;
	case VALUESET:
		string_to_bool(value, &b);
		if (b)
			dmuci_set_value_by_section((struct uci_section *)data, "enable", "1");
		else
			dmuci_set_value_by_section((struct uci_section *)data, "enable", "0");
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSClassification_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}


int os_get_QoSClassification_DHCPType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DHCPType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_DestMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section  *dmmap_section = NULL;
	get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "dest_mask", value);
	return 0;
}

int os_set_QoSClassification_DestMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dest_ip = NULL;
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
	case VALUECHECK:
		if (value[0] == '\0')
			break;
		if (dm_validate_string(value, -1, 49 , NULL, 0, IPPrefix, 3) != 0)
			return FAULT_9007;
		break;
	case VALUESET:
		/* Set received value of dest. mask in /etc/bbfdm/dmmap_qos.
		 * If received value is an empty string then get the value of dest. ip. from dmmap_qos and set it as dest_ip in qos uci file.
		 * If both received value of dest. mask and the dest. ip from dmmap_qos is empty then delete the dest_ip option from qos uci file.
		 * Note: setting an empty string as option value in uci or dmmap will delete that option.
		 * */
		//get dmmap section
		get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
		dmuci_set_value_by_section_bbfdm(dmmap_section, "dest_mask", value);
		if (value[0] == '\0') {
			//get source ip value from /etc/bbfdm/dmmap_qos and set as dest_ip
			dmuci_get_value_by_section_string(dmmap_section, "dest_ip", &dest_ip);
			dmuci_set_value_by_section((struct uci_section *)data, "dest_ip", dest_ip);
		} else {
			dmuci_set_value_by_section((struct uci_section *)data, "dest_ip", value);
		}
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_DestIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}


int os_get_QoSClassification_ProtocolExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_ProtocolExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_SourceMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section  *dmmap_section = NULL;
	get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "src_mask", value);
	return 0;
}

int os_set_QoSClassification_SourceMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *src_ip = NULL;
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
	case VALUECHECK:
		if (value[0] == '\0')
			break;
		if (dm_validate_string(value, -1, 49 , NULL, 0, IPPrefix, 3) != 0)
			return FAULT_9007;
		break;
	case VALUESET:
		/* Set received value of src. mask in /etc/bbfdm/dmmap_qos.
		 * If received value is an empty string then get the value of src. ip. from dmmap_qos and set it as src_ip in qos uci file.
		 * If both received value of src. mask and the src. ip from dmmap_qos is empty then  delete the src_ip option from qos uci file.
		 * Note: setting an empty string as option value in uci or dmmap will delete that option.
		 * */
		//get dmmap section
		get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
		dmuci_set_value_by_section_bbfdm(dmmap_section, "src_mask", value);
		if (value[0] == '\0') {
			//get source ip value from /etc/bbfdm/dmmap_qos and set as src_ip
			dmuci_get_value_by_section_string(dmmap_section, "src_ip", &src_ip);
			dmuci_set_value_by_section((struct uci_section *)data, "src_ip", src_ip);
		} else {
			dmuci_set_value_by_section((struct uci_section *)data, "src_ip", value);
		}
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_SourceIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

int os_set_QoSClassification_SourceIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif

int os_get_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "classifyalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

int os_set_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
		DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "classifyalias", value);
		break;
	}
	return 0;
}

int os_get_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifname;
	dmuci_get_value_by_section_string((struct uci_section *)data, "ifname", &ifname);

	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cPPP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		*value = "";

	return 0;
}

int os_set_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *interface_linker = NULL;
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
			return FAULT_9007;
		break;
	case VALUESET:
		adm_entry_get_linker_value(ctx, value, &interface_linker);
		if (interface_linker)
			dmuci_set_value_by_section((struct uci_section *)data, "ifname", interface_linker);
		break;
	}
	return 0;
}

int os_get_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;
	get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "dest_ip", value);
	return 0;
}

int os_set_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *dest_mask = NULL;
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
	case VALUECHECK:
		if (value[0] == '\0')
			break;
		else if (dm_validate_string(value, -1, 45 , NULL, 0, IPAddress, 2) != 0)
			return FAULT_9007;
		break;
	case VALUESET:
		/* If dest. mask parameter from etc/bbfdm/dmmap_qos is present, set this (dest. mask) value as dest_ip in qos uci file
		 * Else write received dest. ip to /etc/bbfdm/dmmap_qos and qos uci file.
		 * Also write the received dest. ip value to /etc/bbfdm/dmmap_qos.
		 * */
		get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "dest_mask", &dest_mask);

		if (dest_mask[0] != '\0') {
			dmuci_set_value_by_section((struct uci_section *)data, "dest_ip", dest_mask);
		} else 	{
			//note: setting an option to an empty string will delete that option
			dmuci_set_value_by_section((struct uci_section *)data, "dest_ip", value);
		}
		dmuci_set_value_by_section_bbfdm(dmmap_section, "dest_ip", value);
		break;
	}
	return 0;
}

int os_get_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;
	get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "src_ip", value);
	return 0;
}

int os_set_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *src_mask = NULL;
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
	case VALUECHECK:
		if (value[0] == '\0')
			break;
		else if (dm_validate_string(value, -1, 45 , NULL, 0, IPAddress, 2) != 0)
			return FAULT_9007;
		break;
	case VALUESET:
		/*if source mask parameter from etc/bbfdm/dmmap_qos is present, set this (source mask) value as src_ip in qos uci file
		Else write received source ip to /etc/bbfdm/dmmap_qos and qos uci file.
		also write the received source ip value to /etc/bbfdm/dmmap_qos.
		*/
		get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
		dmuci_get_value_by_section_string(dmmap_section, "src_mask", &src_mask);

		if (src_mask[0] != '\0') {
			dmuci_set_value_by_section((struct uci_section *)data, "src_ip", src_mask);
		} else 	{
			//note: setting an option to an empty string will delete that option
			dmuci_set_value_by_section((struct uci_section *)data, "src_ip", value);
		}
		dmuci_set_value_by_section_bbfdm(dmmap_section, "src_ip", value);
		break;
	}
	return 0;
}

int os_get_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "proto", value);
	return 0;
}

int os_set_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1","255"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "proto", value);
		break;
	}
	return 0;
}


int os_get_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dest_port", value);
	return 0;
}

int os_set_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "dest_port", value);
		break;
	}
	return 0;
}

int os_get_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dest_port_range", value);
	return 0;
}

int os_set_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dest_port_range", value);
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestPortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

int os_set_QoSClassification_DestPortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "src_port", value);
	return 0;
}

int os_set_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "src_port", value);
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourcePortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "src_port_range", value);
	return 0;
}

int os_set_QoSClassification_SourcePortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "src_port_range", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_SourcePortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourcePortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_SourceMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "src_mac", value);
	return 0;
}

int os_set_QoSClassification_SourceMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "src_mac", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_SourceMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_DestMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dst_mac", value);
	return 0;
}

int os_set_QoSClassification_DestMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "dst_mac", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_DestMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_Ethertype(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ethertype", value);
	return 0;
}

int os_set_QoSClassification_Ethertype(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "ethertype", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_EthertypeExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_EthertypeExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_LLCControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_LLCControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_LLCControlExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_LLCControlExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SNAPOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SNAPOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SNAPOUIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SNAPOUIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_SourceVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_SourceVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_DestVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DestVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_TCPACK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_TCPACK(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_TCPACKExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_TCPACKExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_IPLengthMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ip_len_min", value);
	return 0;
}

int os_set_QoSClassification_IPLengthMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"0",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "ip_len_min", value);
		break;
	}
	return 0;
}

int os_get_QoSClassification_IPLengthMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "ip_len_max", value);
	return 0;
}

int os_set_QoSClassification_IPLengthMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"0",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "ip_len_max", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_IPLengthExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_IPLengthExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_DSCPCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dscp_filter", value);
	return 0;
}

int os_set_QoSClassification_DSCPCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1","63"}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "dscp_filter", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_DSCPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_DSCPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
/*#Device.QoS.Classification.{i}.DSCPMark!UCI:qos/classify,@i-1/dscp*/
int os_get_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dscp_mark", value);
	return 0;
}

int os_set_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "dscp_mark", value);
		break;
	}
	return 0;
}
int os_get_QoSClassification_EthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "pcp_check", value);
	return 0;
}

int os_set_QoSClassification_EthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "pcp_check", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_EthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_EthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_InnerEthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_InnerEthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_InnerEthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_InnerEthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_EthernetDEICheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_EthernetDEICheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_EthernetDEIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_EthernetDEIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "vid_check", value);
	return 0;
}

int os_set_QoSClassification_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "vid_check", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_OutOfBandInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_OutOfBandInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif
int os_get_QoSClassification_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "traffic_class", value);
	return 0;
}

int os_set_QoSClassification_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
			return FAULT_9007;
		break;
	case VALUESET:
		dmuci_set_value_by_section((struct uci_section *)data, "traffic_class", value);
		break;
	}
	return 0;
}
#if 0
int os_get_QoSClassification_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSClassification_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSClassification_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSApp_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_ProtocolIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_ProtocolIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSApp_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSApp_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSFlow_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_TypeParameters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_TypeParameters(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSFlow_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSFlow_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_CommittedRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_CommittedRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_CommittedBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_CommittedBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_ExcessBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_ExcessBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_PeakRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_PeakRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_PeakBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_PeakBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_MeterType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_MeterType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_PossibleMeterTypes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_ConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_ConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_PartialConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_PartialConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_NonConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSPolicer_NonConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSPolicer_TotalCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_TotalCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_ConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_ConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_PartiallyConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_PartiallyConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_NonConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_get_QoSPolicer_NonConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

int os_get_QoSQueue_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	*value = (*value[0] == '1') ? "1" : "0";
	return 0;
}

int os_set_QoSQueue_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

int os_get_QoSQueue_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	*value = (*value[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

int os_get_QoSQueue_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "queuealias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

int os_set_QoSQueue_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name((struct uci_section *)data), &dmmap_section);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "queuealias", value);
			break;
	}
	return 0;
}

int os_get_QoSQueue_TrafficClasses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "traffic_class", value);
	return 0;
}

int os_set_QoSQueue_TrafficClasses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "traffic_class", value);
			break;
	}
	return 0;
}

int os_get_QoSQueue_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifname;
	dmuci_get_value_by_section_string((struct uci_section *)data, "ifname", &ifname);

	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cPPP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		*value = "";

	return 0;
}

int os_set_QoSQueue_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *interface_linker = NULL;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &interface_linker);
			if (interface_linker)
				dmuci_set_value_by_section((struct uci_section *)data, "ifname", interface_linker);
			break;
	}
	return 0;
}

#if 0
int os_get_QoSQueue_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int os_set_QoSQueue_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int os_get_QoSQueue_HardwareAssisted(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.QoS.Queue.{i}.BufferLength!UCI:qos/class,@i-1/maxsize*/
int os_get_QoSQueue_BufferLength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

int os_get_QoSQueue_Weight(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "weight", value);
	return 0;
}

int os_set_QoSQueue_Weight(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
			case VALUESET:
				dmuci_set_value_by_section((struct uci_section *)data, "weight", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Queue.{i}.Precedence!UCI:qos/queue,@i-1/precedence*/
int os_get_QoSQueue_Precedence(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "precedence", value);
	return 0;
}

int os_set_QoSQueue_Precedence(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "precedence", value);
			break;
	}
	return 0;
}

#if 0
int os_get_QoSQueue_REDThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	/* Simply setting default value as mentioned in tr-181 | since no paraneter in UCI (qos) file */
	char *default_val = "0";
	dmasprintf(value, "%s", default_val);
	return 0;
}

int os_set_QoSQueue_REDThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"100"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSQueue_REDPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	/* Simply setting default value as mentioned in tr-181 | since no paraneter in UCI (qos) file */
	char *default_val = "0";
	dmasprintf(value, "%s", default_val);
	return 0;
}

int os_set_QoSQueue_REDPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,"100"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSQueue_DropAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	/* Simply setting default value as mentioned in tr-181 | since no paraneter in UCI (qos) file */
	char *default_val = "DT";
	dmasprintf(value, "%s", default_val);
	return 0;
}

int os_set_QoSQueue_DropAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			if (dm_validate_string(value, -1, -1, DropAlgorithm, 4, NULL, 0))
				return FAULT_9007;
			break;
	}
	return 0;
}
#endif

int os_get_QoSQueue_SchedulerAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "scheduling", value);
	return 0;
}

int os_set_QoSQueue_SchedulerAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, SchedulerAlgorithm, 3, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "scheduling", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Queue.{i}.ShapingRate!UCI:qos/class,@i-1/rate*/
int os_get_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "rate", value);
	return 0;
}


int os_set_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "rate", value);
			break;
	}
	return 0;
}

int os_get_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "burst_size", value);
	return 0;
}

int os_set_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "burst_size", value);
			break;
	}
	return 0;
}

int os_get_QoSQueueStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_set_QoSQueueStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSQueueStats_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_get_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_set_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSQueueStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_set_QoSQueueStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_set_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSQueueStats_OutputPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_get_QoSQueueStats_OutputBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_get_QoSQueueStats_DroppedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_get_QoSQueueStats_DroppedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_get_QoSQueueStats_QueueOccupancyPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_get_QoSQueueStats_QueueOccupancyPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value="";
	return 0;
}

int os_get_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	*value = (*value[0] == '1') ? "1" : "0";
	return 0;
}

int os_set_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

int os_get_QoSShaper_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	*value = (*value[0] == '1') ? "Enabled" : "Disabled";
	return 0;
}

int os_get_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "shaperalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

int os_set_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name((struct uci_section *)data), &dmmap_section);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_section, "shaperalias", value);
			break;
	}
	return 0;
}

int os_get_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *ifname = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "ifname", &ifname);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cPPP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), ifname, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int os_set_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *interface_linker = NULL;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &interface_linker);
			dmuci_set_value_by_section((struct uci_section *)data, "ifname", interface_linker);
			break;
	}
	return 0;
}

int os_get_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "rate", value);
	return 0;
}

int os_set_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "rate", value);
			break;
	}
	return 0;
}

int os_get_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "burst_size", value);
	return 0;
}

int os_set_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "burst_size", value);
			break;
	}
	return 0;
}
