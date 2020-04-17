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

#include <libbbf_api/dmbbf.h>
#include <libbbf_api/dmcommon.h>
#include <libbbf_api/dmuci.h>
#include <libbbf_api/dmubus.h>
#include <libbbf_api/dmjson.h>
#include "dmentry.h"
#include "qos.h"

/*************************************************************
 * ENTRY METHOD
*************************************************************/
#if 0
/*#Device.QoS.Classification.{i}.!UCI:qos/classify/dmmap_qos*/
static int browseQoSClassificationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
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

static int browseQoSAppInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

static int browseQoSFlowInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}

static int browseQoSPolicerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif
/*#Device.QoS.Queue.{i}.!UCI:qos/queue/dmmap_qos*/
static int browseQoSQueueInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
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
#if 0
static int browseQoSQueueStatsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//TODO
	return 0;
}
#endif

static int browseQoSShaperInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
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
#if 0
static int addObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char *inst, *value, *v;
	struct uci_section *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_qos");
	inst = get_last_instance_bbfdm("dmmap_qos", "classify", "classificationinstance");
	dmuci_add_section_and_rename("qos", "classify", &s, &value);
	//dmuci_set_value_by_section(s, "option", "value");

	dmuci_add_section_bbfdm("dmmap_qos", "classify", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap, inst, "classificationinstance");
	return 0;
}

static int delObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section= NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name((struct uci_section *)data), &dmmap_section);
			if(dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("qos", "classify", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

static int addObjQoSApp(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjQoSApp(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
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

static int addObjQoSFlow(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjQoSFlow(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
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

static int addObjQoSPolicer(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjQoSPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
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

static int addObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char **instance)
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

static int delObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section= NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if(is_section_unnamed(section_name((struct uci_section *)data))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_qos", "queue", "queueinstance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "queueinstance", "dmmap_qos", "queue");
				dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name((struct uci_section *)data), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("qos", "queue", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}
#if 0
static int addObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

static int delObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
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
static int addObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char **instance)
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

static int delObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section= NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if(is_section_unnamed(section_name((struct uci_section *)data))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_qos", "shaper", "shaperinstance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "shaperinstance", "dmmap_qos", "shaper");
				dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name((struct uci_section *)data), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("qos", "shaper", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
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
#if 0
static int get_QoS_MaxClassificationEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.QoS.ClassificationNumberOfEntries!UCI:qos/classify,false/false*/
static int get_QoS_ClassificationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("qos", "classify", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_QoS_MaxAppEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoS_AppNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoS_MaxFlowEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoS_FlowNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoS_MaxPolicerEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoS_PolicerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoS_MaxQueueEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.QoS.QueueNumberOfEntries!UCI:qos/queue,false/false*/
static int get_QoS_QueueNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("qos", "queue", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}
#if 0
static int get_QoS_QueueStatsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoS_MaxShaperEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

static int get_QoS_ShaperNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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
static int get_QoS_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoS_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoS_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoS_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoS_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoS_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoS_DefaultQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoS_DefaultQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoS_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoS_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoS_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoS_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoS_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoS_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoS_AvailableAppList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSClassification_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSClassification_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DHCPType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DHCPType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.QoS.Classification.{i}.DestIP!UCI:qos/classify,@i-1/dsthost*/
static int get_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dsthost", value);
	return 0;
}

static int set_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dsthost", value);
			break;
	}
	return 0;
}

static int get_QoSClassification_DestMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.QoS.Classification.{i}.SourceIP!UCI:qos/classify,@i-1/srchost*/
static int get_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "srchost", value);
	return 0;
}

static int set_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "srchost", value);
			break;
	}
	return 0;
}

static int get_QoSClassification_SourceMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.QoS.Classification.{i}.Protocol!UCI:qos/classify,@i-1/proto*/
static int get_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "proto", value);
	return 0;
}

static int set_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "proto", value);
			break;
	}
	return 0;
}

static int get_QoSClassification_ProtocolExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_ProtocolExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.QoS.Classification.{i}.DestPort!UCI:qos/classify,@i-1/dstports*/
static int get_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dstports", value);
	return 0;
}

static int set_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dstports", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.DestPortRangeMax!UCI:qos/classify,@i-1/portrange*/
static int get_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "portrange", value);
	return 0;
}

static int set_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "portrange", value);
			break;
	}
	return 0;
}

static int get_QoSClassification_DestPortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestPortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.QoS.Classification.{i}.SourcePort!UCI:qos/classify,@i-1/srcports*/
static int get_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "srcports", value);
	return 0;
}

static int set_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "srcports", value);
			break;
	}
	return 0;
}

static int get_QoSClassification_SourcePortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourcePortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourcePortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourcePortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_Ethertype(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_Ethertype(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_EthertypeExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_EthertypeExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_LLCControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_LLCControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_LLCControlExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_LLCControlExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SNAPOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SNAPOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SNAPOUIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SNAPOUIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_SourceVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_SourceVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DestVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DestVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_TCPACK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_TCPACK(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_TCPACKExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_TCPACKExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_IPLengthMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_IPLengthMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_IPLengthMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_IPLengthMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_IPLengthExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_IPLengthExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DSCPCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DSCPCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_DSCPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_DSCPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.QoS.Classification.{i}.DSCPMark!UCI:qos/classify,@i-1/dscp*/
static int get_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "dscp", value);
	return 0;
}

static int set_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "dscp", value);
			break;
	}
	return 0;
}

static int get_QoSClassification_EthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_EthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_EthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_EthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_InnerEthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_InnerEthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_InnerEthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_InnerEthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_EthernetDEICheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_EthernetDEICheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_EthernetDEIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_EthernetDEIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_OutOfBandInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_OutOfBandInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSClassification_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSClassification_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSApp_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_ProtocolIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_ProtocolIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSApp_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSApp_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSFlow_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_TypeParameters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_TypeParameters(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSFlow_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSFlow_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_CommittedRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_CommittedRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_CommittedBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_CommittedBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_ExcessBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_ExcessBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_PeakRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_PeakRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_PeakBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_PeakBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_MeterType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_MeterType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_PossibleMeterTypes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_ConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_ConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_PartialConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_PartialConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_NonConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSPolicer_NonConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSPolicer_TotalCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_TotalCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_ConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_ConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_PartiallyConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_PartiallyConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_NonConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSPolicer_NonConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

static int get_QoSQueue_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	if(*value[0] == '\0' || *value[0] == '0')
		*value = "0";
	else
		*value = "1";
	return 0;
}

static int set_QoSQueue_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if(b)
				dmuci_set_value_by_section((struct uci_section *)data, "enable", "1");
			else
				dmuci_set_value_by_section((struct uci_section *)data, "enable", "0");
			break;
	}
	return 0;
}

static int get_QoSQueue_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	if(*value[0] == '\0' || *value[0] == '0')
		*value = "Disabled";
	else
		*value = "Enabled";
	return 0;
}

static int get_QoSQueue_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;
	get_dmmap_section_of_config_section("dmmap_qos", "queue", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "queuealias", value);
	return 0;
}

static int set_QoSQueue_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueue_TrafficClasses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "traffic_class", value);
	return 0;
}

static int set_QoSQueue_TrafficClasses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueue_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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

static int set_QoSQueue_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

#if 0
static int get_QoSQueue_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSQueue_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueue_HardwareAssisted(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.QoS.Queue.{i}.BufferLength!UCI:qos/class,@i-1/maxsize*/
static int get_QoSQueue_BufferLength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

static int get_QoSQueue_Weight(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "weight", value);
	return 0;
}

static int set_QoSQueue_Weight(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
static int get_QoSQueue_Precedence(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "precedence", value);
	return 0;
}

static int set_QoSQueue_Precedence(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
static int get_QoSQueue_REDThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	/* Simply setting default value as mentioned in tr-181 | since no paraneter in UCI (qos) file */
	char *default_val = "0";
	dmasprintf(value, "%s", default_val);
	return 0;
}

static int set_QoSQueue_REDThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueue_REDPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	/* Simply setting default value as mentioned in tr-181 | since no paraneter in UCI (qos) file */
	char *default_val = "0";
	dmasprintf(value, "%s", default_val);
	return 0;
}

static int set_QoSQueue_REDPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueue_DropAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	/* Simply setting default value as mentioned in tr-181 | since no paraneter in UCI (qos) file */
	char *default_val = "DT";
	dmasprintf(value, "%s", default_val);
	return 0;
}

static int set_QoSQueue_DropAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueue_SchedulerAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "scheduling", value);
	return 0;
}

static int set_QoSQueue_SchedulerAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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


/*#Device.QoS.Queue.{i}.ShapingRate!UCI:qos/class,@i-1/limitrate*/
static int get_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "rate", value);
	return 0;
}


static int set_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "burst_size", value);
	return 0;
}

static int set_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			dmuci_set_value_by_section((struct uci_section *)data, "burst_size", value);
			break;
	}
	return 0;
}
#if 0
static int get_QoSQueueStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSQueueStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueueStats_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueueStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSQueueStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int set_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSQueueStats_OutputPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSQueueStats_OutputBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSQueueStats_DroppedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSQueueStats_DroppedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSQueueStats_QueueOccupancyPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

static int get_QoSQueueStats_QueueOccupancyPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif
static int get_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	if(*value[0] == '\0' || *value[0] == '0')
		*value = "0";
	else
		*value = "1";
	return 0;
}

static int set_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			if(b)
				dmuci_set_value_by_section((struct uci_section *)data, "enable", "1");
			else
				dmuci_set_value_by_section((struct uci_section *)data, "enable", "0");
			break;
	}
	return 0;
}

static int get_QoSShaper_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	if(*value[0] == '\0' || *value[0] == '0')
		*value = "Disabled";
	else
		*value = "Enabled";
	return 0;
}

static int get_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;
	get_dmmap_section_of_config_section("dmmap_qos", "shaper", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "shaperalias", value);
	return 0;
}

static int set_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
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

static int set_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "rate", value);
	return 0;
}

static int set_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

static int get_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "burst_size", value);
	return 0;
}

static int set_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
/* *** Device.QoS. *** */
DMOBJ tQoSObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
//{"Classification", &DMWRITE, addObjQoSClassification, delObjQoSClassification, NULL, browseQoSClassificationInst, NULL, NULL, NULL, NULL, tQoSClassificationParams, NULL, BBFDM_BOTH},
//{"App", &DMWRITE, addObjQoSApp, delObjQoSApp, NULL, browseQoSAppInst, NULL, NULL, NULL, NULL, tQoSAppParams, NULL, BBFDM_BOTH},
//{"Flow", &DMWRITE, addObjQoSFlow, delObjQoSFlow, NULL, browseQoSFlowInst, NULL, NULL, NULL, NULL, tQoSFlowParams, NULL, BBFDM_BOTH},
//{"Policer", &DMWRITE, addObjQoSPolicer, delObjQoSPolicer, NULL, browseQoSPolicerInst, NULL, NULL, NULL, NULL, tQoSPolicerParams, NULL, BBFDM_BOTH},
{"Queue", &DMWRITE, addObjQoSQueue, delObjQoSQueue, NULL, browseQoSQueueInst, NULL, NULL, NULL, NULL, tQoSQueueParams, NULL, BBFDM_BOTH},
//{"QueueStats", &DMWRITE, addObjQoSQueueStats, delObjQoSQueueStats, NULL, browseQoSQueueStatsInst, NULL, NULL, NULL, NULL, tQoSQueueStatsParams, NULL, BBFDM_BOTH},
{"Shaper", &DMWRITE, addObjQoSShaper, delObjQoSShaper, NULL, browseQoSShaperInst, NULL, NULL, NULL, NULL, tQoSShaperParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tQoSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"MaxClassificationEntries", &DMREAD, DMT_UNINT, get_QoS_MaxClassificationEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"ClassificationNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_ClassificationNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxAppEntries", &DMREAD, DMT_UNINT, get_QoS_MaxAppEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"AppNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_AppNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxFlowEntries", &DMREAD, DMT_UNINT, get_QoS_MaxFlowEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"FlowNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_FlowNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxPolicerEntries", &DMREAD, DMT_UNINT, get_QoS_MaxPolicerEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"PolicerNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_PolicerNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxQueueEntries", &DMREAD, DMT_UNINT, get_QoS_MaxQueueEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"QueueNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_QueueNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"QueueStatsNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_QueueStatsNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"MaxShaperEntries", &DMREAD, DMT_UNINT, get_QoS_MaxShaperEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"ShaperNumberOfEntries", &DMREAD, DMT_UNINT, get_QoS_ShaperNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"DefaultForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoS_DefaultForwardingPolicy, set_QoS_DefaultForwardingPolicy, NULL, NULL, BBFDM_BOTH},
//{"DefaultTrafficClass", &DMWRITE, DMT_UNINT, get_QoS_DefaultTrafficClass, set_QoS_DefaultTrafficClass, NULL, NULL, BBFDM_BOTH},
//{"DefaultPolicer", &DMWRITE, DMT_STRING, get_QoS_DefaultPolicer, set_QoS_DefaultPolicer, NULL, NULL, BBFDM_BOTH},
//{"DefaultQueue", &DMWRITE, DMT_STRING, get_QoS_DefaultQueue, set_QoS_DefaultQueue, NULL, NULL, BBFDM_BOTH},
//{"DefaultDSCPMark", &DMWRITE, DMT_INT, get_QoS_DefaultDSCPMark, set_QoS_DefaultDSCPMark, NULL, NULL, BBFDM_BOTH},
//{"DefaultEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoS_DefaultEthernetPriorityMark, set_QoS_DefaultEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"DefaultInnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoS_DefaultInnerEthernetPriorityMark, set_QoS_DefaultInnerEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"AvailableAppList", &DMREAD, DMT_STRING, get_QoS_AvailableAppList, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Classification.{i}. *** */
DMLEAF tQoSClassificationParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSClassification_Enable, set_QoSClassification_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSClassification_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Order", &DMWRITE, DMT_UNINT, get_QoSClassification_Order, set_QoSClassification_Order, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSClassification_Alias, set_QoSClassification_Alias, NULL, NULL, BBFDM_BOTH},
//{"DHCPType", &DMWRITE, DMT_STRING, get_QoSClassification_DHCPType, set_QoSClassification_DHCPType, NULL, NULL, BBFDM_BOTH},
//{"Interface", &DMWRITE, DMT_STRING, get_QoSClassification_Interface, set_QoSClassification_Interface, NULL, NULL, BBFDM_BOTH},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_QoSClassification_AllInterfaces, set_QoSClassification_AllInterfaces, NULL, NULL, BBFDM_BOTH},
//{"DestIP", &DMWRITE, DMT_STRING, get_QoSClassification_DestIP, set_QoSClassification_DestIP, NULL, NULL, BBFDM_BOTH},
//{"DestMask", &DMWRITE, DMT_STRING, get_QoSClassification_DestMask, set_QoSClassification_DestMask, NULL, NULL, BBFDM_BOTH},
//{"DestIPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestIPExclude, set_QoSClassification_DestIPExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceIP", &DMWRITE, DMT_STRING, get_QoSClassification_SourceIP, set_QoSClassification_SourceIP, NULL, NULL, BBFDM_BOTH},
//{"SourceMask", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMask, set_QoSClassification_SourceMask, NULL, NULL, BBFDM_BOTH},
//{"SourceIPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceIPExclude, set_QoSClassification_SourceIPExclude, NULL, NULL, BBFDM_BOTH},
//{"Protocol", &DMWRITE, DMT_INT, get_QoSClassification_Protocol, set_QoSClassification_Protocol, NULL, NULL, BBFDM_BOTH},
//{"ProtocolExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_ProtocolExclude, set_QoSClassification_ProtocolExclude, NULL, NULL, BBFDM_BOTH},
//{"DestPort", &DMWRITE, DMT_INT, get_QoSClassification_DestPort, set_QoSClassification_DestPort, NULL, NULL, BBFDM_BOTH},
//{"DestPortRangeMax", &DMWRITE, DMT_INT, get_QoSClassification_DestPortRangeMax, set_QoSClassification_DestPortRangeMax, NULL, NULL, BBFDM_BOTH},
//{"DestPortExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestPortExclude, set_QoSClassification_DestPortExclude, NULL, NULL, BBFDM_BOTH},
//{"SourcePort", &DMWRITE, DMT_INT, get_QoSClassification_SourcePort, set_QoSClassification_SourcePort, NULL, NULL, BBFDM_BOTH},
//{"SourcePortRangeMax", &DMWRITE, DMT_INT, get_QoSClassification_SourcePortRangeMax, set_QoSClassification_SourcePortRangeMax, NULL, NULL, BBFDM_BOTH},
//{"SourcePortExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourcePortExclude, set_QoSClassification_SourcePortExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceMACAddress", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMACAddress, set_QoSClassification_SourceMACAddress, NULL, NULL, BBFDM_BOTH},
//{"SourceMACMask", &DMWRITE, DMT_STRING, get_QoSClassification_SourceMACMask, set_QoSClassification_SourceMACMask, NULL, NULL, BBFDM_BOTH},
//{"SourceMACExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceMACExclude, set_QoSClassification_SourceMACExclude, NULL, NULL, BBFDM_BOTH},
//{"DestMACAddress", &DMWRITE, DMT_STRING, get_QoSClassification_DestMACAddress, set_QoSClassification_DestMACAddress, NULL, NULL, BBFDM_BOTH},
//{"DestMACMask", &DMWRITE, DMT_STRING, get_QoSClassification_DestMACMask, set_QoSClassification_DestMACMask, NULL, NULL, BBFDM_BOTH},
//{"DestMACExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestMACExclude, set_QoSClassification_DestMACExclude, NULL, NULL, BBFDM_BOTH},
//{"Ethertype", &DMWRITE, DMT_INT, get_QoSClassification_Ethertype, set_QoSClassification_Ethertype, NULL, NULL, BBFDM_BOTH},
//{"EthertypeExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthertypeExclude, set_QoSClassification_EthertypeExclude, NULL, NULL, BBFDM_BOTH},
//{"SSAP", &DMWRITE, DMT_INT, get_QoSClassification_SSAP, set_QoSClassification_SSAP, NULL, NULL, BBFDM_BOTH},
//{"SSAPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SSAPExclude, set_QoSClassification_SSAPExclude, NULL, NULL, BBFDM_BOTH},
//{"DSAP", &DMWRITE, DMT_INT, get_QoSClassification_DSAP, set_QoSClassification_DSAP, NULL, NULL, BBFDM_BOTH},
//{"DSAPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DSAPExclude, set_QoSClassification_DSAPExclude, NULL, NULL, BBFDM_BOTH},
//{"LLCControl", &DMWRITE, DMT_INT, get_QoSClassification_LLCControl, set_QoSClassification_LLCControl, NULL, NULL, BBFDM_BOTH},
//{"LLCControlExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_LLCControlExclude, set_QoSClassification_LLCControlExclude, NULL, NULL, BBFDM_BOTH},
//{"SNAPOUI", &DMWRITE, DMT_INT, get_QoSClassification_SNAPOUI, set_QoSClassification_SNAPOUI, NULL, NULL, BBFDM_BOTH},
//{"SNAPOUIExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SNAPOUIExclude, set_QoSClassification_SNAPOUIExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorClassID", &DMWRITE, DMT_STRING, get_QoSClassification_SourceVendorClassID, set_QoSClassification_SourceVendorClassID, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorClassIDv6", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceVendorClassIDv6, set_QoSClassification_SourceVendorClassIDv6, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceVendorClassIDExclude, set_QoSClassification_SourceVendorClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorClassIDMode", &DMWRITE, DMT_STRING, get_QoSClassification_SourceVendorClassIDMode, set_QoSClassification_SourceVendorClassIDMode, NULL, NULL, BBFDM_BOTH},
//{"DestVendorClassID", &DMWRITE, DMT_STRING, get_QoSClassification_DestVendorClassID, set_QoSClassification_DestVendorClassID, NULL, NULL, BBFDM_BOTH},
//{"DestVendorClassIDv6", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestVendorClassIDv6, set_QoSClassification_DestVendorClassIDv6, NULL, NULL, BBFDM_BOTH},
//{"DestVendorClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestVendorClassIDExclude, set_QoSClassification_DestVendorClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"DestVendorClassIDMode", &DMWRITE, DMT_STRING, get_QoSClassification_DestVendorClassIDMode, set_QoSClassification_DestVendorClassIDMode, NULL, NULL, BBFDM_BOTH},
//{"SourceClientID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceClientID, set_QoSClassification_SourceClientID, NULL, NULL, BBFDM_BOTH},
//{"SourceClientIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceClientIDExclude, set_QoSClassification_SourceClientIDExclude, NULL, NULL, BBFDM_BOTH},
//{"DestClientID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestClientID, set_QoSClassification_DestClientID, NULL, NULL, BBFDM_BOTH},
//{"DestClientIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestClientIDExclude, set_QoSClassification_DestClientIDExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceUserClassID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceUserClassID, set_QoSClassification_SourceUserClassID, NULL, NULL, BBFDM_BOTH},
//{"SourceUserClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceUserClassIDExclude, set_QoSClassification_SourceUserClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"DestUserClassID", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestUserClassID, set_QoSClassification_DestUserClassID, NULL, NULL, BBFDM_BOTH},
//{"DestUserClassIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestUserClassIDExclude, set_QoSClassification_DestUserClassIDExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorSpecificInfo", &DMWRITE, DMT_HEXBIN, get_QoSClassification_SourceVendorSpecificInfo, set_QoSClassification_SourceVendorSpecificInfo, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorSpecificInfoExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_SourceVendorSpecificInfoExclude, set_QoSClassification_SourceVendorSpecificInfoExclude, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorSpecificInfoEnterprise", &DMWRITE, DMT_UNINT, get_QoSClassification_SourceVendorSpecificInfoEnterprise, set_QoSClassification_SourceVendorSpecificInfoEnterprise, NULL, NULL, BBFDM_BOTH},
//{"SourceVendorSpecificInfoSubOption", &DMWRITE, DMT_INT, get_QoSClassification_SourceVendorSpecificInfoSubOption, set_QoSClassification_SourceVendorSpecificInfoSubOption, NULL, NULL, BBFDM_BOTH},
//{"DestVendorSpecificInfo", &DMWRITE, DMT_HEXBIN, get_QoSClassification_DestVendorSpecificInfo, set_QoSClassification_DestVendorSpecificInfo, NULL, NULL, BBFDM_BOTH},
//{"DestVendorSpecificInfoExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DestVendorSpecificInfoExclude, set_QoSClassification_DestVendorSpecificInfoExclude, NULL, NULL, BBFDM_BOTH},
//{"DestVendorSpecificInfoEnterprise", &DMWRITE, DMT_UNINT, get_QoSClassification_DestVendorSpecificInfoEnterprise, set_QoSClassification_DestVendorSpecificInfoEnterprise, NULL, NULL, BBFDM_BOTH},
//{"DestVendorSpecificInfoSubOption", &DMWRITE, DMT_INT, get_QoSClassification_DestVendorSpecificInfoSubOption, set_QoSClassification_DestVendorSpecificInfoSubOption, NULL, NULL, BBFDM_BOTH},
//{"TCPACK", &DMWRITE, DMT_BOOL, get_QoSClassification_TCPACK, set_QoSClassification_TCPACK, NULL, NULL, BBFDM_BOTH},
//{"TCPACKExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_TCPACKExclude, set_QoSClassification_TCPACKExclude, NULL, NULL, BBFDM_BOTH},
//{"IPLengthMin", &DMWRITE, DMT_UNINT, get_QoSClassification_IPLengthMin, set_QoSClassification_IPLengthMin, NULL, NULL, BBFDM_BOTH},
//{"IPLengthMax", &DMWRITE, DMT_UNINT, get_QoSClassification_IPLengthMax, set_QoSClassification_IPLengthMax, NULL, NULL, BBFDM_BOTH},
//{"IPLengthExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_IPLengthExclude, set_QoSClassification_IPLengthExclude, NULL, NULL, BBFDM_BOTH},
//{"DSCPCheck", &DMWRITE, DMT_INT, get_QoSClassification_DSCPCheck, set_QoSClassification_DSCPCheck, NULL, NULL, BBFDM_BOTH},
//{"DSCPExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_DSCPExclude, set_QoSClassification_DSCPExclude, NULL, NULL, BBFDM_BOTH},
//{"DSCPMark", &DMWRITE, DMT_INT, get_QoSClassification_DSCPMark, set_QoSClassification_DSCPMark, NULL, NULL, BBFDM_BOTH},
//{"EthernetPriorityCheck", &DMWRITE, DMT_INT, get_QoSClassification_EthernetPriorityCheck, set_QoSClassification_EthernetPriorityCheck, NULL, NULL, BBFDM_BOTH},
//{"EthernetPriorityExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthernetPriorityExclude, set_QoSClassification_EthernetPriorityExclude, NULL, NULL, BBFDM_BOTH},
//{"EthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSClassification_EthernetPriorityMark, set_QoSClassification_EthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"InnerEthernetPriorityCheck", &DMWRITE, DMT_INT, get_QoSClassification_InnerEthernetPriorityCheck, set_QoSClassification_InnerEthernetPriorityCheck, NULL, NULL, BBFDM_BOTH},
//{"InnerEthernetPriorityExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_InnerEthernetPriorityExclude, set_QoSClassification_InnerEthernetPriorityExclude, NULL, NULL, BBFDM_BOTH},
//{"InnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSClassification_InnerEthernetPriorityMark, set_QoSClassification_InnerEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"EthernetDEICheck", &DMWRITE, DMT_INT, get_QoSClassification_EthernetDEICheck, set_QoSClassification_EthernetDEICheck, NULL, NULL, BBFDM_BOTH},
//{"EthernetDEIExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_EthernetDEIExclude, set_QoSClassification_EthernetDEIExclude, NULL, NULL, BBFDM_BOTH},
//{"VLANIDCheck", &DMWRITE, DMT_INT, get_QoSClassification_VLANIDCheck, set_QoSClassification_VLANIDCheck, NULL, NULL, BBFDM_BOTH},
//{"VLANIDExclude", &DMWRITE, DMT_BOOL, get_QoSClassification_VLANIDExclude, set_QoSClassification_VLANIDExclude, NULL, NULL, BBFDM_BOTH},
//{"OutOfBandInfo", &DMWRITE, DMT_INT, get_QoSClassification_OutOfBandInfo, set_QoSClassification_OutOfBandInfo, NULL, NULL, BBFDM_BOTH},
//{"ForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSClassification_ForwardingPolicy, set_QoSClassification_ForwardingPolicy, NULL, NULL, BBFDM_BOTH},
//{"TrafficClass", &DMWRITE, DMT_INT, get_QoSClassification_TrafficClass, set_QoSClassification_TrafficClass, NULL, NULL, BBFDM_BOTH},
//{"Policer", &DMWRITE, DMT_STRING, get_QoSClassification_Policer, set_QoSClassification_Policer, NULL, NULL, BBFDM_BOTH},
//{"App", &DMWRITE, DMT_STRING, get_QoSClassification_App, set_QoSClassification_App, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.App.{i}. *** */
DMLEAF tQoSAppParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSApp_Enable, set_QoSApp_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSApp_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSApp_Alias, set_QoSApp_Alias, NULL, NULL, BBFDM_BOTH},
//{"ProtocolIdentifier", &DMWRITE, DMT_STRING, get_QoSApp_ProtocolIdentifier, set_QoSApp_ProtocolIdentifier, NULL, NULL, BBFDM_BOTH},
//{"Name", &DMWRITE, DMT_STRING, get_QoSApp_Name, set_QoSApp_Name, NULL, NULL, BBFDM_BOTH},
//{"DefaultForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSApp_DefaultForwardingPolicy, set_QoSApp_DefaultForwardingPolicy, NULL, NULL, BBFDM_BOTH},
//{"DefaultTrafficClass", &DMWRITE, DMT_UNINT, get_QoSApp_DefaultTrafficClass, set_QoSApp_DefaultTrafficClass, NULL, NULL, BBFDM_BOTH},
//{"DefaultPolicer", &DMWRITE, DMT_STRING, get_QoSApp_DefaultPolicer, set_QoSApp_DefaultPolicer, NULL, NULL, BBFDM_BOTH},
//{"DefaultDSCPMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultDSCPMark, set_QoSApp_DefaultDSCPMark, NULL, NULL, BBFDM_BOTH},
//{"DefaultEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultEthernetPriorityMark, set_QoSApp_DefaultEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"DefaultInnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSApp_DefaultInnerEthernetPriorityMark, set_QoSApp_DefaultInnerEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Flow.{i}. *** */
DMLEAF tQoSFlowParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSFlow_Enable, set_QoSFlow_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSFlow_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSFlow_Alias, set_QoSFlow_Alias, NULL, NULL, BBFDM_BOTH},
//{"Type", &DMWRITE, DMT_STRING, get_QoSFlow_Type, set_QoSFlow_Type, NULL, NULL, BBFDM_BOTH},
//{"TypeParameters", &DMWRITE, DMT_STRING, get_QoSFlow_TypeParameters, set_QoSFlow_TypeParameters, NULL, NULL, BBFDM_BOTH},
//{"Name", &DMWRITE, DMT_STRING, get_QoSFlow_Name, set_QoSFlow_Name, NULL, NULL, BBFDM_BOTH},
//{"App", &DMWRITE, DMT_STRING, get_QoSFlow_App, set_QoSFlow_App, NULL, NULL, BBFDM_BOTH},
//{"ForwardingPolicy", &DMWRITE, DMT_UNINT, get_QoSFlow_ForwardingPolicy, set_QoSFlow_ForwardingPolicy, NULL, NULL, BBFDM_BOTH},
//{"TrafficClass", &DMWRITE, DMT_UNINT, get_QoSFlow_TrafficClass, set_QoSFlow_TrafficClass, NULL, NULL, BBFDM_BOTH},
//{"Policer", &DMWRITE, DMT_STRING, get_QoSFlow_Policer, set_QoSFlow_Policer, NULL, NULL, BBFDM_BOTH},
//{"DSCPMark", &DMWRITE, DMT_INT, get_QoSFlow_DSCPMark, set_QoSFlow_DSCPMark, NULL, NULL, BBFDM_BOTH},
//{"EthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSFlow_EthernetPriorityMark, set_QoSFlow_EthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
//{"InnerEthernetPriorityMark", &DMWRITE, DMT_INT, get_QoSFlow_InnerEthernetPriorityMark, set_QoSFlow_InnerEthernetPriorityMark, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Policer.{i}. *** */
DMLEAF tQoSPolicerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSPolicer_Enable, set_QoSPolicer_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSPolicer_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSPolicer_Alias, set_QoSPolicer_Alias, NULL, NULL, BBFDM_BOTH},
//{"CommittedRate", &DMWRITE, DMT_UNINT, get_QoSPolicer_CommittedRate, set_QoSPolicer_CommittedRate, NULL, NULL, BBFDM_BOTH},
//{"CommittedBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_CommittedBurstSize, set_QoSPolicer_CommittedBurstSize, NULL, NULL, BBFDM_BOTH},
//{"ExcessBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_ExcessBurstSize, set_QoSPolicer_ExcessBurstSize, NULL, NULL, BBFDM_BOTH},
//{"PeakRate", &DMWRITE, DMT_UNINT, get_QoSPolicer_PeakRate, set_QoSPolicer_PeakRate, NULL, NULL, BBFDM_BOTH},
//{"PeakBurstSize", &DMWRITE, DMT_UNINT, get_QoSPolicer_PeakBurstSize, set_QoSPolicer_PeakBurstSize, NULL, NULL, BBFDM_BOTH},
//{"MeterType", &DMWRITE, DMT_STRING, get_QoSPolicer_MeterType, set_QoSPolicer_MeterType, NULL, NULL, BBFDM_BOTH},
//{"PossibleMeterTypes", &DMREAD, DMT_STRING, get_QoSPolicer_PossibleMeterTypes, NULL, NULL, NULL, BBFDM_BOTH},
//{"ConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_ConformingAction, set_QoSPolicer_ConformingAction, NULL, NULL, BBFDM_BOTH},
//{"PartialConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_PartialConformingAction, set_QoSPolicer_PartialConformingAction, NULL, NULL, BBFDM_BOTH},
//{"NonConformingAction", &DMWRITE, DMT_STRING, get_QoSPolicer_NonConformingAction, set_QoSPolicer_NonConformingAction, NULL, NULL, BBFDM_BOTH},
//{"TotalCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_TotalCountedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"TotalCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_TotalCountedBytes, NULL, NULL, NULL, BBFDM_BOTH},
//{"ConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_ConformingCountedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"ConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_ConformingCountedBytes, NULL, NULL, NULL, BBFDM_BOTH},
//{"PartiallyConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_PartiallyConformingCountedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"PartiallyConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_PartiallyConformingCountedBytes, NULL, NULL, NULL, BBFDM_BOTH},
//{"NonConformingCountedPackets", &DMREAD, DMT_UNINT, get_QoSPolicer_NonConformingCountedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"NonConformingCountedBytes", &DMREAD, DMT_UNINT, get_QoSPolicer_NonConformingCountedBytes, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Queue.{i}. *** */
DMLEAF tQoSQueueParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_QoSQueue_Enable, set_QoSQueue_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_QoSQueue_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_QoSQueue_Alias, set_QoSQueue_Alias, NULL, NULL, BBFDM_BOTH},
{"TrafficClasses", &DMWRITE, DMT_STRING, get_QoSQueue_TrafficClasses, set_QoSQueue_TrafficClasses, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_QoSQueue_Interface, set_QoSQueue_Interface, NULL, NULL, BBFDM_BOTH},
//{"AllInterfaces", &DMWRITE, DMT_BOOL, get_QoSQueue_AllInterfaces, set_QoSQueue_AllInterfaces, NULL, NULL, BBFDM_BOTH},
//{"HardwareAssisted", &DMREAD, DMT_BOOL, get_QoSQueue_HardwareAssisted, NULL, NULL, NULL, BBFDM_BOTH},
//{"BufferLength", &DMREAD, DMT_UNINT, get_QoSQueue_BufferLength, NULL, NULL, NULL, BBFDM_BOTH},
{"Weight", &DMWRITE, DMT_UNINT, get_QoSQueue_Weight, set_QoSQueue_Weight, NULL, NULL, BBFDM_BOTH},
{"Precedence", &DMWRITE, DMT_UNINT, get_QoSQueue_Precedence, set_QoSQueue_Precedence, NULL, NULL, BBFDM_BOTH},
//{"REDThreshold", &DMWRITE, DMT_UNINT, get_QoSQueue_REDThreshold, set_QoSQueue_REDThreshold, NULL, NULL, BBFDM_BOTH},
//{"REDPercentage", &DMWRITE, DMT_UNINT, get_QoSQueue_REDPercentage, set_QoSQueue_REDPercentage, NULL, NULL, BBFDM_BOTH},
//{"DropAlgorithm", &DMWRITE, DMT_STRING, get_QoSQueue_DropAlgorithm, set_QoSQueue_DropAlgorithm, NULL, NULL, BBFDM_BOTH},
{"SchedulerAlgorithm", &DMWRITE, DMT_STRING, get_QoSQueue_SchedulerAlgorithm, set_QoSQueue_SchedulerAlgorithm, NULL, NULL, BBFDM_BOTH},
{"ShapingRate", &DMWRITE, DMT_INT, get_QoSQueue_ShapingRate, set_QoSQueue_ShapingRate, NULL, NULL, BBFDM_BOTH},
{"ShapingBurstSize", &DMWRITE, DMT_UNINT, get_QoSQueue_ShapingBurstSize, set_QoSQueue_ShapingBurstSize, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.QueueStats.{i}. *** */
DMLEAF tQoSQueueStatsParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_QoSQueueStats_Enable, set_QoSQueueStats_Enable, NULL, NULL, BBFDM_BOTH},
//{"Status", &DMREAD, DMT_STRING, get_QoSQueueStats_Status, NULL, NULL, NULL, BBFDM_BOTH},
//{"Alias", &DMWRITE, DMT_STRING, get_QoSQueueStats_Alias, set_QoSQueueStats_Alias, NULL, NULL, BBFDM_BOTH},
//{"Queue", &DMWRITE, DMT_STRING, get_QoSQueueStats_Queue, set_QoSQueueStats_Queue, NULL, NULL, BBFDM_BOTH},
//{"Interface", &DMWRITE, DMT_STRING, get_QoSQueueStats_Interface, set_QoSQueueStats_Interface, NULL, NULL, BBFDM_BOTH},
//{"OutputPackets", &DMREAD, DMT_UNINT, get_QoSQueueStats_OutputPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"OutputBytes", &DMREAD, DMT_UNINT, get_QoSQueueStats_OutputBytes, NULL, NULL, NULL, BBFDM_BOTH},
//{"DroppedPackets", &DMREAD, DMT_UNINT, get_QoSQueueStats_DroppedPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"DroppedBytes", &DMREAD, DMT_UNINT, get_QoSQueueStats_DroppedBytes, NULL, NULL, NULL, BBFDM_BOTH},
//{"QueueOccupancyPackets", &DMREAD, DMT_UNINT, get_QoSQueueStats_QueueOccupancyPackets, NULL, NULL, NULL, BBFDM_BOTH},
//{"QueueOccupancyPercentage", &DMREAD, DMT_UNINT, get_QoSQueueStats_QueueOccupancyPercentage, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.QoS.Shaper.{i}. *** */
DMLEAF tQoSShaperParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_QoSShaper_Enable, set_QoSShaper_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_QoSShaper_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_QoSShaper_Alias, set_QoSShaper_Alias, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_QoSShaper_Interface, set_QoSShaper_Interface, NULL, NULL, BBFDM_BOTH},
{"ShapingRate", &DMWRITE, DMT_INT, get_QoSShaper_ShapingRate, set_QoSShaper_ShapingRate, NULL, NULL, BBFDM_BOTH},
{"ShapingBurstSize", &DMWRITE, DMT_UNINT, get_QoSShaper_ShapingBurstSize, set_QoSShaper_ShapingBurstSize, NULL, NULL, BBFDM_BOTH},
{0}
};


