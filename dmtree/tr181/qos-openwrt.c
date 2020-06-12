/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "qos.h"
#include "os.h"

struct queuestats
{
	struct uci_section *dmsect;
	char dev[50];
	char user[50];
	char priomap[50];
	int noqueue;
	int pfifo_fast;
	int refcnt;
	int bands;
	int bytes_sent;
	int pkt_sent;
	int pkt_dropped;
	int pkt_overlimits;
	int pkt_requeues;
	int backlog_b;
	int backlog_p;
	int backlog_requeues;
};

int not_implemented(char **value)
{
	*value = "";
	return 0;
}

/**************************************************************************
* LINKER
***************************************************************************/
int os_get_linker_qos_queue(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	return not_implemented(linker);
}
#if 0
int get_linker_qos_queue(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data && ((struct dmmap_dup *)data)->config_section) {
		dmasprintf(linker,"%s", section_name(((struct dmmap_dup *)data)->config_section));
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}
#endif
/**************************************************************************
* Browse functions
***************************************************************************/
/*#Device.QoS.Classification.{i}.!UCI:qos/classify/dmmap_qos*/
int os_browseQoSClassificationInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *wnum_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "classify", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		wnum =  handle_update_instance(1, dmctx, &wnum_last, update_instance_alias, 3, p->dmmap_section, "classifinstance", "classifalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}
#if 0
int browseQoSAppInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

int browseQoSFlowInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}

int browseQoSPolicerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}
#endif


int os_browseQoSQueueInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}


struct uci_section *get_dup_qos_stats_section_in_dmmap(char *dmmap_package, char *section_type, char *dev)
{
	struct uci_section *s;

	uci_path_foreach_option_eq(bbfdm, dmmap_package, section_type, "dev_link", dev, s) {
		return s;
	}

	return NULL;
}

int os_browseQoSQueueStatsInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *dmmap_sect;
	char *questatsout[256], *instance = NULL, *inst_last = NULL, *v, *lastinstancestore = NULL, dev[50] = "", user[50] = "";
	int length, i, ret;
	struct queuestats queuests = {0}, emptyquestats = {0};
	regex_t regex1 = {}, regex2 = {};

	regcomp(&regex1, "^qdisc noqueue [0-9]*: dev [[:alnum:]]* [[:alnum:]]* refcnt [0-9]*", 0);
	regcomp(&regex2, "^qdisc pfifo_fast [0-9]*: dev [[:alnum:]]* [[:alnum:]]* refcnt [0-9]*", 0);
	check_create_dmmap_package("dmmap_qos");
	command_exec_output_to_array("tc -s qdisc", questatsout, &length);
	for (i = 0; i < length; i++){
		switch (i%3) {
			case 0: ret = regexec(&regex1, questatsout[i], 0, NULL, 0);
				 	if (ret == 0)
				 		sscanf(questatsout[i], "qdisc noqueue %d: dev %49s %49s refcnt %d\n", &queuests.noqueue, dev, user, &queuests.refcnt);
				 	else {
				 		ret= regexec(&regex2, questatsout[i], 0, NULL, 0);
				 		if (ret == 0)
				 			sscanf(questatsout[i], "qdisc pfifo_fast %d: dev %49s %49s refcnt %d\n", &queuests.pfifo_fast, dev, user, &queuests.refcnt);
				 	}
					strcpy(queuests.dev, dev);
					break;
			case 1: sscanf(questatsout[i], " Sent %d bytes %d pkt (dropped %d, overlimits %d requeues %d)\n", &queuests.bytes_sent, &queuests.pkt_sent, &queuests.pkt_dropped, &queuests.pkt_overlimits, &queuests.pkt_requeues);
					break;
			case 2: sscanf(questatsout[i], " backlog %db %dp requeues %d\n", &queuests.backlog_b, &queuests.backlog_p, &queuests.backlog_requeues);
					if ((dmmap_sect = get_dup_qos_stats_section_in_dmmap("dmmap_qos", "qos_queue_stats", queuests.dev)) == NULL) {
						dmuci_add_section_bbfdm("dmmap_qos", "qos_queue_stats", &dmmap_sect, &v);
						DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "dev_link", queuests.dev);
					}
					queuests.dmsect= dmmap_sect;

					if(lastinstancestore != NULL && inst_last !=NULL)
						inst_last= dmstrdup(lastinstancestore);
					instance = handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, dmmap_sect, "queuestatsinstance", "queuestatsalias");
					lastinstancestore= dmstrdup(inst_last);
					if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&queuests, instance) == DM_STOP)
						goto end;
					queuests = emptyquestats;
					break;
		}
	}
	regfree(&regex1);
	regfree(&regex2);
	end:
		return 0;
}


int os_browseQoSShaperInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	return 0;
}


int os_addObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s, *dmmap_qos_classify;
	char *last_inst = NULL, *sect_name = NULL, *qos_comment, *v;
	char ib[8];
	last_inst = get_last_instance_bbfdm("dmmap_qos", "classify", "classifinstance");
	if (last_inst)
		snprintf(ib, sizeof(ib), "%s", last_inst);
	else
		snprintf(ib, sizeof(ib), "%s", "1");
	dmasprintf(&qos_comment, "QoS classify %d", atoi(ib)+1);

	dmuci_add_section("qos", "classify", &s, &sect_name);
	dmuci_set_value_by_section(s, "comment", qos_comment);

	dmuci_add_section_bbfdm("dmmap_qos", "classify", &dmmap_qos_classify, &v);
	dmuci_set_value_by_section(dmmap_qos_classify, "section_name", sect_name);
	*instance = update_instance_bbfdm(dmmap_qos_classify, last_inst, "classifinstance");
	return 0;
}

int os_delObjQoSClassification(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dmmap_dup *p = (struct dmmap_dup*)data;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if(is_section_unnamed(section_name(p->config_section))){
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_qos", "classify", "classifinstance", section_name(p->config_section), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "classifinstance", "dmmap_qos", "classify");
				dmuci_delete_by_section_unnamed(p->config_section, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_qos", "classify", section_name(p->config_section), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(p->config_section, NULL, NULL);
			}
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

int os_addObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s, *dmmap_qos_class;
	char *last_inst = NULL, *sect_name = NULL, *v;
	char ib[8];

	last_inst = get_last_instance_bbfdm("dmmap_qos", "class", "queueinstance");
	if (last_inst)
		snprintf(ib, sizeof(ib), "%s", last_inst);
	else
		snprintf(ib, sizeof(ib), "%s", "1");

	dmuci_add_section("qos", "class", &s, &sect_name);
	dmuci_set_value_by_section(s, "packetsize", "1000");

	dmuci_add_section_bbfdm("dmmap_qos", "class", &dmmap_qos_class, &v);
	dmuci_set_value_by_section(dmmap_qos_class, "section_name", sect_name);
	*instance = update_instance_bbfdm(dmmap_qos_class, last_inst, "queueinstance");
	return 0;
}

int os_delObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name(p->config_section))) {
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_qos", "class", "queueinstance", section_name(p->config_section), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "queueinstance", "dmmap_qos", "class");
				dmuci_delete_by_section_unnamed(p->config_section, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_qos", "class", section_name(p->config_section), &dmmap_section);
				dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(p->config_section, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("qos", "class", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_qos", "class", section_name(ss), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_qos", "class", section_name(ss), &dmmap_section);
				if (dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}
#endif

int os_addObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	return 0;
}

int os_delObjQoSQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return 0;
}


int os_addObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//TODO
	return 0;
}

int os_delObjQoSQueueStats(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	//TODO
	return 0;
}

int os_addObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	return 0;
}

int os_delObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	return 0;
}

#if 0
int addObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s, *dmmap_qos_class;
	char *last_inst = NULL, *sect_name = NULL, *v;
	char ib[8];

	last_inst= get_last_instance_bbfdm_without_update("dmmap_qos", "class", "shaperinstance");
	if (last_inst)
		snprintf(ib, sizeof(ib), "%s", last_inst);
	else
		snprintf(ib, sizeof(ib), "%s", "1");

	dmuci_add_section("qos", "class", &s, &sect_name);
	dmuci_set_value_by_section(s, "limitrate", "1000");

	dmuci_add_section_bbfdm("dmmap_qos", "class", &dmmap_qos_class, &v);
	dmuci_set_value_by_section(dmmap_qos_class, "section_name", sect_name);
	*instance = update_instance_bbfdm(dmmap_qos_class, last_inst, "shaperinstance");
	return 0;
}

int delObjQoSShaper(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	struct uci_section *s, *dmmap_sect;
	switch (del_action) {
		case DEL_INST:
			dmuci_set_value_by_section(p->config_section, "limitrate", "");
			dmuci_set_value_by_section(p->dmmap_section, "shaperinstance", "");
			break;
		case DEL_ALL:
			uci_foreach_sections("qos", "class", s) {
				get_dmmap_section_of_config_section("dmmap_qos", "class", section_name(s), &dmmap_sect);
				dmuci_set_value_by_section(s, "limitrate", "");
				dmuci_set_value_by_section(dmmap_sect, "shaperinstance", "");
			}
			break;
	}
	return 0;
}

int get_QoS_MaxClassificationEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

/*#Device.QoS.ClassificationNumberOfEntries!UCI:qos/classify/*/
int os_get_QoS_ClassificationNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	int nbre= 0;
	uci_foreach_sections("qos", "classify", s) {
		nbre++;
	}
	dmasprintf(value, "%d", nbre);
	return 0;
}

#if 0
int get_QoS_MaxAppEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoS_AppNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoS_MaxFlowEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoS_FlowNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoS_MaxPolicerEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoS_PolicerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoS_MaxQueueEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif
/*#Device.QoS.QueueNumberOfEntries!UCI:qos/class/*/
int os_get_QoS_QueueNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_get_QoS_QueueStatsNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *questatsout[256];
	int length;

	command_exec_output_to_array("tc -s qdisc", questatsout, &length);
	dmasprintf(value, "%d", length/3);
	return 0;
}

int os_get_QoS_ShaperNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

#if 0
int get_QoS_MaxShaperEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoS_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoS_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoS_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoS_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoS_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoS_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoS_DefaultQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker;

	dmuci_get_option_value_string("qos", "Default", "default", &linker);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cQoS%cQueue%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL)
		*value = "";
	return 0;
}


int set_QoS_DefaultQueue(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			dmuci_set_value("qos", "Default", "default", linker);
			break;
	}
	return 0;
}

int get_QoS_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s;
	char *linker, *classtarget;

	dmuci_get_option_value_string("qos", "Default", "default", &linker);
	uci_foreach_sections("qos", "classify", s) {
		dmuci_get_value_by_section_string(s, "target", &classtarget);
		if (strcmp(classtarget, linker) == 0) {
			dmuci_get_value_by_section_string(s, "dscp", value);
			return 0;
		}
	}
	*value= "";
	return 0;
}

int set_QoS_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
int get_QoS_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoS_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoS_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoS_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoS_AvailableAppList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSClassification_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSClassification_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{"1",NULL}}, 1))
				return FAULT_9007;
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
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->dmmap_section, "classifalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

int os_set_QoSClassification_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->dmmap_section, "classifalias", value);
			break;
	}
	return 0;
}

#if 0
int get_QoSClassification_DHCPType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DHCPType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DHCPType, 2, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif

int os_get_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup *) data;
	struct uci_section *s;
	char *classes = NULL, **classesarr, *classgroup = NULL, *ifaceclassgrp, *targetclass;
	size_t length;

	dmuci_get_value_by_section_string(p->config_section, "target", &targetclass);
	uci_foreach_sections("qos", "classgroup", s) {
		dmuci_get_value_by_section_string(s, "classes", &classes);
		classesarr = strsplit(classes, " ", &length);
		if (classes != NULL && is_array_elt_exist(classesarr, targetclass, length)) {
			dmasprintf(&classgroup, "%s", section_name(s));
			break;
		}
	}
	if (classgroup == NULL)
		return 0;
	uci_foreach_sections("qos", "interface", s) {
		dmuci_get_value_by_section_string(s, "classgroup", &ifaceclassgrp);
		if (ifaceclassgrp != NULL && strcmp(ifaceclassgrp, classgroup) == 0) {
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), section_name(s), value);
			if (*value == NULL)
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cPPP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), section_name(s), value);
			if (*value == NULL)
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), section_name(s), value);
			if (*value == NULL)
				*value = "";
		}
	}
	return 0;
}

int os_set_QoSClassification_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

#if 0
int get_QoSClassification_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DestMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, 0, IPPrefix, 3))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SourceMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 49, NULL, 0, IPPrefix, 3))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceIPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_ProtocolExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_ProtocolExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DestPortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestPortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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
#endif

/*#Device.QoS.Classification.{i}.DestIP!UCI:qos/classify,@i-1/dsthost*/
int os_get_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "dsthost", value);
	return 0;
}

int os_set_QoSClassification_DestIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "dsthost", value);
			break;
	}
	return 0;
}



/*#Device.QoS.Classification.{i}.SourceIP!UCI:qos/classify,@i-1/srchost*/
int os_get_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "srchost", value);
	return 0;
}

int os_set_QoSClassification_SourceIP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 45, NULL, 0, IPAddress, 2))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "srchost", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.Protocol!UCI:qos/classify,@i-1/proto*/
int os_get_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "proto", value);
	return 0;
}

int os_set_QoSClassification_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "proto", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.DestPort!UCI:qos/classify,@i-1/dstports*/
int os_get_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "dstports", value);
	return 0;
}

int os_set_QoSClassification_DestPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "dstports", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.DestPortRangeMax!UCI:qos/classify,@i-1/portrange*/
int os_get_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "portrange", value);
	return 0;
}

int os_set_QoSClassification_DestPortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "portrange", value);
			break;
	}
	return 0;
}

/*#Device.QoS.Classification.{i}.SourcePort!UCI:qos/classify,@i-1/srcports*/
int os_get_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "srcports", value);
	return 0;
}

int os_set_QoSClassification_SourcePort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "srcports", value);
			break;
	}
	return 0;
}

#if 0
int get_QoSClassification_SourcePortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourcePortRangeMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourcePortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourcePortExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SourceMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DestMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestMACAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestMACMask(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 17, NULL, 0, MACAddress, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestMACExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_Ethertype(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_Ethertype(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_EthertypeExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_EthertypeExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DSAP(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DSAPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_LLCControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_LLCControl(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_LLCControlExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_LLCControlExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SNAPOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SNAPOUI(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SNAPOUIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SNAPOUIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SourceVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 255, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SourceVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, VendorClassIDMode, 4, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestVendorClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 255, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestVendorClassIDv6(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestVendorClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DestVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestVendorClassIDMode(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, VendorClassIDMode, 4, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DestClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestClientID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestClientIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SourceUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DestUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestUserClassID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestUserClassIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SourceVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_SourceVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_SourceVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_SourceVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"0","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestVendorSpecificInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_hexBinary(value, RANGE_ARGS{{NULL,"65535"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestVendorSpecificInfoExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DestVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestVendorSpecificInfoEnterprise(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DestVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DestVendorSpecificInfoSubOption(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"0","255"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_TCPACK(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_TCPACK(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_TCPACKExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_TCPACKExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_IPLengthMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_IPLengthMin(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_IPLengthMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_IPLengthMax(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_IPLengthExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_IPLengthExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_DSCPCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DSCPCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1","63"}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_DSCPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_DSCPExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

/*#Device.QoS.Classification.{i}.DSCPMark!UCI:qos/classify,@i-1/dscp*/
int get_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup *)data;
	dmuci_get_value_by_section_string(p->config_section, "dscp", value);
	return 0;
}

int set_QoSClassification_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup *)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->config_section, "dscp", value);
			break;
	}
	return 0;
}

int get_QoSClassification_EthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_EthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_EthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_EthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_InnerEthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_InnerEthernetPriorityCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_InnerEthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_InnerEthernetPriorityExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_EthernetDEICheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_EthernetDEICheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_EthernetDEIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_EthernetDEIExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSClassification_OutOfBandInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_OutOfBandInfo(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSClassification_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSClassification_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSApp_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSApp_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_ProtocolIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_ProtocolIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_DefaultForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_DefaultTrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_DefaultPolicer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_DefaultEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSApp_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSApp_DefaultInnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSFlow_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSFlow_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_TypeParameters(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_TypeParameters(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_App(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_ForwardingPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_TrafficClass(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_Policer(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_DSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_EthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSFlow_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSFlow_InnerEthernetPriorityMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-2",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSPolicer_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_CommittedRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_CommittedRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_CommittedBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_CommittedBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_ExcessBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_ExcessBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_PeakRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_PeakRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_PeakBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_PeakBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_MeterType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_MeterType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_PossibleMeterTypes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_ConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_ConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, ConformingAction, 5))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_PartialConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_PartialConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, ConformingAction, 5))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_NonConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSPolicer_NonConformingAction(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, NULL, 0, ConformingAction, 5))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSPolicer_TotalCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_TotalCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_ConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_ConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_PartiallyConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_PartiallyConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_NonConformingCountedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSPolicer_NonConformingCountedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}
#endif

int os_get_QoSQueue_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSQueue_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_get_QoSQueue_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSQueue_TrafficClasses(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_TrafficClasses(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSQueue_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSQueue_Weight(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_Weight(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSQueue_Precedence(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_Precedence(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSQueue_SchedulerAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_SchedulerAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSShaper_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_get_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

int os_get_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_set_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)
	{
	case VALUECHECK:
		break;
	case VALUESET:
		break;
	}
	return 0;
}

#if 0
/*#Device.QoS.Queue.{i}.!UCI:qos/class/dmmap_qos*/
int browseQoSQueueInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *wnum_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "class", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		wnum =  handle_update_instance(1, dmctx, &wnum_last, update_instance_alias, 3, p->dmmap_section, "queueinstance", "queuealias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int get_QoSQueue_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSQueue_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSQueue_HardwareAssisted(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.QoS.Queue.{i}.BufferLength!UCI:qos/class,@i-1/maxsize*/
int get_QoSQueue_BufferLength(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->config_section, "maxsize", value);
	return 0;
}

int get_QoSQueue_REDThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSQueue_REDThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSQueue_REDPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSQueue_REDPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSQueue_DropAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSQueue_DropAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, -1, DropAlgorithm, 4, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

/*#Device.QoS.Queue.{i}.ShapingRate!UCI:qos/class,@i-1/limitrate*/
int get_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	char *rate= NULL;

	dmuci_get_value_by_section_string(p->config_section, "limitrate", &rate);
	if (rate != NULL && atoi(rate)>=0)
		dmasprintf(value, "%s", rate);
	else
		dmasprintf(value, "%s", "-1");
	return 0;
}

int set_QoSQueue_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if(atoi(value)>=0)
				dmuci_set_value_by_section(p->config_section, "limitrate", value);
			else
				dmuci_set_value_by_section(p->config_section, "limitrate", "");

			break;
	}
	return 0;
}

int get_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSQueue_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSQueueStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSQueueStats_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSQueueStats_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSQueueStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSQueueStats_Queue(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif

int os_get_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *qts= (struct queuestats*)data;
	dmuci_get_value_by_section_string(qts->dmsect, "queuestatsalias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
	return 0;
}

int os_set_QoSQueueStats_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct queuestats *qts= (struct queuestats*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(qts->dmsect, "queuestatsalias", value);
			break;
	}
	return 0;
}

int os_get_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *qts= (struct queuestats*)data;

	adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), qts->dev, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cPPP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), qts->dev, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), qts->dev, value);
	if (*value == NULL)
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cWiFi%cRadio%c", dmroot, dm_delim, dm_delim, dm_delim), qts->dev, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int os_set_QoSQueueStats_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int os_get_QoSQueueStats_OutputPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *queuests= (struct queuestats*)data;
	dmasprintf(value, "%d", queuests->pkt_sent);
	return 0;
}

int os_get_QoSQueueStats_OutputBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *queuests= (struct queuestats*)data;
	dmasprintf(value, "%d", queuests->bytes_sent);
	return 0;
}

int os_get_QoSQueueStats_DroppedPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *queuests= (struct queuestats*)data;
	dmasprintf(value, "%d", queuests->pkt_dropped);
	return 0;
}

int os_get_QoSQueueStats_DroppedBytes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	return not_implemented(value);
}

int os_get_QoSQueueStats_QueueOccupancyPackets(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct queuestats *queuests= (struct queuestats*)data;
	dmasprintf(value, "%d", queuests->pkt_requeues);
	return 0;
}

#if 0
int get_QoSQueueStats_QueueOccupancyPercentage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int browseQoSShaperInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *wnum = NULL, *wnum_last = NULL;
	struct dmmap_dup *p;
	char *limitrate = NULL;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("qos", "class", "dmmap_qos", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		dmuci_get_value_by_section_string(p->config_section, "limitrate", &limitrate);
		if (limitrate == NULL || strlen(limitrate) == 0)
			continue;
		wnum = handle_update_instance(1, dmctx, &wnum_last, update_instance_alias, 3, p->dmmap_section, "shaperinstance", "shaperalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p, wnum) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

int get_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSShaper_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
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

int get_QoSShaper_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int get_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	dmuci_get_value_by_section_string(p->dmmap_section, "shaperalias", value);
	return 0;
}

int set_QoSShaper_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section(p->dmmap_section, "shaperalias", value);
			break;
	}
	return 0;
}

int get_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p = (struct dmmap_dup *)data;
	struct uci_section *s;
	char *classes = NULL, **classesarr, *classgroup = NULL, *ifaceclassgrp;
	size_t length;

	uci_foreach_sections("qos", "classgroup", s) {
		dmuci_get_value_by_section_string(s, "classes", &classes);
		classesarr= strsplit(classes, " ", &length);
		if (classes != NULL && is_array_elt_exist(classesarr, section_name(p->config_section), length)){
			dmasprintf(&classgroup, "%s", section_name(s));
			break;
		}
	}
	if(classgroup == NULL)
		return 0;
	uci_foreach_sections("qos", "interface", s) {
		dmuci_get_value_by_section_string(s, "classgroup", &ifaceclassgrp);
		if (ifaceclassgrp != NULL && strcmp(ifaceclassgrp, classgroup) == 0) {
			adm_entry_get_linker_param(ctx, dm_print_path("%s%cIP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), section_name(s), value);
			if (*value == NULL)
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cPPP%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), section_name(s), value);
			if (*value == NULL)
				adm_entry_get_linker_param(ctx, dm_print_path("%s%cEthernet%cInterface%c", dmroot, dm_delim, dm_delim, dm_delim), section_name(s), value);
			if (*value == NULL)
				*value = "";
		}
	}
	return 0;
}

int set_QoSShaper_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 256, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;
	char *rate= NULL;

	dmuci_get_value_by_section_string(p->config_section, "limitrate", &rate);
	if (rate != NULL && atoi(rate)>=0)
		dmasprintf(value, "%s", rate);
	else
		dmasprintf(value, "%s", "-1");
	return 0;
}

int set_QoSShaper_ShapingRate(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dmmap_dup *p= (struct dmmap_dup*)data;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, RANGE_ARGS{{"-1",NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			if(atoi(value)>=0)
				dmuci_set_value_by_section(p->config_section, "limitrate", value);
			else
				dmuci_set_value_by_section(p->config_section, "limitrate", "");

			break;
	}
	return 0;
}

int get_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_QoSShaper_ShapingBurstSize(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, RANGE_ARGS{{NULL,NULL}}, 1))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}
#endif

