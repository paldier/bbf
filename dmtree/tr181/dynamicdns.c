/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include <stdbool.h>
#include "dmbbf.h"
#include "dmcommon.h"
#include "dmuci.h"
#include "dmubus.h"
#include "dmjson.h"
#include "dmentry.h"
#include "dynamicdns.h"

/* *** Device.DynamicDNS. *** */
DMOBJ tDynamicDNSObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Client", &DMWRITE, addObjDynamicDNSClient, delObjDynamicDNSClient, NULL, browseDynamicDNSClientInst, NULL, NULL, NULL, tDynamicDNSClientObj, tDynamicDNSClientParams, NULL, BBFDM_BOTH},
{"Server", &DMWRITE, addObjDynamicDNSServer, delObjDynamicDNSServer, NULL, browseDynamicDNSServerInst, NULL, NULL, NULL, NULL, tDynamicDNSServerParams, get_linker_dynamicdns_server, BBFDM_BOTH},
{0}
};

DMLEAF tDynamicDNSParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ClientNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNS_ClientNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"ServerNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNS_ServerNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"SupportedServices", &DMREAD, DMT_STRING, get_DynamicDNS_SupportedServices, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DynamicDNS.Client.{i}. *** */
DMOBJ tDynamicDNSClientObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"Hostname", &DMWRITE, NULL, NULL, NULL, browseDynamicDNSClientHostnameInst, NULL, NULL, NULL, NULL, tDynamicDNSClientHostnameParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tDynamicDNSClientParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DynamicDNSClient_Enable, set_DynamicDNSClient_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DynamicDNSClient_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Alias, set_DynamicDNSClient_Alias, NULL, NULL, BBFDM_BOTH},
{"LastError", &DMREAD, DMT_STRING, get_DynamicDNSClient_LastError, NULL, NULL, NULL, BBFDM_BOTH},
{"Server", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Server, set_DynamicDNSClient_Server, NULL, NULL, BBFDM_BOTH},
{"Interface", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Interface, set_DynamicDNSClient_Interface, NULL, NULL, BBFDM_BOTH},
{"Username", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Username, set_DynamicDNSClient_Username, NULL, NULL, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_DynamicDNSClient_Password, set_DynamicDNSClient_Password, NULL, NULL, BBFDM_BOTH},
{"HostnameNumberOfEntries", &DMREAD, DMT_UNINT, get_DynamicDNSClient_HostnameNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DynamicDNS.Client.{i}.Hostname.{i}. *** */
DMLEAF tDynamicDNSClientHostnameParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_DynamicDNSClientHostname_Enable, set_DynamicDNSClientHostname_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_DynamicDNSClientHostname_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_DynamicDNSClientHostname_Name, set_DynamicDNSClientHostname_Name, NULL, NULL, BBFDM_BOTH},
{"LastUpdate", &DMREAD, DMT_TIME, get_DynamicDNSClientHostname_LastUpdate, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.DynamicDNS.Server.{i}. *** */
DMLEAF tDynamicDNSServerParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Enable, set_DynamicDNSServer_Enable, NULL, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Name, set_DynamicDNSServer_Name, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Alias, set_DynamicDNSServer_Alias, NULL, NULL, BBFDM_BOTH},
{"ServiceName", &DMWRITE, DMT_STRING, get_DynamicDNSServer_ServiceName, set_DynamicDNSServer_ServiceName, NULL, NULL, BBFDM_BOTH},
{"ServerAddress", &DMWRITE, DMT_STRING, get_DynamicDNSServer_ServerAddress, set_DynamicDNSServer_ServerAddress, NULL, NULL, BBFDM_BOTH},
{"ServerPort", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_ServerPort, set_DynamicDNSServer_ServerPort, NULL, NULL, BBFDM_BOTH},
{"SupportedProtocols", &DMREAD, DMT_STRING, get_DynamicDNSServer_SupportedProtocols, NULL, NULL, NULL, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_STRING, get_DynamicDNSServer_Protocol, set_DynamicDNSServer_Protocol, NULL, NULL, BBFDM_BOTH},
{"CheckInterval", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_CheckInterval, set_DynamicDNSServer_CheckInterval, NULL, NULL, BBFDM_BOTH},
{"RetryInterval", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_RetryInterval, set_DynamicDNSServer_RetryInterval, NULL, NULL, BBFDM_BOTH},
{"MaxRetries", &DMWRITE, DMT_UNINT, get_DynamicDNSServer_MaxRetries, set_DynamicDNSServer_MaxRetries, NULL, NULL, BBFDM_BOTH},
{0}
};

/**************************************************************************
* LINKER
***************************************************************************/
int get_linker_dynamicdns_server(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	char *service_name;
	if (data) {
		dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
		dmasprintf(linker, "%s", service_name);
		return 0;
	} else {
		*linker = "";
		return 0;
	}
}

/*************************************************************
 * ENTRY METHOD
/*************************************************************/
/*#Device.DynamicDNS.Client.{i}.!UCI:ddns/service/dmmap_ddns*/
int browseDynamicDNSClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("ddns", "service", "dmmap_ddns", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, p->dmmap_section, "clientinstance", "clientalias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, inst) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int dmmap_synchronizeDynamicDNSServer(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	struct uci_section *s = NULL, *sddns = NULL, *stmp = NULL, *ss = NULL;
	char *service_name = NULL, *dmmap_service_name = NULL, *name = NULL, *retry_interval = NULL, *retry_unit = NULL;
	char *enabled = NULL, *dns_server = NULL, *use_https = NULL, *check_interval = NULL, *check_unit = NULL, *retry_count = NULL;
	int found;

	check_create_dmmap_package("dmmap_ddns");
	uci_path_foreach_sections_safe(bbfdm, "dmmap_ddns", "ddns_server", stmp, s) {
		dmuci_get_value_by_section_string(s, "service_name", &dmmap_service_name);
		found = 0;
		uci_foreach_sections("ddns", "service", ss) {
			dmuci_get_value_by_section_string(ss, "service_name", &service_name);
			if (strcmp(service_name, dmmap_service_name) == 0) {
				found = 1;
				break;
			}
			if (found)
				break;
		}
		if (!found)
			dmuci_delete_by_section(s, NULL, NULL);
	}

	uci_foreach_sections("ddns", "service", s) {
		dmuci_get_value_by_section_string(s, "service_name", &service_name);
		if (*service_name == '\0')
			continue;
		dmuci_get_value_by_section_string(s, "enabled", &enabled);
		dmuci_get_value_by_section_string(s, "dns_server", &dns_server);
		dmuci_get_value_by_section_string(s, "use_https", &use_https);
		dmuci_get_value_by_section_string(s, "check_interval", &check_interval);
		dmuci_get_value_by_section_string(s, "check_unit", &check_unit);
		dmuci_get_value_by_section_string(s, "retry_interval", &retry_interval);
		dmuci_get_value_by_section_string(s, "retry_unit", &retry_unit);
		dmuci_get_value_by_section_string(s, "retry_count", &retry_count);
		found = 0;
		uci_path_foreach_sections(bbfdm, "dmmap_ddns", "ddns_server", ss) {
			dmuci_get_value_by_section_string(ss, "service_name", &dmmap_service_name);
			if (strcmp(service_name, dmmap_service_name) == 0) {
				found = 1;
				//Update dmmap with ddns config
				dmuci_set_value_by_section(ss, "section_name", section_name(s));
				dmuci_set_value_by_section(ss, "enabled", enabled);
				dmuci_set_value_by_section(ss, "service_name", service_name);
				dmuci_set_value_by_section(ss, "dns_server", dns_server);
				dmuci_set_value_by_section(ss, "use_https", use_https);
				dmuci_set_value_by_section(ss, "check_interval", check_interval);
				dmuci_set_value_by_section(ss, "check_unit", check_unit);
				dmuci_set_value_by_section(ss, "retry_interval", retry_interval);
				dmuci_set_value_by_section(ss, "retry_unit", retry_unit);
				dmuci_set_value_by_section(ss, "retry_count", retry_count);
				break;
			}
		}
		if (found)
			continue;

		dmuci_add_section_bbfdm("dmmap_ddns", "ddns_server", &sddns, &name);
		dmuci_set_value_by_section(sddns, "section_name", section_name(s));
		dmuci_set_value_by_section(sddns, "enabled", enabled);
		dmuci_set_value_by_section(sddns, "service_name", service_name);
		dmuci_set_value_by_section(sddns, "dns_server", dns_server);
		dmuci_set_value_by_section(sddns, "use_https", use_https);
		dmuci_set_value_by_section(sddns, "check_interval", check_interval);
		dmuci_set_value_by_section(sddns, "check_unit", check_unit);
		dmuci_set_value_by_section(sddns, "retry_interval", retry_interval);
		dmuci_set_value_by_section(sddns, "retry_unit", retry_unit);
		dmuci_set_value_by_section(sddns, "retry_count", retry_count);
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.!UCI:ddns/service/dmmap_ddns*/
int browseDynamicDNSServerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *inst = NULL, *inst_last = NULL;
	struct uci_section *s = NULL;

	dmmap_synchronizeDynamicDNSServer(dmctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_ddns", "ddns_server", s)
	{
		inst =  handle_update_instance(1, dmctx, &inst_last, update_instance_alias, 3, s, "serverinstance", "serveralias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, inst) == DM_STOP)
			break;
	}
	return 0;
}

int browseDynamicDNSClientHostnameInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	DM_LINK_INST_OBJ(dmctx, parent_node, prev_data, "1");
	return 0;
}

/*************************************************************
 * ADD & DEL OBJ
/*************************************************************/
int addObjDynamicDNSClient(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char inst[8], *last_inst, *value, *v, *s_name;
	struct uci_section *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_ddns");
	last_inst = get_last_instance_bbfdm("dmmap_ddns", "service", "clientinstance");
	sprintf(inst, "%s", last_inst ? last_inst : "1");
	dmasprintf(&s_name, "Ddns_%d", atoi(inst)+1);

	dmuci_add_section("ddns", "service", &s, &value);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "enabled", "1");
	dmuci_set_value_by_section(s, "use_syslog", "0");
	dmuci_set_value_by_section(s, "use_https", "0");
	dmuci_set_value_by_section(s, "force_interval", "72");
	dmuci_set_value_by_section(s, "force_unit", "hours");
	dmuci_set_value_by_section(s, "check_interval", "10");
	dmuci_set_value_by_section(s, "check_unit", "minutes");
	dmuci_set_value_by_section(s, "retry_interval", "60");
	dmuci_set_value_by_section(s, "retry_unit", "value");
	dmuci_set_value_by_section(s, "ip_source", "interface");

	dmuci_add_section_bbfdm("dmmap_ddns", "service", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap, last_inst, "clientinstance");
	return 0;
}

int delObjDynamicDNSClient(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name((struct uci_section *)data), &dmmap_section);
			if(dmmap_section != NULL)
				dmuci_delete_by_section(dmmap_section, NULL, NULL);
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("ddns", "service", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name(ss), &dmmap_section);
				if(dmmap_section != NULL)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

int addObjDynamicDNSServer(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	char inst[8], *last_inst, *value, *v, *s_name;
	struct uci_section *dmmap = NULL, *s = NULL;

	check_create_dmmap_package("dmmap_ddns");
	last_inst = get_last_instance_bbfdm("dmmap_ddns", "ddns_server", "serverinstance");
	sprintf(inst, "%s", last_inst ? last_inst : "1");
	dmasprintf(&s_name, "server_%d", atoi(inst)+1);
	dmuci_add_section("ddns", "service", &s, &value);
	dmuci_rename_section_by_section(s, s_name);
	dmuci_set_value_by_section(s, "service_name", s_name);
	dmuci_set_value_by_section(s, "enabled", "1");
	dmuci_set_value_by_section(s, "use_syslog", "0");
	dmuci_set_value_by_section(s, "use_https", "0");
	dmuci_set_value_by_section(s, "force_interval", "72");
	dmuci_set_value_by_section(s, "force_unit", "hours");
	dmuci_set_value_by_section(s, "check_interval", "10");
	dmuci_set_value_by_section(s, "check_unit", "minutes");
	dmuci_set_value_by_section(s, "retry_interval", "60");
	dmuci_set_value_by_section(s, "retry_unit", "value");
	dmuci_set_value_by_section(s, "ip_source", "interface");

	dmuci_add_section_bbfdm("dmmap_ddns", "ddns_server", &dmmap, &v);
	dmuci_set_value_by_section(dmmap, "section_name", section_name(s));
	*instance = update_instance_bbfdm(dmmap, last_inst, "serverinstance");
	return 0;
}

int delObjDynamicDNSServer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *stmp = NULL, *dmmap_section= NULL;
	int found = 0;
	char *service_name;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq_safe("ddns", "service", "service_name", service_name, stmp, s) {
				dmuci_delete_by_section(s, NULL, NULL);
			}
			dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			break;
		case DEL_ALL:
			uci_foreach_sections("ddns", "service", s) {
				if (found != 0){
					get_dmmap_section_of_config_section("dmmap_ddns", "ddns_server", section_name(ss), &dmmap_section);
					if(dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_ddns", "ddns_server", section_name(ss), &dmmap_section);
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
/*************************************************************/
int get_DynamicDNS_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("ddns", "service", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

int get_DynamicDNS_ServerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	dmmap_synchronizeDynamicDNSServer(ctx, NULL, NULL, NULL);
	uci_path_foreach_sections(bbfdm, "dmmap_ddns", "ddns_server", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

int get_DynamicDNS_SupportedServices(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	FILE *fp = NULL;
	char line[256] = "", buf[1024] = "", buf_tmp[1024] = "", *pch = NULL, *spch = NULL;

	*value = "";
	fp = fopen(DDNS_PROVIDERS_FILE, "r");
	if ( fp != NULL) {
		while (fgets(line, 256, fp) != NULL) {
			if (line[0] == '#')
				continue;

			pch = strtok_r(line, "\t", &spch);
			remove_substring(pch, "\"");
			remove_substring(pch, " ");
			if (strcmp(buf, "") == 0) {
				sprintf(buf, "%s", pch);
			} else {
				strcpy(buf_tmp, buf);
				sprintf(buf, "%s,%s", buf_tmp, pch);
			}
		}
		fclose(fp);
		*value = dmstrdup(buf);
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Enable!UCI:ddns/service,@i-1/enabled*/
int get_DynamicDNSClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", value);
	if (*value[0] == '\0')
		*value = "0";
	return 0;
}

int set_DynamicDNSClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Status!UCI:ddns/service,@i-1/enabled*/
int get_DynamicDNSClient_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	FILE* fp = NULL;
	char buf[512] = "", path[64] = "", status[32] = "", *enable, *logdir = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enable);
	if (*enable == '\0' || strcmp(enable, "0") == 0) {
		strcpy(status, "Disabled");
	} else {
		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		if (*logdir == '\0')
			logdir = "/var/log/ddns";
		sprintf(path, "%s/%s.log", logdir, section_name((struct uci_section *)data));
		fp = fopen(path, "r");
		if (fp != NULL) {
			strcpy(status, "Connecting");
			while (fgets(buf, 512, fp) != NULL) {
				if (strstr(buf, "Update successful"))
					strcpy(status, "Updated");
				else if (strstr(buf, "ERROR") && strstr(buf, "Please check your configuration"))
					strcpy(status, "Error_Misconfigured");
				else if (strstr(buf, "Registered IP"))
					strcpy(status, "Connecting");
				else if (strstr(buf, "failed"))
					strcpy(status, "Error");
			}
			fclose(fp);
		} else
			strcpy(status, "Error");
	}
	*value = dmstrdup(status);
	return 0;
}

int get_DynamicDNSClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section;
	get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name((struct uci_section *)data), &dmmap_section);
	if (dmmap_section)
		dmuci_get_value_by_section_string(dmmap_section, "clientalias", value);
	return 0;
}

int set_DynamicDNSClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_ddns", "service", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(dmmap_section, "clientalias", value);
			break;
	}
	return 0;
}

int get_DynamicDNSClient_LastError(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	FILE* fp = NULL;
	char buf[512] = "", path[64] = "", status[32] = "", *enable, *logdir = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enable);
	if (*enable == '\0' || strcmp(enable, "0") == 0) {
		strcpy(status, "NO_ERROR");
	} else {
		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		if (*logdir == '\0')
			logdir = "/var/log/ddns";
		sprintf(path, "%s/%s.log", logdir, section_name((struct uci_section *)data));
		fp = fopen(path, "r");
		if (fp != NULL) {
			strcpy(status, "NO_ERROR");
			while (fgets(buf, 512, fp) != NULL) {
				if (strstr(buf, "ERROR") && strstr(buf, "Please check your configuration"))
					strcpy(status, "MISCONFIGURATION_ERROR");
				else if (strstr(buf, "NO valid IP found"))
					strcpy(status, "DNS_ERROR");
				else if (strstr(buf, "Authentication Failed"))
					strcpy(status, "AUTHENTICATION_ERROR");
				else if (strstr(buf, "Transfer failed") || (strstr(buf, "WARN") && strstr(buf, "failed")))
					strcpy(status, "CONNECTION_ERROR");
				else if (strstr(buf, "Registered IP") || strstr(buf, "Update successful"))
					strcpy(status, "NO_ERROR");
			}
			fclose(fp);
		} else
			strcpy(status, "MISCONFIGURATION_ERROR");
	}
	*value = dmstrdup(status);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Server!UCI:ddns/service,@i-1/service_name*/
int get_DynamicDNSClient_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *service_name;
	dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
	adm_entry_get_linker_param(ctx, "Device.DynamicDNS.Server.", service_name, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int set_DynamicDNSClient_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker)
				dmuci_set_value_by_section((struct uci_section *)data, "service_name", linker);
			else
				return FAULT_9005;
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Interface!UCI:ddns/service,@i-1/interface*/
int get_DynamicDNSClient_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *interface;
	dmuci_get_value_by_section_string((struct uci_section *)data, "interface", &interface);
	adm_entry_get_linker_param(ctx, "Device.IP.Interface.", interface, value);
	if (*value == NULL)
		*value = "";
	return 0;
}

int set_DynamicDNSClient_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *linker = NULL;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			adm_entry_get_linker_value(ctx, value, &linker);
			if (linker)
				dmuci_set_value_by_section((struct uci_section *)data, "interface", linker);
			else
				return FAULT_9005;
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Username!UCI:ddns/service,@i-1/username*/
int get_DynamicDNSClient_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "username", value);
	return 0;
}

int set_DynamicDNSClient_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "username", value);
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Password!UCI:ddns/service,@i-1/password*/
int get_DynamicDNSClient_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

int set_DynamicDNSClient_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "password", value);
			break;
	}
	return 0;
}

int get_DynamicDNSClient_HostnameNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Enable!UCI:ddns/service,@i-1/enabled*/
int get_DynamicDNSClientHostname_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", value);
	if (*value[0] == '\0')
		*value = "0";
	return 0;
}

int set_DynamicDNSClientHostname_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	switch (action)	{
		case VALUECHECK:
			if (string_to_bool(value, &b))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Status!UCI:ddns/service,@i-1/enabled*/
int get_DynamicDNSClientHostname_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	FILE* fp = NULL;
	char buf[512] = "", path[64] = "", status[32] = "", *enable, *logdir = NULL;

	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", &enable);
	if (*enable == '\0' || strcmp(enable, "0") == 0) {
		strcpy(status, "Disabled");
	} else {
		dmuci_get_option_value_string("ddns", "global", "ddns_logdir", &logdir);
		if (*logdir == '\0')
			logdir = "/var/log/ddns";
		sprintf(path, "%s/%s.log", logdir, section_name((struct uci_section *)data));
		fp = fopen(path, "r");
		if (fp != NULL) {
			strcpy(status, "Registered");
			while (fgets(buf, 512, fp) != NULL) {
				if (strstr(buf, "Registered IP") || strstr(buf, "Update successful"))
					strcpy(status, "Registered");
				else if (strstr(buf, "Update needed"))
					strcpy(status, "UpdateNeeded");
				else if (strstr(buf, "NO valid IP found"))
					strcpy(status, "Error");
			}
			fclose(fp);
		} else
			strcpy(status, "Error");
	}
	*value = dmstrdup(status);
	return 0;
}

/*#Device.DynamicDNS.Client.{i}.Hostname.{i}.Name!UCI:ddns/service,@i-1/domain*/
int get_DynamicDNSClientHostname_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "domain", value);
	return 0;
}

int set_DynamicDNSClientHostname_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "domain", value);
			dmuci_set_value_by_section((struct uci_section *)data, "lookup_host", value);
			break;
	}
	return 0;
}

int get_DynamicDNSClientHostname_LastUpdate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct tm *ts;
	time_t epoch_time, now = time(NULL);
	FILE* fp = NULL;
	char *pch = NULL, *spch = NULL, *last_time = NULL, *uptime = NULL, *rundir = NULL;
	char current_time[32] = "", buf[16] = "", path[64] = "";
	*value = "0";

	dmuci_get_option_value_string("ddns", "global", "ddns_rundir", &rundir);
	if (*rundir == '\0')
		rundir = "/var/run/ddns";
	sprintf(path, "%s/%s.update", rundir, section_name((struct uci_section *)data));

	fp = fopen(path, "r");
	if (fp != NULL) {
		fgets(buf, 16, fp);
		pch = strtok_r(buf, "\n", &spch);
		fclose(fp);
		last_time = dmstrdup(pch);
	} else
		last_time = "0";

	fp = fopen("/proc/uptime", "r");
	if (fp != NULL) {
		fgets(buf, 16, fp);
		pch = strtok_r(buf, ".", &spch);
		fclose(fp);
		uptime = dmstrdup(pch);
	} else
		uptime = "0";

	epoch_time = now - atoi(uptime) + atoi(last_time);
	ts = localtime(&epoch_time);
	strftime(current_time, sizeof(current_time), "%Y-%m-%dT%H:%M:%S%Z", ts);
	*value = dmstrdup(current_time);
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.Enable!UCI:ddns/service,@i-1/enabled*/
int get_DynamicDNSServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", value);
	if (*value[0] == '\0')
		*value = "0";
	return 0;
}

int set_DynamicDNSServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", value);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "enabled", value);
			}
			break;
	}
	return 0;
}

int get_DynamicDNSServer_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "section_name", value);
	return 0;
}

int set_DynamicDNSServer_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "section_name", value);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_rename_section_by_section(s, value);
				break;
			}
			break;
	}
	return 0;
}

int get_DynamicDNSServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "serveralias", value);
	return 0;
}

int set_DynamicDNSServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "serveralias", value);
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.ServiceName!UCI:ddns/service,@i-1/service_name*/
int get_DynamicDNSServer_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", value);
	return 0;
}

int set_DynamicDNSServer_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "service_name", value);
			}
			dmuci_set_value_by_section((struct uci_section *)data, "service_name", value);
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.ServerAddress!UCI:ddns/service,@i-1/dns_server*/
int get_DynamicDNSServer_ServerAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dns_server;

	dmuci_get_value_by_section_string((struct uci_section *)data, "dns_server", &dns_server);
	if (*dns_server == '\0') {
		dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", value);
	} else {
		char *addr = strchr(dns_server, ':');
		if (addr)
			*addr = '\0';
		*value = dmstrdup(dns_server);
	}
	return 0;
}

int set_DynamicDNSServer_ServerAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char new[64], *dns_server, *service_name;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "dns_server", &dns_server);
			if (*dns_server == '\0') {
				dmuci_set_value_by_section((struct uci_section *)data, "dns_server", value);
			} else {
				char *addr = strchr(dns_server, ':');
				if (addr)
					sprintf(new, "%s%s", value, addr);
				else
					strcpy(new, value);
				dmuci_set_value_by_section((struct uci_section *)data, "dns_server", new);
			}
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_get_value_by_section_string(s, "dns_server", &dns_server);
				if (*dns_server == '\0') {
					dmuci_set_value_by_section(s, "dns_server", value);
				} else {
					char *addr = strchr(dns_server, ':');
					if (addr)
						sprintf(new, "%s%s", value, addr);
					else
						strcpy(new, value);
					dmuci_set_value_by_section(s, "dns_server", new);
				}


			}


			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.ServerPort!UCI:ddns/service,@i-1/dns_server*/
int get_DynamicDNSServer_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *dns_server;
	*value = "0";

	dmuci_get_value_by_section_string((struct uci_section *)data, "dns_server", &dns_server);
	if (*dns_server == '\0')
		return 0;

	char *port = strchr(dns_server, ':');
	if (port)
		*value = dmstrdup(port);
	return 0;
}

int set_DynamicDNSServer_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char new[64], *dns_server, *service_name;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "dns_server", &dns_server);
			if (*dns_server == '\0') {
				dmuci_set_value_by_section((struct uci_section *)data, "dns_server", value);
			} else {
				char *addr = strchr(dns_server, ':');
				if (addr) {
					*addr = '\0';
					sprintf(new, "%s%s", dns_server, value);
				} else {
					sprintf(new, "%s:%s", dns_server, value);
				}
				dmuci_set_value_by_section((struct uci_section *)data, "dns_server", new);
			}
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_get_value_by_section_string(s, "dns_server", &dns_server);
				if (*dns_server == '\0') {
					dmuci_set_value_by_section(s, "dns_server", value);
				} else {
					char *addr = strchr(dns_server, ':');
					if (addr) {
						*addr = '\0';
						sprintf(new, "%s%s", dns_server, value);
					} else {
						sprintf(new, "%s:%s", dns_server, value);
					}
					dmuci_set_value_by_section(s, "dns_server", new);
				}
			}
			break;
	}
	return 0;
}

int get_DynamicDNSServer_SupportedProtocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP,HTTPS";
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.Protocol!UCI:ddns/service,@i-1/use_https*/
int get_DynamicDNSServer_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "use_https", value);
	if (*value[0] == '\0' || strcmp(*value, "0") == 0)
		*value = "HTTP";
	else
		*value = "HTTPS";
	return 0;
}

int set_DynamicDNSServer_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			if (strcmp(value, "HTTP") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "use_https", "0");
			else if (strcmp(value, "HTTPS") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "use_https", "1");
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				if (strcmp(value, "HTTP") == 0)
					dmuci_set_value_by_section(s, "use_https", "0");
				else if (strcmp(value, "HTTPS") == 0)
					dmuci_set_value_by_section(s, "use_https", "1");
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.CheckInterval!UCI:ddns/service,@i-1/check_interval*/
int get_DynamicDNSServer_CheckInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "check_interval", value);
	if (*value[0] == '\0')
		*value = "600";
	return 0;
}

int set_DynamicDNSServer_CheckInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char buf[16] = "", *check_unit, *service_name;
	int check_interval = 0;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "check_unit", &check_unit);
			if (strcmp(check_unit, "hours") == 0)
				check_interval = atoi(value) * 3600;
			else if (strcmp(check_unit, "minutes") == 0)
				check_interval = atoi(value) * 60;
			else
				check_interval = atoi(value);
			sprintf(buf, "%d", check_interval);
			dmuci_set_value_by_section((struct uci_section *)data, "check_interval", buf);

			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "check_interval", buf);
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.RetryInterval!UCI:ddns/service,@i-1/retry_interval*/
int get_DynamicDNSServer_RetryInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "retry_interval", value);
	if (*value[0] == '\0')
		*value = "259200";
	return 0;
}

int set_DynamicDNSServer_RetryInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char buf[16] = "", *retry_unit, *service_name;
	int retry_interval = 0;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_get_value_by_section_string((struct uci_section *)data, "retry_unit", &retry_unit);
			if (strcmp(retry_unit, "hours") == 0)
				retry_interval = atoi(value) * 3600;
			else if (strcmp(retry_unit, "minutes") == 0)
				retry_interval = atoi(value) * 60;
			else
				retry_interval = atoi(value);
			sprintf(buf, "%d", retry_interval);
			dmuci_set_value_by_section((struct uci_section *)data, "retry_interval", buf);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "retry_interval", buf);
			}
			break;
	}
	return 0;
}

/*#Device.DynamicDNS.Server.{i}.MaxRetries!UCI:ddns/service,@i-1/retry_count*/
int get_DynamicDNSServer_MaxRetries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "retry_count", value);
	if (*value[0] == '\0')
		*value = "5";
	return 0;
}

int set_DynamicDNSServer_MaxRetries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s;
	char *service_name;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "retry_count", value);
			dmuci_get_value_by_section_string((struct uci_section *)data, "service_name", &service_name);
			uci_foreach_option_eq("ddns", "service", "service_name", service_name, s) {
				dmuci_set_value_by_section(s, "retry_count", value);
			}
			break;
	}
	return 0;
}

