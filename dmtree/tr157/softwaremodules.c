/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "dmentry.h"
#include "softwaremodules.h"

/**************************************************************************
* LINKER
***************************************************************************/
static int get_exe_cenv_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data) {
		char *name = dmjson_get_value((json_object *)data, 1, "name");
		*linker = dmstrdup(name);
		return 0;
	}
	*linker = "";
	return 0;
}

static int get_du_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker)
{
	if (data) {
		char *name = dmjson_get_value((json_object *)data, 1, "name");
		char *environment = dmjson_get_value((json_object *)data, 1, "environment");
		dmasprintf(linker, "%s-%s", name, environment);
		return 0;
	}
	*linker = "";
	return 0;
}

/*************************************************************
* ENTRY METHOD
*************************************************************/
static int browseSoftwareModulesExecEnvInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	char *idx, *idx_last = NULL;
	int id = 0, j = 0;

	dmubus_call("swmodules", "environment", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "environment") {
			idx = handle_update_instance(1, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)du_obj, idx) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int browseSoftwareModulesDeploymentUnitInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	char *idx, *idx_last = NULL;
	int id = 0, j = 0;

	dmubus_call("swmodules", "du_list", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "deployment_unit") {
			idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)du_obj, idx) == DM_STOP)
				break;
		}
	}
	return 0;
}

static int browseSoftwareModulesExecutionUnitInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	char *idx, *idx_last = NULL;
	int id = 0, j = 0;

	dmubus_call("swmodules", "eu_list", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "execution_unit") {
			idx = handle_update_instance(2, dmctx, &idx_last, update_instance_without_section, 1, ++id);
			if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)du_obj, idx) == DM_STOP)
				break;
		}
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
*************************************************************/
static int get_SoftwareModules_ExecEnvNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *environment = NULL;
	size_t nbre_env = 0;

	dmubus_call("swmodules", "environment", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "environment", &environment);
	nbre_env = json_object_array_length(environment);
	dmasprintf(value, "%d", nbre_env);
	return 0;
}

static int get_SoftwareModules_DeploymentUnitNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *deployment_unit = NULL;
	size_t nbre_du = 0;

	dmubus_call("swmodules", "du_list", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "deployment_unit", &deployment_unit);
	nbre_du = json_object_array_length(deployment_unit);
	dmasprintf(value, "%d", nbre_du);
	return 0;
}

static int get_SoftwareModules_ExecutionUnitNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *execution_unit = NULL;
	size_t nbre_env = 0;

	dmubus_call("swmodules", "eu_list", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "0");
	json_object_object_get_ex(res, "execution_unit", &execution_unit);
	nbre_env = json_object_array_length(execution_unit);
	dmasprintf(value, "%d", nbre_env);
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.Enable!UBUS:swmodules/environment//environment[i-1].status*/
static int get_SoftwareModulesExecEnv_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "status");
	if (strcmp(*value, "Up") == 0)
		*value = "1";
	else
		*value = "0";
	return 0;
}

static int set_SoftwareModulesExecEnv_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *env_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			env_name = dmjson_get_value((json_object *)data, 1, "name");
			if (strcmp(env_name, "OpenWRT_Linux")) {
				if (b)
					dmcmd_no_wait("/usr/bin/lxc-start", 2, "-n", env_name);
				else
					dmcmd_no_wait("/usr/bin/lxc-stop", 2, "-n", env_name);
			}
			break;
	}
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.Status!UBUS:swmodules/environment//environment[i-1].status*/
static int get_SoftwareModulesExecEnv_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "status");
	return 0;
}

static int get_SoftwareModulesExecEnv_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

static int set_SoftwareModulesExecEnv_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;
	char *env_name;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			env_name = dmjson_get_value((json_object *)data, 1, "name");
			if (strcmp(env_name, "OpenWRT_Linux") == 0) {
				if (b) dmcmd_no_wait("/sbin/defaultreset", 0);
			}
			break;
	}
	return 0;
}

static int get_SoftwareModulesExecEnv_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *env_name, *name;

	name = dmjson_get_value((json_object *)data, 1, "name");
	uci_path_foreach_sections(bbfdm, "dmmap", "environment", s) {
		dmuci_get_value_by_section_string(s, "name", &env_name);
		if (strcmp(env_name, name) == 0) {
			dmuci_get_value_by_section_string(s, "alias", value);
			if ((*value)[0] == '\0')
				dmasprintf(value, "cpe-%s", instance);
			return 0;
		}
	}
	return 0;
}

static int set_SoftwareModulesExecEnv_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;
	char *name, *v;
	int found = 0;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			name = dmjson_get_value((json_object *)data, 1, "name");
			uci_path_foreach_option_eq(bbfdm, "dmmap", "environment", "name", name, s) {
				dmuci_set_value_by_section_bbfdm(s, "alias", value);
				found = 1;
			}
			if (!found) {
				dmuci_add_section_bbfdm("dmmap", "environment", &dmmap, &v);
				dmuci_set_value_by_section(dmmap, "name", name);
				dmuci_set_value_by_section(dmmap, "alias", value);
			}
			break;
	}
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.Name!UBUS:swmodules/environment//environment[i-1].name*/
static int get_SoftwareModulesExecEnv_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "name");
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.Type!UBUS:swmodules/environment//environment[i-1].type*/
static int get_SoftwareModulesExecEnv_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "type");
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.Vendor!UBUS:swmodules/environment//environment[i-1].vendor*/
static int get_SoftwareModulesExecEnv_Vendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "vendor");
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.Version!UBUS:swmodules/environment//environment[i-1].version*/
static int get_SoftwareModulesExecEnv_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "version");
	return 0;
}

static int get_SoftwareModulesExecEnv_ParentExecEnv(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *env_name = dmjson_get_value((json_object *)data, 1, "name");
	*value = "";
	if (strcmp(env_name, "OpenWRT_Linux")) {
		char *linker = dmstrdup(env_name);
		adm_entry_get_linker_param(ctx, dm_print_path("%s%cSoftwareModules%cExecEnv%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
		if (*value == NULL) {
			*value = "";
			return 0;
		}
	}
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.AllocatedDiskSpace!UBUS:swmodules/environment//environment[i-1].allocateddiskspace*/
static int get_SoftwareModulesExecEnv_AllocatedDiskSpace(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "allocated_disk_space");
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.AvailableDiskSpace!UBUS:swmodules/environment//environment[i-1].availablediskspace*/
static int get_SoftwareModulesExecEnv_AvailableDiskSpace(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "available_disk_space");
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.AllocatedMemory!UBUS:swmodules/environment//environment[i-1].allocatedmemory*/
static int get_SoftwareModulesExecEnv_AllocatedMemory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "allocated_memory");
	return 0;
}

/*#Device.SoftwareModules.ExecEnv.{i}.AvailableMemory!UBUS:swmodules/environment//environment[i-1].availablememory*/
static int get_SoftwareModulesExecEnv_AvailableMemory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "available_memory");
	return 0;
}

static int get_SoftwareModulesExecEnv_ActiveExecutionUnits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	int j = 0, env = 0;
	char *environment, *eu_list = NULL, *eu_list_tmp = NULL;

	char *curr_env = dmjson_get_value((json_object *)data, 1, "name");
	dmubus_call("swmodules", "eu_list", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "execution_unit") {
		env++;
		environment = dmjson_get_value(du_obj, 1, "environment");
		if (strcmp(environment, curr_env) == 0) {
			if(!eu_list) {
				dmasprintf(&eu_list, "%s", dm_print_path("%s%cSoftwareModules%cExecutionUnit%c%d%c", dmroot, dm_delim, dm_delim, dm_delim, env, dm_delim));
			} else {
				eu_list_tmp = dmstrdup(eu_list);
				dmfree(eu_list);
				dmasprintf(&eu_list, "%s,%s", eu_list_tmp, dm_print_path("%s%cSoftwareModules%cExecutionUnit%c%d%c", dmroot, dm_delim, dm_delim, dm_delim, env, dm_delim));
				dmfree(eu_list_tmp);
			}
		}
	}
	if(eu_list)
		*value = eu_list;
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.UUID!UBUS:swmodules/du_list//deployment_unit[i-1].uuid*/
static int get_SoftwareModulesDeploymentUnit_UUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "uuid");
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.DUID!UBUS:swmodules/du_list//deployment_unit[i-1].duid*/
static int get_SoftwareModulesDeploymentUnit_DUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "duid");
	return 0;
}

static int get_SoftwareModulesDeploymentUnit_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *du_name, *du_env, *environment, *name;

	name = dmjson_get_value((json_object *)data, 1, "name");
	environment = dmjson_get_value((json_object *)data, 1, "environment");
	uci_path_foreach_sections(bbfdm, "dmmap", "deployment_unit", s) {
		dmuci_get_value_by_section_string(s, "name", &du_name);
		dmuci_get_value_by_section_string(s, "environment", &du_env);
		if ((strcmp(du_name, name) == 0) && (strcmp(du_env, environment) == 0)) {
			dmuci_get_value_by_section_string(s, "alias", value);
			if ((*value)[0] == '\0')
				dmasprintf(value, "cpe-%s", instance);
			return 0;
		}
	}
	return 0;
}

static int set_SoftwareModulesDeploymentUnit_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;
	char *du_name, *du_env, *environment, *name, *v;
	int found = 0;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			name = dmjson_get_value((json_object *)data, 1, "name");
			environment = dmjson_get_value((json_object *)data, 1, "environment");
			uci_path_foreach_sections(bbfdm, "dmmap", "deployment_unit", s) {
				dmuci_get_value_by_section_string(s, "name", &du_name);
				dmuci_get_value_by_section_string(s, "environment", &du_env);
				if ((strcmp(du_name, name) == 0) && (strcmp(du_env, environment) == 0)) {
					dmuci_set_value_by_section_bbfdm(s, "alias", value);
					found = 1;
					break;
				}
			}
			if (!found) {
				dmuci_add_section_bbfdm("dmmap", "deployment_unit", &dmmap, &v);
				dmuci_set_value_by_section(dmmap, "name", name);
				dmuci_set_value_by_section(dmmap, "environment", environment);
				dmuci_set_value_by_section(dmmap, "alias", value);
			}
			break;
	}
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.Name!UBUS:swmodules/du_list//deployment_unit[i-1].name*/
static int get_SoftwareModulesDeploymentUnit_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "name");
	return 0;
}

static int get_SoftwareModulesDeploymentUnit_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Installed";
	return 0;
}

static int get_SoftwareModulesDeploymentUnit_Resolved(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.URL!UBUS:swmodules/du_list//deployment_unit[i-1].url*/
static int get_SoftwareModulesDeploymentUnit_URL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "url");
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.Description!UBUS:swmodules/du_list//deployment_unit[i-1].description*/
static int get_SoftwareModulesDeploymentUnit_Description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "description");
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.Vendor!UBUS:swmodules/du_list//deployment_unit[i-1].vendor*/
static int get_SoftwareModulesDeploymentUnit_Vendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "vendor");
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.Version!UBUS:swmodules/du_list//deployment_unit[i-1].version*/
static int get_SoftwareModulesDeploymentUnit_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "version");
	return 0;
}

static int get_SoftwareModulesDeploymentUnit_VendorLogList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.VendorConfigList!UBUS:swmodules/du_list//deployment_unit[i-1].config*/
static int get_SoftwareModulesDeploymentUnit_VendorConfigList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *name, *vcf_instance, *config;

	*value = "";
	config = dmjson_get_value((json_object *)data, 1, "config");
	if (!strlen(config))
		return 0;

	uci_path_foreach_sections(bbfdm, DMMAP, "vcf", s) {
		dmuci_get_value_by_section_string(s, "name", &name);
		if (strcmp(name, config) == 0) {
			dmuci_get_value_by_section_string(s, "vcf_instance", &vcf_instance);
			*value = strdup(dm_print_path("%s%cDeviceInfo%cVendorConfigFile%c%s%c", dmroot, dm_delim, dm_delim, dm_delim, vcf_instance, dm_delim));
			break;
		}
	}
	return 0;
}

static int get_SoftwareModulesDeploymentUnit_ExecutionUnitList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	char *environment, *name, *curr_environment, *curr_name;
	int j = 0, env = 0;

	curr_name = dmjson_get_value((json_object *)data, 1, "name");
	curr_environment = dmjson_get_value((json_object *)data, 1, "environment");

	dmubus_call("swmodules", "eu_list", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "execution_unit") {
		env++;
		name = dmjson_get_value(du_obj, 1, "name");
		environment = dmjson_get_value(du_obj, 1, "environment");
		if ((strcmp(name, curr_name) == 0) && (strcmp(environment, curr_environment) == 0)) {
			dmasprintf(value, "%s", dm_print_path("%s%cSoftwareModules%cExecutionUnit%c%d%c", dmroot, dm_delim, dm_delim, dm_delim, env, dm_delim));
			break;
		}
	}
	return 0;
}

/*#Device.SoftwareModules.DeploymentUnit.{i}.ExecutionEnvRef!UBUS:swmodules/du_list//deployment_unit[i-1].environment*/
static int get_SoftwareModulesDeploymentUnit_ExecutionEnvRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "environment");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cSoftwareModules%cExecEnv%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL) {
		*value = "";
		return 0;
	}
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.EUID!UBUS:swmodules/eu_list//execution_unit[i-1].euid*/
static int get_SoftwareModulesExecutionUnit_EUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "euid");
	return 0;
}

static int get_SoftwareModulesExecutionUnit_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *eu_euid, *eu_env, *environment, *euid;

	euid = dmjson_get_value((json_object *)data, 1, "euid");
	environment = dmjson_get_value((json_object *)data, 1, "environment");
	uci_path_foreach_sections(bbfdm, "dmmap", "execution_unit", s) {
		dmuci_get_value_by_section_string(s, "euid", &eu_euid);
		dmuci_get_value_by_section_string(s, "environment", &eu_env);
		if ((strcmp(eu_euid, euid) == 0) && (strcmp(eu_env, environment) == 0)) {
			dmuci_get_value_by_section_string(s, "alias", value);
			if ((*value)[0] == '\0')
				dmasprintf(value, "cpe-%s", instance);
			return 0;
		}
	}
	return 0;
}

static int set_SoftwareModulesExecutionUnit_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *s = NULL, *dmmap = NULL;
	char *eu_euid, *eu_env, *environment, *euid, *v;
	int found = 0;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			euid = dmjson_get_value((json_object *)data, 1, "euid");
			environment = dmjson_get_value((json_object *)data, 1, "environment");
			uci_path_foreach_sections(bbfdm, "dmmap", "execution_unit", s) {
				dmuci_get_value_by_section_string(s, "euid", &eu_euid);
				dmuci_get_value_by_section_string(s, "environment", &eu_env);
				if ((strcmp(eu_euid, euid) == 0) && (strcmp(eu_env, environment) == 0)) {
					dmuci_set_value_by_section_bbfdm(s, "alias", value);
					found = 1;
					break;
				}
			}
			if (!found) {
				dmuci_add_section_bbfdm("dmmap", "execution_unit", &dmmap, &v);
				dmuci_set_value_by_section(dmmap, "euid", euid);
				dmuci_set_value_by_section(dmmap, "environment", environment);
				dmuci_set_value_by_section(dmmap, "alias", value);
			}
			break;
	}
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.Name!UBUS:swmodules/eu_list//execution_unit[i-1].name*/
static int get_SoftwareModulesExecutionUnit_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "name");
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.ExecEnvLabel!UBUS:swmodules/eu_list//execution_unit[i-1].euid*/
static int get_SoftwareModulesExecutionUnit_ExecEnvLabel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "euid");
	return 0;
}

static int get_SoftwareModulesExecutionUnit_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "Active";
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.Vendor!UBUS:swmodules/eu_list//execution_unit[i-1].vendor*/
static int get_SoftwareModulesExecutionUnit_Vendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "vendor");
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.Version!UBUS:swmodules/eu_list//execution_unit[i-1].version*/
static int get_SoftwareModulesExecutionUnit_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "version");
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.Description!UBUS:swmodules/eu_list//execution_unit[i-1].description*/
static int get_SoftwareModulesExecutionUnit_Description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "description");
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.DiskSpaceInUse!UBUS:swmodules/eu_list//execution_unit[i-1].disk_space*/
static int get_SoftwareModulesExecutionUnit_DiskSpaceInUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "disk_space");
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.MemoryInUse!UBUS:swmodules/eu_list//execution_unit[i-1].memory_space*/
static int get_SoftwareModulesExecutionUnit_MemoryInUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmjson_get_value((json_object *)data, 1, "memory_space");
	return 0;
}

static int get_SoftwareModulesExecutionUnit_References(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	char *environment, *name, *curr_environment, *curr_name;
	int j = 0, env = 0;

	curr_name = dmjson_get_value((json_object *)data, 1, "name");
	curr_environment = dmjson_get_value((json_object *)data, 1, "environment");

	dmubus_call("swmodules", "du_list", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "deployment_unit") {
			env++;
			name = dmjson_get_value(du_obj, 1, "name");
			environment = dmjson_get_value(du_obj, 1, "environment");
			if ((strcmp(name, curr_name) == 0) && (strcmp(environment, curr_environment) == 0)) {
				dmasprintf(value, "%s", dm_print_path("%s%cSoftwareModules%cDeploymentUnit%c%d%c", dmroot, dm_delim, dm_delim, dm_delim, env, dm_delim));
				break;
			}
		}
	}
	return 0;
}

static int get_SoftwareModulesExecutionUnit_AssociatedProcessList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	json_object *res = NULL, *processes_obj = NULL, *arrobj = NULL;
	char *euid, *pid;
	int j = 0, process = 0;

	euid = dmjson_get_value((json_object *)data, 1, "euid");
	dmubus_call("router.system", "processes", UBUS_ARGS{}, 0, &res);
	DM_ASSERT(res, *value = "");
	dmjson_foreach_obj_in_array(res, arrobj, processes_obj, j, 1, "processes") {
		process++;
		pid = dmjson_get_value(processes_obj, 1, "PID");
		if (strcmp(euid, pid) == 0) {
			dmasprintf(value, "%s", dm_print_path("%s%cDeviceInfo%cProcessStatus%cProcess%c%d%c", dmroot, dm_delim, dm_delim, dm_delim, dm_delim, process, dm_delim));
			break;
		}
	}
	return 0;
}

static int get_SoftwareModulesExecutionUnit_VendorLogList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.VendorConfigList!UBUS:swmodules/eu_list//execution_unit[i-1].config*/
static int get_SoftwareModulesExecutionUnit_VendorConfigList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	char *name, *vcf_instance, *config;

	*value = "";
	config = dmjson_get_value((json_object *)data, 1, "config");
	if (!strlen(config))
		return 0;

	uci_path_foreach_sections(bbfdm, DMMAP, "vcf", s) {
		dmuci_get_value_by_section_string(s, "name", &name);
		if (strcmp(name, config) == 0) {
			dmuci_get_value_by_section_string(s, "vcf_instance", &vcf_instance);
			*value = strdup(dm_print_path("%s%cDeviceInfo%cVendorConfigFile%c%s%c", dmroot, dm_delim, dm_delim, dm_delim, vcf_instance, dm_delim));
			break;
		}
	}
	return 0;
}

/*#Device.SoftwareModules.ExecutionUnit.{i}.ExecutionEnvRef!UBUS:swmodules/eu_list//execution_unit[i-1].environment*/
static int get_SoftwareModulesExecutionUnit_ExecutionEnvRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *linker = dmjson_get_value((json_object *)data, 1, "environment");
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cSoftwareModules%cExecEnv%c", dmroot, dm_delim, dm_delim, dm_delim), linker, value);
	if (*value == NULL) {
		*value = "";
		return 0;
	}
	return 0;
}

char *get_deployment_unit_reference(struct dmctx *ctx, char *package_name, char *package_env)
{
	char *linker, *value;
	dmasprintf(&linker, "%s-%s", package_name, package_env);
	adm_entry_get_linker_param(ctx, dm_print_path("%s%cSoftwareModules%cDeploymentUnit%c", dmroot, dm_delim, dm_delim, dm_delim), linker, &value);
	return value;
}

void get_deployment_unit_name_version(char *uuid, char **name, char **version, char **env)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	int j = 0;
	char *cur_uuid;

	dmubus_call("swmodules", "du_list", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "deployment_unit") {
			cur_uuid = dmjson_get_value(du_obj, 1, "uuid");
			if (strcmp(cur_uuid, uuid) == 0) {
				*name = dmjson_get_value(du_obj, 1, "name");
				*version = dmjson_get_value(du_obj, 1, "version");
				*env = dmjson_get_value(du_obj, 1, "environment");
				return;
			}
		}
	}
}

char *get_softwaremodules_uuid(char *url)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	char *cur_url, *uuid = "";
	int j = 0;

	dmubus_call("swmodules", "du_list", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "deployment_unit") {
			cur_url = dmjson_get_value(du_obj, 1, "url");
			if (strcmp(cur_url, url) == 0) {
				uuid = dmjson_get_value(du_obj, 1, "uuid");
				break;
			}
		}
	}
	return uuid;
}

char *get_softwaremodules_url(char *uuid)
{
	json_object *res = NULL, *du_obj = NULL, *arrobj = NULL;
	char *cur_uuid, *url = "";
	int j = 0;

	dmubus_call("swmodules", "du_list", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmjson_foreach_obj_in_array(res, arrobj, du_obj, j, 1, "deployment_unit") {
			cur_uuid = dmjson_get_value(du_obj, 1, "uuid");
			if (strcmp(cur_uuid, uuid) == 0) {
				url = dmjson_get_value(du_obj, 1, "url");
				break;
			}
		}
	}
	return url;
}

/* *** Device.SoftwareModules. *** */
DMOBJ tSoftwareModulesObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"ExecEnv", &DMREAD, NULL, NULL, NULL, browseSoftwareModulesExecEnvInst, NULL, NULL, NULL, NULL, tSoftwareModulesExecEnvParams, get_exe_cenv_linker, BBFDM_BOTH},
{"DeploymentUnit", &DMREAD, NULL, NULL, NULL, browseSoftwareModulesDeploymentUnitInst, NULL, NULL, NULL, NULL, tSoftwareModulesDeploymentUnitParams, get_du_linker, BBFDM_BOTH},
{"ExecutionUnit", &DMREAD, NULL, NULL, NULL, browseSoftwareModulesExecutionUnitInst, NULL, NULL, NULL, tSoftwareModulesExecutionUnitObj, tSoftwareModulesExecutionUnitParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tSoftwareModulesParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ExecEnvNumberOfEntries", &DMREAD, DMT_UNINT, get_SoftwareModules_ExecEnvNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"DeploymentUnitNumberOfEntries", &DMREAD, DMT_UNINT, get_SoftwareModules_DeploymentUnitNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"ExecutionUnitNumberOfEntries", &DMREAD, DMT_UNINT, get_SoftwareModules_ExecutionUnitNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.SoftwareModules.ExecEnv.{i}. *** */
DMLEAF tSoftwareModulesExecEnvParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_SoftwareModulesExecEnv_Enable, set_SoftwareModulesExecEnv_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_SoftwareModulesExecEnv_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Reset", &DMWRITE, DMT_BOOL, get_SoftwareModulesExecEnv_Reset, set_SoftwareModulesExecEnv_Reset, NULL, NULL, BBFDM_CWMP},
{"Alias", &DMWRITE, DMT_STRING, get_SoftwareModulesExecEnv_Alias, set_SoftwareModulesExecEnv_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_SoftwareModulesExecEnv_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"Type", &DMREAD, DMT_STRING, get_SoftwareModulesExecEnv_Type, NULL, NULL, NULL, BBFDM_BOTH},
//{"InitialRunLevel", &DMWRITE, DMT_UNINT, get_SoftwareModulesExecEnv_InitialRunLevel, set_SoftwareModulesExecEnv_InitialRunLevel, NULL, NULL, BBFDM_BOTH},
//{"RequestedRunLevel", &DMWRITE, DMT_INT, get_SoftwareModulesExecEnv_RequestedRunLevel, set_SoftwareModulesExecEnv_RequestedRunLevel, NULL, NULL, BBFDM_CWMP},
//{"CurrentRunLevel", &DMREAD, DMT_INT, get_SoftwareModulesExecEnv_CurrentRunLevel, NULL, NULL, NULL, BBFDM_BOTH},
//{"InitialExecutionUnitRunLevel", &DMWRITE, DMT_INT, get_SoftwareModulesExecEnv_InitialExecutionUnitRunLevel, set_SoftwareModulesExecEnv_InitialExecutionUnitRunLevel, NULL, NULL, BBFDM_BOTH},
{"Vendor", &DMREAD, DMT_STRING, get_SoftwareModulesExecEnv_Vendor, NULL, NULL, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_SoftwareModulesExecEnv_Version, NULL, NULL, NULL, BBFDM_BOTH},
{"ParentExecEnv", &DMREAD, DMT_STRING, get_SoftwareModulesExecEnv_ParentExecEnv, NULL, NULL, NULL, BBFDM_BOTH},
{"AllocatedDiskSpace", &DMREAD, DMT_INT, get_SoftwareModulesExecEnv_AllocatedDiskSpace, NULL, NULL, NULL, BBFDM_BOTH},
{"AvailableDiskSpace", &DMREAD, DMT_INT, get_SoftwareModulesExecEnv_AvailableDiskSpace, NULL, NULL, NULL, BBFDM_BOTH},
{"AllocatedMemory", &DMREAD, DMT_INT, get_SoftwareModulesExecEnv_AllocatedMemory, NULL, NULL, NULL, BBFDM_BOTH},
{"AvailableMemory", &DMREAD, DMT_INT, get_SoftwareModulesExecEnv_AvailableMemory, NULL, NULL, NULL, BBFDM_BOTH},
{"ActiveExecutionUnits", &DMREAD, DMT_STRING, get_SoftwareModulesExecEnv_ActiveExecutionUnits, NULL, NULL, NULL, BBFDM_BOTH},
//{"ProcessorRefList", &DMREAD, DMT_STRING, get_SoftwareModulesExecEnv_ProcessorRefList, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.SoftwareModules.DeploymentUnit.{i}. *** */
DMLEAF tSoftwareModulesDeploymentUnitParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"UUID", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_UUID, NULL, NULL, NULL, BBFDM_BOTH},
{"DUID", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_DUID, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_SoftwareModulesDeploymentUnit_Alias, set_SoftwareModulesDeploymentUnit_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"Resolved", &DMREAD, DMT_BOOL, get_SoftwareModulesDeploymentUnit_Resolved, NULL, NULL, NULL, BBFDM_BOTH},
{"URL", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_URL, NULL, NULL, NULL, BBFDM_BOTH},
{"Description", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_Description, NULL, NULL, NULL, BBFDM_BOTH},
{"Vendor", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_Vendor, NULL, NULL, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_Version, NULL, NULL, NULL, BBFDM_BOTH},
{"VendorLogList", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_VendorLogList, NULL, NULL, NULL, BBFDM_BOTH},
{"VendorConfigList", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_VendorConfigList, NULL, NULL, NULL, BBFDM_BOTH},
{"ExecutionUnitList", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_ExecutionUnitList, NULL, NULL, NULL, BBFDM_BOTH},
{"ExecutionEnvRef", &DMREAD, DMT_STRING, get_SoftwareModulesDeploymentUnit_ExecutionEnvRef, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.SoftwareModules.ExecutionUnit.{i}. *** */
DMOBJ tSoftwareModulesExecutionUnitObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
//{"Extensions", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tSoftwareModulesExecutionUnitParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"EUID", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_EUID, NULL, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_SoftwareModulesExecutionUnit_Alias, set_SoftwareModulesExecutionUnit_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_Name, NULL, NULL, NULL, BBFDM_BOTH},
{"ExecEnvLabel", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_ExecEnvLabel, NULL, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_Status, NULL, NULL, &DMACTIVE, BBFDM_BOTH},
//{"RequestedState", &DMWRITE, DMT_STRING, get_SoftwareModulesExecutionUnit_RequestedState, set_SoftwareModulesExecutionUnit_RequestedState, NULL, NULL, BBFDM_CWMP},
//{"ExecutionFaultCode", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_ExecutionFaultCode, NULL, NULL, NULL, BBFDM_BOTH},
//{"ExecutionFaultMessage", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_ExecutionFaultMessage, NULL, NULL, NULL, BBFDM_BOTH},
//{"AutoStart", &DMWRITE, DMT_BOOL, get_SoftwareModulesExecutionUnit_AutoStart, set_SoftwareModulesExecutionUnit_AutoStart, NULL, NULL, BBFDM_BOTH},
//{"RunLevel", &DMWRITE, DMT_UNINT, get_SoftwareModulesExecutionUnit_RunLevel, set_SoftwareModulesExecutionUnit_RunLevel, NULL, NULL, BBFDM_BOTH},
{"Vendor", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_Vendor, NULL, NULL, NULL, BBFDM_BOTH},
{"Version", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_Version, NULL, NULL, NULL, BBFDM_BOTH},
{"Description", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_Description, NULL, NULL, NULL, BBFDM_BOTH},
{"DiskSpaceInUse", &DMREAD, DMT_INT, get_SoftwareModulesExecutionUnit_DiskSpaceInUse, NULL, NULL, NULL, BBFDM_BOTH},
{"MemoryInUse", &DMREAD, DMT_INT, get_SoftwareModulesExecutionUnit_MemoryInUse, NULL, NULL, NULL, BBFDM_BOTH},
{"References", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_References, NULL, NULL, NULL, BBFDM_BOTH},
{"AssociatedProcessList", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_AssociatedProcessList, NULL, NULL, NULL, BBFDM_BOTH},
{"VendorLogList", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_VendorLogList, NULL, NULL, NULL, BBFDM_BOTH},
{"VendorConfigList", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_VendorConfigList, NULL, NULL, NULL, BBFDM_BOTH},
//{"SupportedDataModelList", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_SupportedDataModelList, NULL, NULL, NULL, BBFDM_CWMP},
{"ExecutionEnvRef", &DMREAD, DMT_STRING, get_SoftwareModulesExecutionUnit_ExecutionEnvRef, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
