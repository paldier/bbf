/*
*      This program is free software: you can redistribute it and/or modify
*      it under the terms of the GNU General Public License as published by
*      the Free Software Foundation, either version 2 of the License, or
*      (at your option) any later version.
*
*      Copyright (C) 2019 iopsys Software Solutions AB
*		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
*/

#ifndef __SOFTWAREMODULES_H
#define __SOFTWAREMODULES_H

extern DMOBJ tSoftwareModulesObj[];
extern DMLEAF tSoftwareModulesParams[];
extern DMLEAF tSoftwareModulesExecEnvParams[];
extern DMLEAF tSoftwareModulesDeploymentUnitParams[];
extern DMOBJ tSoftwareModulesExecutionUnitObj[];
extern DMLEAF tSoftwareModulesExecutionUnitParams[];

int browseSoftwareModulesExecEnvInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseSoftwareModulesDeploymentUnitInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseSoftwareModulesExecutionUnitInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int get_SoftwareModules_ExecEnvNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModules_DeploymentUnitNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModules_ExecutionUnitNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecEnv_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecEnv_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecEnv_Reset(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecEnv_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecEnv_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecEnv_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_Type(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_InitialRunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecEnv_InitialRunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecEnv_RequestedRunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecEnv_RequestedRunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecEnv_CurrentRunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_InitialExecutionUnitRunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecEnv_InitialExecutionUnitRunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecEnv_Vendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_ParentExecEnv(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_AllocatedDiskSpace(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_AvailableDiskSpace(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_AllocatedMemory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_AvailableMemory(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_ActiveExecutionUnits(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecEnv_ProcessorRefList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_UUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_DUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesDeploymentUnit_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesDeploymentUnit_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_Resolved(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_URL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_Description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_Vendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_VendorLogList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_VendorConfigList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_ExecutionUnitList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesDeploymentUnit_ExecutionEnvRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_EUID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecutionUnit_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecutionUnit_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_ExecEnvLabel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_RequestedState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecutionUnit_RequestedState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecutionUnit_ExecutionFaultCode(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_ExecutionFaultMessage(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_AutoStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecutionUnit_AutoStart(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecutionUnit_RunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SoftwareModulesExecutionUnit_RunLevel(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SoftwareModulesExecutionUnit_Vendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_Version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_Description(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_DiskSpaceInUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_MemoryInUse(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_References(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_AssociatedProcessList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_VendorLogList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_VendorConfigList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_SupportedDataModelList(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SoftwareModulesExecutionUnit_ExecutionEnvRef(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

int get_exe_cenv_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);
int get_du_linker(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);

char *get_deployment_unit_reference(struct dmctx *ctx, char *package_name, char *package_env);
void get_deployment_unit_name_version(char *uuid, char **name, char **version, char **env);
char *get_softwaremodules_uuid(char *url);
char *get_softwaremodules_url(char *uuid);

#endif //__SOFTWAREMODULES_H

