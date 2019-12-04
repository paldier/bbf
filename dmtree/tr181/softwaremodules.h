/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Imen Bhiri <imen.bhiri@pivasoftware.com>
 */

#ifndef __SOFTWARE_MODULE_H
#define __SOFTWARE_MODULE_H

extern DMOBJ tSoftwareModulesObj[];
extern DMLEAF tSoftwareModulesDeploymentUnitParams[];

int browsesoftwaremodules_deploymentunitInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int update_softwaremodules_url(char *uuid, char *url);
char *get_softwaremodules_uuid(char *url);
char *get_softwaremodules_username(char *uuid);
char *get_softwaremodules_pass(char *uuid);
char *get_softwaremodules_instance(char *uuid);
char *get_softwaremodules_version(char *uuid);
char *add_softwaremodules_deploymentunit(char *uuid, char*url, char *username, char *password, char *name, char *version);
char *get_softwaremodules_name(char *uuid);
char *get_softwaremodules_url(char *uuid);

int get_deploymentunit_uuid(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_deploymentunit_name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_deploymentunit_resolved(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_deploymentunit_url(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_deploymentunit_vendor(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_deploymentunit_version(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_deploymentunit_execution_env_ref(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

#endif
