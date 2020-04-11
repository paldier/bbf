/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#ifndef __SOFTWAREMODULES_H
#define __SOFTWAREMODULES_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tSoftwareModulesObj[];
extern DMLEAF tSoftwareModulesParams[];
extern DMLEAF tSoftwareModulesExecEnvParams[];
extern DMLEAF tSoftwareModulesDeploymentUnitParams[];
extern DMOBJ tSoftwareModulesExecutionUnitObj[];
extern DMLEAF tSoftwareModulesExecutionUnitParams[];

char *get_deployment_unit_reference(struct dmctx *ctx, char *package_name, char *package_env);
void get_deployment_unit_name_version(char *uuid, char **name, char **version, char **env);
char *get_softwaremodules_uuid(char *url);
char *get_softwaremodules_url(char *uuid);

#endif //__SOFTWAREMODULES_H

