/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __DATAMODELVERSION_H
#define __DATAMODELVERSION_H

#include <libbbf_api/dmbbf.h>
#include <libbbf_api/dmcommon.h>

int get_Device_RootDataModelVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

#endif
