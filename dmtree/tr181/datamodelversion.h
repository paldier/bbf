/*
*      This program is free software: you can redistribute it and/or modify
*      it under the terms of the GNU General Public License as published by
*      the Free Software Foundation, either version 2 of the License, or
*      (at your option) any later version.
*
*      Copyright (C) 2019 iopsys Software Solutions AB
*		Author: Omar Kallel <omar.kallel@pivasoftware.com>
*/

#ifndef __DATAMODELVERSION_H
#define __DATAMODELVERSION_H

#include "dmbbf.h"
#include "dmcommon.h"

int get_Device_RootDataModelVersion(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);

#endif
