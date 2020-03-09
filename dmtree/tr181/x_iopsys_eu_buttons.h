/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Imen Bhiri <imen.bhiri@pivasoftware.com>
 *	  Author Omar Kallel <omar.kallel@pivasoftware.com>
 *
 */

#ifndef __SE_BUTTONS_H
#define __SE_BUTTONS_H

#include <libbbf_api/dmcommon.h>

extern DMLEAF X_IOPSYS_EU_ButtonParams[];

int browseXIopsysEuButton(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

#endif
