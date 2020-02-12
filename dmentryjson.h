/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __DMENTRYJSON_H__
#define __DMENTRYJSON_H__

#include <libbbf_api/dmcommon.h>

#define JSON_FOLDER_PATH "/etc/bbfdm/json"

int check_stats_json_folder(char *json_folder_path);
int load_json_dynamic_arrays(struct dmctx *ctx);
int free_json_dynamic_arrays(DMOBJ *dm_entryobj);

#endif //__DMENTRYJSON_H__
