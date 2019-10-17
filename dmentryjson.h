/*
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	Copyright (C) 2019 iopsys Software Solutions AB
 *	  Author Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __DMENTRYJSON_H__
#define __DMENTRYJSON_H__

#define JSON_FOLDER_PATH "/etc/bbfdm/json"

int check_stats_folder(char *folder_path);
int load_json_dynamic_arrays(struct dmctx *ctx);
int free_json_dynamic_arrays(void);

#endif //__DMENTRYJSON_H__
