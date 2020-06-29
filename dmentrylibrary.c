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

#include "dmentrylibrary.h"
#include "dmoperate.h"

static char library_hash[64] = "";

static int get_stats_library_folder(char *folder_path, int *file_count, unsigned long *size, unsigned long *date)
{
	struct stat stats;
	struct dirent *entry;
	DIR *dirp = NULL;
	char buf[264] = {0};
	int filecount = 0;
	unsigned long filesize = 0, filedate = 0;

	if (folder_exists(folder_path)) {
		dirp = opendir(folder_path);
		while ((entry = readdir(dirp)) != NULL) {
			if ((entry->d_type == DT_REG) && (strstr(entry->d_name, ".so"))) {
				filecount++;
				snprintf(buf, sizeof(buf), "%s/%s", folder_path, entry->d_name);
				if (!stat(buf, &stats)) {
					filesize = (filesize + stats.st_size) / 2;
					filedate = (filedate + stats.st_mtime) / 2;
				}
			}
		}
		if (dirp) closedir(dirp);

		*file_count = filecount;
		*size = filesize;
		*date = filedate;
		return 1;
	}
	return 0;
}

int check_stats_library_folder(char *library_folder_path)
{
	int file_count = 0;
	unsigned long size = 0, date = 0;
	char str[128] = "";

	if (!get_stats_library_folder(library_folder_path, &file_count, &size, &date))
		return 0;

	snprintf(str, sizeof(str), "count:%d,sizes:%lu,date:%lu", file_count, size, date);
	if (strcmp(str, library_hash)) {
		strcpy(library_hash, str);
		return 1;
	}
	return 0;
}

static int dm_browse_node_dynamic_object_tree(DMNODE *parent_node, DMOBJ *entryobj)
{
	if (!entryobj)
		return 0;

	for (; entryobj->obj; entryobj++) {
		if (entryobj->nextdynamicobj) {
			struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + INDX_LIBRARY_OBJ_MOUNT;
			if (next_dyn_array->nextobj) FREE(next_dyn_array->nextobj);
		}

		DMNODE node = {0};
		node.obj = entryobj;
		node.parent = parent_node;
		node.instance_level = parent_node->instance_level;
		node.matched = parent_node->matched;

		if (entryobj->nextobj)
			dm_browse_node_dynamic_object_tree(&node, entryobj->nextobj);
	}
	return 0;
}

int free_library_dynamic_arrays(DMOBJ *dm_entryobj)
{
	DMOBJ *root = dm_entryobj;
	DMNODE node = {.current_object = ""};
	dm_browse_node_dynamic_object_tree(&node, root);
	FREE(dynamic_operate);
	return 0;
}

static int check_library_root_obj(struct dmctx *ctx, char *in_param, DMOBJ **root_entry)
{
	int obj_found = 0;
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};
	dm_check_dynamic_obj(ctx, &node, root, in_param, in_param, root_entry, &obj_found);
	if(obj_found && *root_entry) return 1;
	return 0;
}

static int get_index_of_available_dynamic_array(struct dm_obj_s **jentryobj)
{
	int i, idx = 0;
	for (i = 0; jentryobj[i]; i++) {
		idx++;
	}
	return idx;
}

int load_library_dynamic_arrays(struct dmctx *ctx)
{
	struct dirent *ent;
	DIR *dir = NULL;

	if (folder_exists(LIBRARY_FOLDER_PATH)) {
		sysfs_foreach_file(LIBRARY_FOLDER_PATH, dir, ent) {
			if (strstr(ent->d_name, ".so")) {
				void *handle;
				LIB_MAP_OBJ *root_dynamic_obj = NULL;
				LIB_MAP_OPERATE *root_dynamic_operate = NULL;
				DMOBJ *dm_entryobj = NULL;
				char buf[280] = "";
				int i;

				snprintf(buf, sizeof(buf), "%s/%s", LIBRARY_FOLDER_PATH, ent->d_name);
				handle = dlopen(buf, RTLD_LAZY);
				if (!handle) continue;

				//Dynamic Object
				*(void **) (&root_dynamic_obj) = dlsym(handle, "tRootDynamicObj");
				if(root_dynamic_obj) {
					for (i = 0; root_dynamic_obj[i].path; i++) {
						if (!root_dynamic_obj[i].root_obj) continue;
						int check_obj = check_library_root_obj(ctx, root_dynamic_obj[i].path, &dm_entryobj);
						if ((check_obj == 0) || (!dm_entryobj)) continue;

						if (dm_entryobj->nextdynamicobj == NULL) {
							dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
							dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].isstatic = 0;
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].isstatic = 1;
						}

						if (dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].nextobj == NULL) {
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].nextobj = calloc(2, sizeof(struct dm_obj_s *));
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].nextobj[0] = root_dynamic_obj[i].root_obj;
						} else {
							int idx = get_index_of_available_dynamic_array(dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].nextobj);
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].nextobj = realloc(dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].nextobj, (idx + 2) * sizeof(struct dm_obj_s *));
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].nextobj[idx] = root_dynamic_obj[i].root_obj;
							dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].nextobj[idx+1] = NULL;
						}
					}
				}

				//Dynamic Operate
				*(void **) (&root_dynamic_operate) = dlsym(handle, "tRootDynamicOperate");
				if(root_dynamic_operate) {
					for (i = 0; root_dynamic_operate[i].path; i++) {
						if (root_dynamic_operate[i].operate && root_dynamic_operate[i].type)
							add_dynamic_operate(root_dynamic_operate[i].path,
									    root_dynamic_operate[i].operate,
									    root_dynamic_operate[i].type);
					}
				}

				if (handle) dlclose(handle);
			}
		}
		if (dir) closedir(dir);
	}
	return 0;
}
