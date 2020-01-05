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

#include "dmentryjson.h"
#include "dmmemjson.h"

LIST_HEAD(json_list);
static char json_hash[64] = "";

static int get_stats_json_folder(char *folder_path, int *file_count, unsigned long *size, unsigned long *date)
{
	struct stat stats;
	struct dirent *entry;
	DIR *dirp = NULL;
	char buf[256] = {0};
	int filecount = 0;
	unsigned long filesize = 0, filedate = 0;

	if (isfolderexist(folder_path)) {
		dirp = opendir(folder_path);
		while ((entry = readdir(dirp)) != NULL) {
			if ((entry->d_type == DT_REG) && (strstr(entry->d_name, ".json"))) {
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

static void add_json_data_to_list(struct list_head *dup_list, char *name, char *arg1, const char *arg2, const char *arg3, const char *arg4, const char *arg5, const char *arg6)
{
	struct dm_json_parameter *dm_json_parameter;
	dm_json_parameter = dmcallocjson(1, sizeof(struct dm_json_parameter));
	list_add_tail(&dm_json_parameter->list, dup_list);
	if(name) dm_json_parameter->name = dmstrdupjson(name);
	if (arg1) dm_json_parameter->arg1 = dmstrdupjson(arg1);
	if (arg2) dm_json_parameter->arg2 = dmstrdupjson(arg2);
	if (arg3) dm_json_parameter->arg3 = dmstrdupjson(arg3);
	if (arg4) dm_json_parameter->arg4 = dmstrdupjson(arg4);
	if (arg5) dm_json_parameter->arg5 = dmstrdupjson(arg5);
	if (arg6) dm_json_parameter->arg6 = dmstrdupjson(arg6);
}

static void delete_json_data_from_list(struct dm_json_parameter *dm_json_parameter)
{
	list_del(&dm_json_parameter->list);
	if (dm_json_parameter->name) dmfreejson(dm_json_parameter->name);
	if (dm_json_parameter->arg1) dmfreejson(dm_json_parameter->arg1);
	if (dm_json_parameter->arg2) dmfreejson(dm_json_parameter->arg2);
	if (dm_json_parameter->arg3) dmfreejson(dm_json_parameter->arg3);
	if (dm_json_parameter->arg4) dmfreejson(dm_json_parameter->arg4);
	if (dm_json_parameter->arg5) dmfreejson(dm_json_parameter->arg5);
	if (dm_json_parameter->arg6) dmfreejson(dm_json_parameter->arg6);
	if (dm_json_parameter) dmfreejson(dm_json_parameter);
}

static void free_json_data_from_list(struct list_head *dup_list)
{
	struct dm_json_parameter *dm_json_parameter;
	while (dup_list->next != dup_list) {
		dm_json_parameter = list_entry(dup_list->next, struct dm_json_parameter, list);
		delete_json_data_from_list(dm_json_parameter);
	}
}

static int dm_browse_node_json_object_tree(DMNODE *parent_node, DMOBJ *entryobj)
{
	if (!entryobj)
		return 0;

	for (; entryobj->obj; entryobj++) {
		if (entryobj->nextdynamicobj) {
			struct dm_dynamic_obj *next_dyn_array = entryobj->nextdynamicobj + INDX_JSON_OBJ_MOUNT;
			if (next_dyn_array->nextobj) FREE(next_dyn_array->nextobj);
		}

		DMNODE node = {0};
		node.obj = entryobj;
		node.parent = parent_node;
		node.instance_level = parent_node->instance_level;
		node.matched = parent_node->matched;

		if (entryobj->nextobj)
			dm_browse_node_json_object_tree(&node, entryobj->nextobj);
	}
	return 0;
}

static int free_node_object_tree_dynamic_array(DMOBJ *dm_entryobj)
{
	DMOBJ *root = dm_entryobj;
	DMNODE node = {.current_object = ""};
	dm_browse_node_json_object_tree(&node, root);
	return 0;
}

int free_json_dynamic_arrays(DMOBJ *dm_entryobj)
{
	free_json_data_from_list(&json_list);
	dmcleanmemjson();
	free_node_object_tree_dynamic_array(dm_entryobj);
	return 0;
}

int check_stats_json_folder(char *json_folder_path)
{
	int file_count = 0;
	unsigned long size = 0, date = 0;
	char str[64] = "";

	if (!get_stats_json_folder(json_folder_path, &file_count, &size, &date))
		return 0;
	
	snprintf(str, sizeof(str), "count:%d,sizes:%lu,date:%lu", file_count, size, date);
	if (strcmp(str, json_hash)) {
		strcpy(json_hash, str);
		return 1;
	}
	return 0;
}

static void generate_prefixobj_and_obj_full_obj(char *full_obj, char **prefix_obj, char **obj)
{
	char *pch, *pchr, *tmp_obj = NULL, *str = NULL;

	str = dmstrdupjson(full_obj);
	for (pch = strtok_r(str, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {
		if (pchr != NULL && *pchr != '\0') {
			if (*prefix_obj == NULL) {
				dmasprintfjson(prefix_obj, "%s.", pch);
			} else {
				tmp_obj = dmstrdupjson(*prefix_obj);
				dmfreejson(*prefix_obj);
				dmasprintfjson(prefix_obj, "%s%s.", tmp_obj, pch);
				dmfreejson(tmp_obj);
			}
		} else {
			*obj = dmstrdupjson(pch);
		}
	}
	if(str) dmfreejson(str);
}

static char *generate_obj_without_instance(char *full_obj, bool is_obj)
{
	char *pch, *pchr, *tmp_obj = NULL, *str = NULL, *obj = NULL;

	str = dmstrdupjson(full_obj);
	for (pch = strtok_r(str, ".", &pchr); pch != NULL; pch = strtok_r(NULL, ".", &pchr)) {
		if (atoi(pch) == 0) {
			if (obj == NULL) {
				dmasprintfjson(&obj, "%s.", pch);
			} else {
				tmp_obj = dmstrdupjson(obj);
				dmfreejson(obj);
				if (is_obj)
					dmasprintfjson(&obj, "%s%s.", tmp_obj, pch);
				else {
					if (pchr != NULL && *pchr != '\0')
						dmasprintfjson(&obj, "%s%s.", tmp_obj, pch);
					else
						dmasprintfjson(&obj, "%s%s", tmp_obj, pch);
				}
				dmfreejson(tmp_obj);
			}
		}
	}
	if(str) dmfreejson(str);
	return obj;
}

static char *replace_string(const char *str, const char *old_string, const char *new_string)
{
	char *value;
	int i, cnt = 0;
	int new_string_len = strlen(new_string);
	int old_string_len = strlen(old_string);

	for (i = 0; str[i] != '\0'; i++) {
		if (strstr(&str[i], old_string) == &str[i]) {
			cnt++;
			i += old_string_len - 1;
		}
	}

	value = (char *)dmmallocjson(i + cnt * (new_string_len - old_string_len) + 1);
	i = 0;
	while (*str) {
		if (strstr(str, old_string) == str) {
			strcpy(&value[i], new_string);
			i += new_string_len;
			str += old_string_len;
		}
		else
			value[i++] = *str++;
	}
	value[i] = '\0';

	return value;
}

int get_index_of_available_entry(DMOBJ *jentryobj)
{
	int idx = 0;
	for (; (jentryobj && jentryobj->obj); jentryobj++) {
		idx++;
	}
	return idx;
}

static int check_json_root_obj(struct dmctx *ctx, char *in_param_json, DMOBJ **root_entry)
{
	char *prefix_obj = NULL, *obj = NULL, *full_obj;
	int prefix_obj_found = 0, obj_found = 0;
	DMOBJ *root = ctx->dm_entryobj;
	DMNODE node = {.current_object = ""};

	full_obj = replace_string(in_param_json, ".{i}.", ".");

	if (strcmp(full_obj, "Device.") == 0)
		prefix_obj = full_obj;
	else
		generate_prefixobj_and_obj_full_obj(full_obj, &prefix_obj, &obj);

	dm_check_dynamic_obj(ctx, &node, root, full_obj, prefix_obj, root_entry, &prefix_obj_found);
	if(prefix_obj_found && *root_entry) {
		dm_check_dynamic_obj(ctx, &node, root, full_obj, full_obj, root_entry, &obj_found);
		dmfreejson(full_obj);
		if(obj_found)
			return 1;
		else
			return 2;
	}
	dmfreejson(full_obj);
	return 0;
}

int browse_obj(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_dmmap_file :: arg5="" :: arg6=""

	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL, *prefix_obj = NULL, *object = NULL;
	char buf_instance[64] = "", buf_alias[64] = "";
	struct dm_json_parameter *pleaf;

	char *obj = generate_obj_without_instance(parent_node->current_object, true);
	generate_prefixobj_and_obj_full_obj(parent_node->current_object, &prefix_obj, &object);

	snprintf(buf_instance, sizeof(buf_instance), "%s_instance", object);
	snprintf(buf_alias, sizeof(buf_alias), "%s_alias", object);
	for (int i = 0; buf_instance[i]; i++) {
		buf_instance[i] = tolower(buf_instance[i]);
	}
	for (int i = 0; buf_alias[i]; i++) {
		buf_alias[i] = tolower(buf_alias[i]);
	}

	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		char *instance = NULL, *instnbr = NULL;
		struct dmmap_dup *p;
		LIST_HEAD(dup_list);

		if(arg2 && arg3 && arg4) {
			synchronize_specific_config_sections_with_dmmap(arg2, arg3, arg4, &dup_list);
			list_for_each_entry(p, &dup_list, list) {
				instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias, 3, p->dmmap_section, buf_instance, buf_alias);
				if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, instance) == DM_STOP)
					break;
			}
		}
		free_dmmap_config_dup_list(&dup_list);
	}
	return 0;
}

static int add_obj(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_dmmap_file :: arg5="" :: arg6=""

	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL, *prefix_obj = NULL, *object = NULL;
	struct dm_json_parameter *pleaf;
	char buf_instance[64] = "";

	char *obj = generate_obj_without_instance(refparam, true);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		generate_prefixobj_and_obj_full_obj(refparam, &prefix_obj, &object);
		snprintf(buf_instance, sizeof(buf_instance), "%s_instance", object);
		for (int i = 0; buf_instance[i]; i++) {
			buf_instance[i] = tolower(buf_instance[i]);
		}

		if(arg2 && arg3 && arg4) {
			char *inst = NULL, *sect_name = NULL, *v;
			struct uci_section *section = NULL, *dmmap = NULL;

			check_create_dmmap_package(arg4);
			inst = get_last_instance_bbfdm(arg4, arg3, buf_instance);
			dmuci_add_section(arg2, arg3, &section, &sect_name);

			dmuci_add_section_bbfdm(arg4, arg3, &dmmap, &v);
			dmuci_set_value_by_section(dmmap, "section_name", sect_name);
			*instance = update_instance_bbfdm(dmmap, inst, buf_instance);
		}
	}
	return 0;
}

static int delete_obj(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_dmmap_file :: arg5="" :: arg6=""

	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL;
	struct dm_json_parameter *pleaf;

	char *obj = generate_obj_without_instance(refparam, true);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		if(arg2 && arg3 && arg4) {
			struct uci_section *s = NULL, *ss = NULL, *dmmap_section= NULL;
			int found = 0;

			switch (del_action) {
				case DEL_INST:
					get_dmmap_section_of_config_section(arg4, arg3, section_name((struct uci_section *)data), &dmmap_section);
					if (dmmap_section != NULL)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
					break;
				case DEL_ALL:
					uci_foreach_sections(arg2, arg3, s) {
						if (found != 0) {
							get_dmmap_section_of_config_section(arg4, arg3, section_name(ss), &dmmap_section);
							if (dmmap_section != NULL)
								dmuci_delete_by_section(dmmap_section, NULL, NULL);
							dmuci_delete_by_section(ss, NULL, NULL);
						}
						ss = s;
						found++;
					}
					if (ss != NULL) {
						get_dmmap_section_of_config_section(arg4, arg3, section_name(ss), &dmmap_section);
						if(dmmap_section != NULL)
							dmuci_delete_by_section(dmmap_section, NULL, NULL);
						dmuci_delete_by_section(ss, NULL, NULL);
					}
					break;
			}
		}
	}
	return 0;
}

static int getvalue_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct dm_json_parameter *pleaf;
	char *arg1 = NULL, *arg2 = NULL, *arg3 = NULL, *arg4 = NULL, *arg5 = NULL, *arg6 = NULL;

	char *obj = generate_obj_without_instance(refparam, false);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg3 = pleaf->arg3;
			arg4 = pleaf->arg4;
			arg5 = pleaf->arg5;
			arg6 = pleaf->arg6;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_section_name :: arg5=uci_section_index :: arg6=uci_option_name

		if (data && arg6) {
			dmuci_get_value_by_section_string((struct uci_section *)data, arg6, value);
		} else {
			if (arg2 && arg4 && arg6)
				dmuci_get_option_value_string(arg2, arg4, arg6, value);
			else
				*value = "";
		}
	} else if (arg1 && strcmp(arg1, "ubus") == 0) {
		//UBUS: arg1=type :: arg2=ubus_object :: arg3=ubus_method :: arg4=ubus_args1 :: arg5=ubus_args2 :: arg6=ubus_key

		json_object *res = NULL;
		if (arg2 && arg3 && arg4 && arg5) {
			if (data && (strcmp(arg5, "@Name") == 0))
				dmubus_call(arg2, arg3, UBUS_ARGS{{arg4, section_name((struct uci_section *)data), String}}, 1, &res);
			else
				dmubus_call(arg2, arg3, UBUS_ARGS{{arg4, arg5, String}}, 1, &res);

		} else if (arg2 && arg3) {
			dmubus_call(arg2, arg3, UBUS_ARGS{{}}, 0, &res);
		}

		DM_ASSERT(res, *value = "");

		if (arg6) {
			char arg6_1[32] = "";
			strcpy(arg6_1, arg6);
			char *opt = strchr(arg6_1, '.');
			if (opt) {
				*opt = '\0';
				char *arg6_2 = opt + 1;
				if (data && (strcmp(arg6_1, "@Name") == 0))
					*value = dmjson_get_value(res, 2, section_name((struct uci_section *)data), arg6_2);
				else
					*value = dmjson_get_value(res, 2, arg6_1, arg6_2);
			} else {
				*value = dmjson_get_value(res, 1, arg6);
			}
		}
	} else {
		*value = "";
	}

	return 0;
}

static int setvalue_param(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct dm_json_parameter *pleaf;
	char *arg1 = NULL, *arg2 = NULL, *arg4 = NULL, *arg6 = NULL;

	char *obj = generate_obj_without_instance(refparam, false);
	list_for_each_entry(pleaf, &json_list, list) {
		if (strcmp(pleaf->name, obj) == 0) {
			arg1 = pleaf->arg1;
			arg2 = pleaf->arg2;
			arg4 = pleaf->arg4;
			arg6 = pleaf->arg6;
			break;
		}
	}

	if (arg1 && strcmp(arg1, "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_section_name :: arg5=uci_section_index :: arg6=uci_option_name

		switch (action) {
			case VALUECHECK:
				break;
			case VALUESET:
				if (data && arg6) {
					dmuci_set_value_by_section((struct uci_section *)data, arg6, value);
				} else {
					if (arg2 && arg4 && arg6)
						dmuci_set_value(arg2, arg4, arg6, value);
				}
				break;
		}
	}
	return 0;
}

static bool is_obj(char *object, json_object *jobj)
{
	json_object_object_foreach(jobj, key, json_obj) {
		if((strcmp(key, "type") == 0) && (strcmp(json_object_get_string(json_obj), "object") == 0))
			return true;
		else if((strcmp(key, "type") == 0) && (strcmp(json_object_get_string(json_obj), "object") != 0))
			return false;
	}
	return false;
}

static void parse_mapping_obj(char *object, json_object *mapping, struct list_head *list)
{
	struct json_object *type, *obj;
	json_object_object_get_ex(mapping, "type", &type);

	if (strcmp(json_object_get_string(type), "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_dmmap_file :: arg5="" :: arg6=""

		struct json_object *file, *section, *section_type, *dmmap_file;
		json_object_object_get_ex(mapping, "uci", &obj);
		json_object_object_get_ex(obj, "file", &file);
		json_object_object_get_ex(obj, "section", &section);
		json_object_object_get_ex(section, "type", &section_type);
		json_object_object_get_ex(obj, "dmmapfile", &dmmap_file);

		//Add to list
		add_json_data_to_list(list, object, "uci", json_object_get_string(file), json_object_get_string(section_type), json_object_get_string(dmmap_file), "", "");
	}
	else {
		//Add to list
		add_json_data_to_list(list, object, "", "", "", "", "", "");
	}
}

static void parse_mapping_param(char *parameter, json_object *mapping, struct list_head *list)
{
	struct json_object *type, *obj;
	json_object_object_get_ex(mapping, "type", &type);

	if (strcmp(json_object_get_string(type), "uci") == 0) {
		//UCI: arg1=type :: arg2=uci_file :: arg3=uci_section_type :: arg4=uci_section_name :: arg5=uci_section_index :: arg6=uci_option_name

		struct json_object *file, *section, *type, *section_name, *index, *option, *option_name;
		json_object_object_get_ex(mapping, "uci", &obj);
		json_object_object_get_ex(obj, "file", &file);
		json_object_object_get_ex(obj, "section", &section);
		json_object_object_get_ex(section, "type", &type);
		json_object_object_get_ex(section, "name", &section_name);
		json_object_object_get_ex(section, "index", &index);
		json_object_object_get_ex(obj, "option", &option);
		json_object_object_get_ex(option, "name", &option_name);

		//Add to list
		add_json_data_to_list(list, parameter, "uci", json_object_get_string(file), json_object_get_string(type), json_object_get_string(section_name), json_object_get_string(index), json_object_get_string(option_name));
	}
	else if (strcmp(json_object_get_string(type), "ubus") == 0) {
		//UBUS: arg1=type :: arg2=ubus_object :: arg3=ubus_method :: arg4=ubus_args1 :: arg5=ubus_args2 :: arg6=ubus_key

		struct json_object *object, *method, *key, *args;
		char *args1 = NULL;
		json_object_object_get_ex(mapping, "ubus", &obj);
		json_object_object_get_ex(obj, "object", &object);
		json_object_object_get_ex(obj, "method", &method);
		json_object_object_get_ex(obj, "args", &args);
		json_object_object_foreach(args, arg1, args2) {
			args1 = arg1;
		}
		json_object_object_get_ex(obj, "key", &key);

		//Add to list
		add_json_data_to_list(list, parameter, "ubus", json_object_get_string(object), json_object_get_string(method), args1, json_object_get_string(args2), json_object_get_string(key));
	}
	else {
		//Add to list
		add_json_data_to_list(list, parameter, "", "", "", "", "", "");
	}
}

static void parse_param(char *object, char *param, json_object *jobj, DMLEAF *pleaf, int i, struct list_head *list)
{
	/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type(8)*/
	struct json_object *type, *protocols, *proto, *write, *mapping;
	char full_param[256] = "";
	size_t n_proto;

	if (!pleaf) return;

	//PARAM
	pleaf[i].parameter = dmstrdupjson(param);

	//permission
	json_object_object_get_ex(jobj, "write", &write);
	pleaf[i].permission = json_object_get_boolean(write) ? &DMWRITE : &DMREAD;

	//type
	json_object_object_get_ex(jobj, "type", &type);
	if (strcmp(json_object_get_string(type), "boolean") == 0)
		pleaf[i].type = DMT_BOOL;
	else if (strcmp(json_object_get_string(type), "unsignedInt") == 0)
		pleaf[i].type = DMT_UNINT;
	else if (strcmp(json_object_get_string(type), "unsignedLong") == 0)
		pleaf[i].type = DMT_UNLONG;
	else if (strcmp(json_object_get_string(type), "hexBinary") == 0)
		pleaf[i].type = DMT_HEXBIN;
	else if (strcmp(json_object_get_string(type), "int") == 0)
		pleaf[i].type = DMT_INT;
	else if (strcmp(json_object_get_string(type), "long") == 0)
		pleaf[i].type = DMT_LONG;
	else if (strcmp(json_object_get_string(type), "dateTime") == 0)
		pleaf[i].type = DMT_TIME;
	else
		pleaf[i].type = DMT_STRING;

	//getvalue
	pleaf[i].getvalue = getvalue_param;

	//setvalue
	pleaf[i].setvalue = json_object_get_boolean(write) ? setvalue_param : NULL;

	//forced_inform
	pleaf[i].forced_inform = NULL;

	//notification
	pleaf[i].notification = NULL;

	//bbfdm_type
	json_object_object_get_ex(jobj, "protocols", &protocols);
	n_proto = json_object_array_length(protocols);
	if (n_proto == 2)
		pleaf[i].bbfdm_type = BBFDM_BOTH;
	else if (n_proto == 1) {
		proto = json_object_array_get_idx(protocols, 0);
		if (strcmp(json_object_get_string(proto), "cwmp") == 0)
			pleaf[i].bbfdm_type = BBFDM_CWMP;
		else if (strcmp(json_object_get_string(proto), "usp") == 0)
			pleaf[i].bbfdm_type = BBFDM_USP;
		else
			pleaf[i].bbfdm_type = BBFDM_BOTH;
	} else
		pleaf[i].bbfdm_type = BBFDM_BOTH;

	snprintf(full_param, sizeof(full_param), "%s%s", object, param);
	json_object_object_get_ex(jobj, "mapping", &mapping);
	parse_mapping_param(full_param, mapping, list);
}

static void count_obj_param_under_jsonobj(json_object *jsonobj, int *obj_number, int *param_number)
{
	json_object_object_foreach(jsonobj, key, jobj) {
		if (json_object_get_type(jobj) == json_type_object) {
			json_object_object_foreach(jobj, key1, jobj1) {
				if ((strcmp(key1, "type") == 0) && (strcmp(json_object_get_string(jobj1), "object") == 0)) {
					(*obj_number)++;
					break;
				}
				else if (((strcmp(key1, "type") == 0) && (strcmp(json_object_get_string(jobj1), "object") != 0)) && (strcmp(key, "mapping") != 0)) {
					(*param_number)++;
					break;
				}
			}
		}
	}
}

static void parse_obj(char *object, json_object *jobj, DMOBJ *pobj, int index, struct list_head *list)
{
	/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type(13)*/

	char *full_obj = NULL, *prfix_obj = NULL, *obj_str = NULL;
	int obj_number = 0, param_number = 0, i = 0, j = 0;
	DMOBJ *next_obj = NULL;
	DMLEAF *next_leaf = NULL;

	count_obj_param_under_jsonobj(jobj, &obj_number, &param_number);
	full_obj = replace_string(object, ".{i}.", ".");
	generate_prefixobj_and_obj_full_obj(full_obj, &prfix_obj, &obj_str);

	if (!pobj) return;
	//OBJ
	pobj[index].obj = obj_str;

	//nextobj
	if (obj_number != 0)
		next_obj = dmcallocjson(obj_number+1, sizeof(struct dm_obj_s));
	else
		next_obj = NULL;

	pobj[index].nextobj = next_obj;

	//leaf
	if (param_number != 0) {
		next_leaf = dmcallocjson(param_number+1, sizeof(struct dm_leaf_s));
		pobj[index].leaf = next_leaf;
	} else {
		pobj[index].leaf = NULL;
	}

	json_object_object_foreach(jobj, key, json_obj) {
		//bbfdm_type
		if (strcmp(key, "protocols") == 0) {
			size_t n_proto = json_object_array_length(json_obj);
			if (n_proto == 2)
				pobj[index].bbfdm_type = BBFDM_BOTH;
			else if (n_proto == 1) {
				struct json_object *proto = json_object_array_get_idx(json_obj, 0);
				if (strcmp(json_object_get_string(proto), "cwmp") == 0)
					pobj[index].bbfdm_type = BBFDM_CWMP;
				else if (strcmp(json_object_get_string(proto), "usp") == 0)
					pobj[index].bbfdm_type = BBFDM_USP;
				else
					pobj[index].bbfdm_type = BBFDM_BOTH;
			} else
				pobj[index].bbfdm_type = BBFDM_BOTH;
		}

		if (strcmp(key, "array") == 0) {
			//permission
			pobj[index].permission = json_object_get_boolean(json_obj) ? &DMWRITE : &DMREAD;

			//addobj
			pobj[index].addobj = json_object_get_boolean(json_obj) ? add_obj : NULL;

			//delobj
			pobj[index].delobj = json_object_get_boolean(json_obj) ? delete_obj : NULL;

			//checkobj
			pobj[index].checkobj = NULL;

			//browseinstobj
			pobj[index].browseinstobj = json_object_get_boolean(json_obj) ? browse_obj : NULL;

			//forced_inform
			pobj[index].forced_inform = NULL;

			//notification
			pobj[index].notification = NULL;

			//nextdynamicobj
			pobj[index].nextdynamicobj = NULL;

			//linker
			pobj[index].get_linker = NULL;
		}

		if (strcmp(key, "mapping") == 0 && json_object_get_type(json_obj) == json_type_object) {
			parse_mapping_obj(full_obj, json_obj, list);
		}

		if (json_object_get_type(json_obj) == json_type_object && is_obj(key, json_obj)) {
			parse_obj(key, json_obj, next_obj, j, list);
			j++;
		}

		if (json_object_get_type(json_obj) == json_type_object && !is_obj(key, json_obj) && strcmp(key, "mapping") != 0) {
			parse_param(full_obj, key, json_obj, next_leaf, i, list);
			i++;
		}
	}
}

static void parse_next_obj(struct dmctx *ctx, json_object *jobj)
{
	json_object_object_foreach(jobj, key, json_obj) {
		DMOBJ *dm_entryobj = NULL;
		if (json_object_get_type(json_obj) == json_type_object && is_obj(key, json_obj)) {
			int check_obj = check_json_root_obj(ctx, key, &dm_entryobj);
			if (check_obj == 0) continue;
			if (check_obj == 1) {
				parse_next_obj(ctx, json_obj);
			} else {
				if (!dm_entryobj) continue;

				if (dm_entryobj->nextdynamicobj == NULL) {
					dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
					dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].isstatic = 0;
				}

				if (dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj == NULL) {
					dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj = calloc(2, sizeof(struct dm_obj_s *));
				}

				if (dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0] == NULL) {
					dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0] = dmcallocjson(2, sizeof(struct dm_obj_s));
					parse_obj(key, jobj, dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0], 0, &json_list);
				} else {
					int idx = get_index_of_available_entry(dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0]);
					dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0] = dmreallocjson(dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0], (idx + 2) * sizeof(struct dm_obj_s));
					memset(dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0] + (idx + 1), 0, sizeof(struct dm_obj_s));
					parse_obj(key, jobj, dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0], idx, &json_list);
				}
			}
		}
	}
}

int load_json_dynamic_arrays(struct dmctx *ctx)
{
	struct dirent *ent;
	DIR *dir = NULL;

	if (isfolderexist(JSON_FOLDER_PATH)) {
		sysfs_foreach_file(JSON_FOLDER_PATH, dir, ent) {
			if (strstr(ent->d_name, ".json")) {
				DMOBJ *dm_entryobj = NULL;
				json_object *json;
				char buf[32] = "";
				snprintf(buf, sizeof(buf), "%s/%s", JSON_FOLDER_PATH, ent->d_name);
				json = json_object_from_file(buf);
				if (!json) continue;

				json_object_object_foreach(json, key, jobj) {
					if (!key) break;
					int check_obj = check_json_root_obj(ctx, key, &dm_entryobj);
					if (check_obj == 0) continue;
					if (check_obj == 1) {
						parse_next_obj(ctx, jobj);
						continue;
					}
					if (!dm_entryobj) continue;

					if (dm_entryobj->nextdynamicobj == NULL) {
						dm_entryobj->nextdynamicobj = calloc(__INDX_DYNAMIC_MAX, sizeof(struct dm_dynamic_obj));
						dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].isstatic = 0;
						dm_entryobj->nextdynamicobj[INDX_LIBRARY_OBJ_MOUNT].isstatic = 1;
					}

					if (dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj == NULL) {
						dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj = calloc(2, sizeof(struct dm_obj_s *));
					}

					if (dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0] == NULL) {
						dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0] = dmcallocjson(2, sizeof(struct dm_obj_s));
						parse_obj(key, jobj, dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0], 0, &json_list);
					} else {
						int idx = get_index_of_available_entry(dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0]);
						dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0] = dmreallocjson(dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0], (idx + 2) * sizeof(struct dm_obj_s));
						memset(dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0] + (idx + 1), 0, sizeof(struct dm_obj_s));
						parse_obj(key, jobj, dm_entryobj->nextdynamicobj[INDX_JSON_OBJ_MOUNT].nextobj[0], idx, &json_list);
					}
				}
				if (json) json_object_put(json);
			}
		}
		if (dir) closedir(dir);
	}
	return 0;
}
