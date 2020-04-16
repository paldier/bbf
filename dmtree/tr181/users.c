/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *
 *      Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "users.h"

/***************************** Browse Functions ***********************************/
/*#Device.Users.User.{i}.!UCI:users/user/dmmap_users*/
static int browseUserInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *instance, *instnbr = NULL;
	struct dmmap_dup *p;
	LIST_HEAD(dup_list);

	synchronize_specific_config_sections_with_dmmap("users", "user", "dmmap_users", &dup_list);
	list_for_each_entry(p, &dup_list, list) {
		instance =  handle_update_instance(1, dmctx, &instnbr, update_instance_alias, 3, p->dmmap_section, "user_instance", "user_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)p->config_section, instance) == DM_STOP)
			break;
	}
	free_dmmap_config_dup_list(&dup_list);
	return 0;
}

static int add_users_user(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *s, *dmmap_user;
	char ib[8], *last_inst = NULL, *sect_name = NULL, *username, *v;

	last_inst = get_last_instance_bbfdm("dmmap_users", "user", "user_instance");
	snprintf(ib, sizeof(ib), "%s", last_inst ? last_inst : "1");
	dmasprintf(&username, "user_%d", atoi(ib)+1);
	dmuci_add_section("users", "user", &s, &sect_name);
	dmuci_rename_section_by_section(s, username);
	dmuci_set_value_by_section(s, "enabled", "1");
	dmuci_set_value_by_section(s, "password", username);
	check_create_dmmap_package("dmmap_users");
	dmuci_add_section_bbfdm("dmmap_users", "user", &dmmap_user, &v);
	dmuci_set_value_by_section(dmmap_user, "section_name", sect_name);
	*instance = update_instance_bbfdm(dmmap_user, last_inst, "user_instance");
	return 0;
}

static int delete_users_user(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	struct uci_section *s = NULL, *ss = NULL, *dmmap_section = NULL;
	int found = 0;

	switch (del_action) {
		case DEL_INST:
			if (is_section_unnamed(section_name((struct uci_section *)data))) {
				LIST_HEAD(dup_list);
				delete_sections_save_next_sections("dmmap_users", "user", "user_instance", section_name((struct uci_section *)data), atoi(instance), &dup_list);
				update_dmmap_sections(&dup_list, "user_instance", "dmmap_users", "user");
				dmuci_delete_by_section_unnamed((struct uci_section *)data, NULL, NULL);
			} else {
				get_dmmap_section_of_config_section("dmmap_users", "user", section_name((struct uci_section *)data), &dmmap_section);
				if (dmmap_section)
					dmuci_delete_by_section_unnamed_bbfdm(dmmap_section, NULL, NULL);
				dmuci_delete_by_section((struct uci_section *)data, NULL, NULL);
			}
			break;
		case DEL_ALL:
			uci_foreach_sections("users", "user", s) {
				if (found != 0) {
					get_dmmap_section_of_config_section("dmmap_users", "user", section_name(ss), &dmmap_section);
					if (dmmap_section)
						dmuci_delete_by_section(dmmap_section, NULL, NULL);
					dmuci_delete_by_section(ss, NULL, NULL);
				}
				ss = s;
				found++;
			}
			if (ss != NULL) {
				get_dmmap_section_of_config_section("dmmap_users", "user", section_name(ss), &dmmap_section);
				if (dmmap_section)
					dmuci_delete_by_section(dmmap_section, NULL, NULL);
				dmuci_delete_by_section(ss, NULL, NULL);
			}
			break;
	}
	return 0;
}

/***************************************** Set/Get Parameter functions ***********************/
/*#Device.Users.UserNumberOfEntries!UCI:users/user/*/
static int get_users_user_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("users", "user", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

static int get_user_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *dmmap_section = NULL;

	get_dmmap_section_of_config_section("dmmap_users", "user", section_name((struct uci_section *)data), &dmmap_section);
	dmuci_get_value_by_section_string(dmmap_section, "user_alias", value);
	if ((*value)[0] == '\0')
		dmasprintf(value, "cpe-%s", instance);
    return 0;
}

/*#Device.Users.User.{i}.Enable!UCI:users/user,@i-1/enabled*/
static int get_user_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enabled", value);
    return 0;
}

static int get_user_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = dmstrdup(section_name((struct uci_section *)data));
    return 0;
}

/*#Device.Users.User.{i}.Password!UCI:users/user,@i-1/password*/
static int get_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
    return 0;
}

/*#Device.Users.User.{i}.RemoteAccessCapable!UCI:users/user,@i-1/remote_access*/
static int get_user_remote_accessable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "remote_access", value);
    return 0;
}

/*#Device.Users.User.{i}.Language!UCI:users/user,@i-1/language*/
static int get_user_language(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "language", value);
    return 0;
}

static int set_user_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct uci_section *dmmap_section = NULL;

	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			get_dmmap_section_of_config_section("dmmap_users", "user", section_name((struct uci_section *)data), &dmmap_section);
			if (dmmap_section)
				dmuci_set_value_by_section(dmmap_section, "user_alias", value);
			return 0;
	}
	return 0;
}

static int set_user_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "enabled", value);
			break;
	}
	return 0;
}

static int set_user_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_rename_section_by_section((struct uci_section *)data, value);
			break;
	}
	return 0;
}

static int set_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 64, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "password", value);
			break;
	}
	return 0;
}

static int set_user_remote_accessable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "remote_access", value);
			break;
	}
	return 0;
}

static int set_user_language(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action) {
		case VALUECHECK:
			if (dm_validate_string(value, -1, 16, NULL, 0, NULL, 0))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "language", value);
			break;
	}
	return 0;
}

/* *** Device.Users. *** */
DMOBJ tUsersObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"User", &DMWRITE, add_users_user, delete_users_user, NULL, browseUserInst, NULL, NULL, NULL, NULL, tUsersUserParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tUsersParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"UserNumberOfEntries", &DMREAD, DMT_UNINT, get_users_user_number_of_entries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Users.User.{i}. *** */
DMLEAF tUsersUserParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Alias", &DMWRITE, DMT_STRING, get_user_alias, set_user_alias, NULL, NULL, BBFDM_BOTH},
{"Enable", &DMWRITE, DMT_BOOL, get_user_enable, set_user_enable, NULL, NULL, BBFDM_BOTH},
{"Username", &DMWRITE, DMT_STRING, get_user_username, set_user_username, NULL, NULL, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_user_password, set_user_password, NULL, NULL, BBFDM_BOTH},
{"RemoteAccessCapable", &DMWRITE, DMT_BOOL, get_user_remote_accessable, set_user_remote_accessable, NULL, NULL, BBFDM_BOTH},
{"Language", &DMWRITE, DMT_STRING, get_user_language, set_user_language, NULL, NULL, BBFDM_BOTH},
{0}
};
