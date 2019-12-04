/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *      Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef _USERS_H
#define _USERS_H

#include "dmbbf.h"

extern DMOBJ tUsersObj[];
extern DMLEAF tUsersParams[];
extern DMLEAF tUsersUserParams[];


int browseUserInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int add_users_user(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delete_users_user(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int get_users_user_number_of_entries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_user_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_user_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_user_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_user_remote_accessable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_user_language(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_user_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_user_username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_user_password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_user_alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_user_remote_accessable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int set_user_language(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
#endif
