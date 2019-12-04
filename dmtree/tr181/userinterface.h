/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#ifndef __USER_INTERFACE_H
#define __USER_INTERFACE_H

extern DMLEAF tUserInterfaceRemoteAccessParams[];
extern DMOBJ tUserInterfaceObj[];

int get_userint_remoteaccesss_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_userint_remoteaccesss_enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_userint_remoteaccesss_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_userint_remoteaccesss_port(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_userint_remoteaccesss_supportedprotocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_userint_remoteaccesss_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_userint_remoteaccesss_protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
#endif
