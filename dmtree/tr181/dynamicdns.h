/*
*      This program is free software: you can redistribute it and/or modify
*      it under the terms of the GNU General Public License as published by
*      the Free Software Foundation, either version 2 of the License, or
*      (at your option) any later version.
*
*      Copyright (C) 2019 iopsys Software Solutions AB
*		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
*/

#ifndef __DYNAMICDNS_H
#define __DYNAMICDNS_H

extern DMOBJ tDynamicDNSObj[];
extern DMLEAF tDynamicDNSParams[];
extern DMOBJ tDynamicDNSClientObj[];
extern DMLEAF tDynamicDNSClientParams[];
extern DMLEAF tDynamicDNSClientHostnameParams[];
extern DMLEAF tDynamicDNSServerParams[];

#define DDNS_PROVIDERS_FILE "/etc/ddns/services"

int browseDynamicDNSClientInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseDynamicDNSServerInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseDynamicDNSClientHostnameInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int addObjDynamicDNSClient(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjDynamicDNSClient(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int addObjDynamicDNSServer(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjDynamicDNSServer(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int get_linker_dynamicdns_server(char *refparam, struct dmctx *dmctx, void *data, char *instance, char **linker);

int get_DynamicDNS_ClientNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNS_ServerNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNS_SupportedServices(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNSClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSClient_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSClient_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNSClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSClient_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSClient_LastError(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNSClient_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSClient_Server(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSClient_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSClient_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSClient_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSClient_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSClient_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSClient_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSClient_HostnameNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNSClientHostname_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSClientHostname_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSClientHostname_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNSClientHostname_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSClientHostname_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSClientHostname_LastUpdate(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNSServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_ServiceName(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_ServerAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_ServerAddress(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_ServerPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_SupportedProtocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_DynamicDNSServer_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_CheckInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_CheckInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_RetryInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_RetryInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_DynamicDNSServer_MaxRetries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_DynamicDNSServer_MaxRetries(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif //__DYNAMICDNS_H

