/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __GRE_H
#define __GRE_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tGREObj[];
extern DMLEAF tGREParams[];
extern DMOBJ tGRETunnelObj[];
extern DMLEAF tGRETunnelParams[];
extern DMLEAF tGRETunnelStatsParams[];
extern DMOBJ tGRETunnelInterfaceObj[];
extern DMLEAF tGRETunnelInterfaceParams[];
extern DMLEAF tGRETunnelInterfaceStatsParams[];
extern DMLEAF tGREFilterParams[];

int browseGRETunnelInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseGREFilterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseGRETunnelInterfaceInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int addObjGRETunnel(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjGRETunnel(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int addObjGREFilter(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjGREFilter(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int addObjGRETunnelInterface(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjGRETunnelInterface(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

int get_GRE_TunnelNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRE_FilterNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnel_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnel_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnel_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnel_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnel_RemoteEndpoints(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnel_RemoteEndpoints(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnel_KeepAlivePolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnel_KeepAlivePolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnel_KeepAliveTimeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnel_KeepAliveTimeout(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnel_KeepAliveThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnel_KeepAliveThreshold(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnel_DeliveryHeaderProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnel_DeliveryHeaderProtocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnel_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnel_DefaultDSCPMark(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnel_ConnectedRemoteEndpoint(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnel_InterfaceNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelStats_KeepAliveSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelStats_KeepAliveReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnelInterface_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnelInterface_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnelInterface_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnelInterface_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterface_LastChange(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnelInterface_LowerLayers(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnelInterface_ProtocolIdOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnelInterface_ProtocolIdOverride(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnelInterface_UseChecksum(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnelInterface_UseChecksum(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnelInterface_KeyIdentifierGenerationPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnelInterface_KeyIdentifierGenerationPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnelInterface_KeyIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnelInterface_KeyIdentifier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnelInterface_UseSequenceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GRETunnelInterface_UseSequenceNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GRETunnelInterfaceStats_BytesSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterfaceStats_BytesReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterfaceStats_PacketsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterfaceStats_PacketsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterfaceStats_ErrorsSent(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterfaceStats_ErrorsReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterfaceStats_DiscardChecksumReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GRETunnelInterfaceStats_DiscardSequenceNumberReceived(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GREFilter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GREFilter_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GREFilter_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_GREFilter_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GREFilter_Order(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GREFilter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GREFilter_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GREFilter_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GREFilter_Interface(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GREFilter_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GREFilter_AllInterfaces(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GREFilter_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GREFilter_VLANIDCheck(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GREFilter_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GREFilter_VLANIDExclude(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_GREFilter_DSCPMarkPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_GREFilter_DSCPMarkPolicy(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif //__GRE_H

