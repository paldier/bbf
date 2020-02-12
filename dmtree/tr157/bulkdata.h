/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#ifndef __BULKDATA_H
#define __BULKDATA_H

#include <libbbf_api/dmcommon.h>

extern DMOBJ tBulkDataObj[];
extern DMLEAF tBulkDataParams[];
extern DMOBJ tBulkDataProfileObj[];
extern DMLEAF tBulkDataProfileParams[];
extern DMLEAF tBulkDataProfileParameterParams[];
extern DMLEAF tBulkDataProfileCSVEncodingParams[];
extern DMLEAF tBulkDataProfileJSONEncodingParams[];
extern DMOBJ tBulkDataProfileHTTPObj[];
extern DMLEAF tBulkDataProfileHTTPParams[];
extern DMLEAF tBulkDataProfileHTTPRequestURIParameterParams[];

int browseBulkDataProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseBulkDataProfileParameterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);
int browseBulkDataProfileHTTPRequestURIParameterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int addObjBulkDataProfile(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjBulkDataProfile(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int addObjBulkDataProfileParameter(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjBulkDataProfileParameter(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);
int addObjBulkDataProfileHTTPRequestURIParameter(char *refparam, struct dmctx *ctx, void *data, char **instance);
int delObjBulkDataProfileHTTPRequestURIParameter(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action);

int get_BulkData_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkData_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkData_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkData_MinReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkData_Protocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkData_EncodingTypes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkData_ParameterWildCardSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkData_MaxNumberOfProfiles(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkData_MaxNumberOfParameterReferences(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkData_ProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkDataProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_NumberOfRetainedFailedReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_NumberOfRetainedFailedReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_EncodingType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_EncodingType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_ReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_ReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_TimeReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_TimeReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_StreamingHost(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_StreamingHost(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_StreamingPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_StreamingPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_StreamingSessionID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_StreamingSessionID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_FileTransferURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_FileTransferURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_FileTransferUsername(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_FileTransferUsername(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_FileTransferPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_FileTransferPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_ControlFileFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfile_ControlFileFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfile_ParameterNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkDataProfile_Controller(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkDataProfileParameter_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileParameter_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileParameter_Reference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileParameter_Reference(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileCSVEncoding_FieldSeparator(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileCSVEncoding_FieldSeparator(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileCSVEncoding_RowSeparator(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileCSVEncoding_RowSeparator(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileCSVEncoding_EscapeCharacter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileCSVEncoding_EscapeCharacter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileCSVEncoding_ReportFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileCSVEncoding_ReportFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileCSVEncoding_RowTimestamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileCSVEncoding_RowTimestamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileJSONEncoding_ReportFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileJSONEncoding_ReportFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileJSONEncoding_ReportTimestamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileJSONEncoding_ReportTimestamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_URL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_URL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_CompressionsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkDataProfileHTTP_Compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_Compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_MethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkDataProfileHTTP_Method(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_Method(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_UseDateHeader(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_UseDateHeader(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_RetryEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_RetryEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_RetryMinimumWaitInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_RetryMinimumWaitInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_RetryIntervalMultiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_RetryIntervalMultiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTP_RequestURIParameterNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_BulkDataProfileHTTP_PersistAcrossReboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTP_PersistAcrossReboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTPRequestURIParameter_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTPRequestURIParameter_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_BulkDataProfileHTTPRequestURIParameter_Reference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_BulkDataProfileHTTPRequestURIParameter_Reference(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);

#endif //__BULKDATA_H

