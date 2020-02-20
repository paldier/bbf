/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *		Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include "bulkdata.h"

/* *** Device.BulkData. *** */
DMOBJ tBulkDataObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Profile", &DMWRITE, addObjBulkDataProfile, delObjBulkDataProfile, NULL, browseBulkDataProfileInst, NULL, NULL, NULL, tBulkDataProfileObj, tBulkDataProfileParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBulkDataParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BulkData_Enable, set_BulkData_Enable, NULL, NULL, BBFDM_BOTH},
{"Status", &DMREAD, DMT_STRING, get_BulkData_Status, NULL, NULL, NULL, BBFDM_BOTH},
{"MinReportingInterval", &DMREAD, DMT_UNINT, get_BulkData_MinReportingInterval, NULL, NULL, NULL, BBFDM_BOTH},
{"Protocols", &DMREAD, DMT_STRING, get_BulkData_Protocols, NULL, NULL, NULL, BBFDM_BOTH},
{"EncodingTypes", &DMREAD, DMT_STRING, get_BulkData_EncodingTypes, NULL, NULL, NULL, BBFDM_BOTH},
{"ParameterWildCardSupported", &DMREAD, DMT_BOOL, get_BulkData_ParameterWildCardSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxNumberOfProfiles", &DMREAD, DMT_INT, get_BulkData_MaxNumberOfProfiles, NULL, NULL, NULL, BBFDM_BOTH},
{"MaxNumberOfParameterReferences", &DMREAD, DMT_INT, get_BulkData_MaxNumberOfParameterReferences, NULL, NULL, NULL, BBFDM_BOTH},
{"ProfileNumberOfEntries", &DMREAD, DMT_UNINT, get_BulkData_ProfileNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.BulkData.Profile.{i}. *** */
DMOBJ tBulkDataProfileObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Parameter", &DMWRITE, addObjBulkDataProfileParameter, delObjBulkDataProfileParameter, NULL, browseBulkDataProfileParameterInst, NULL, NULL, NULL, NULL, tBulkDataProfileParameterParams, NULL, BBFDM_BOTH},
{"CSVEncoding", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBulkDataProfileCSVEncodingParams, NULL, BBFDM_BOTH},
{"JSONEncoding", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBulkDataProfileJSONEncodingParams, NULL, BBFDM_BOTH},
{"HTTP", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tBulkDataProfileHTTPObj, tBulkDataProfileHTTPParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBulkDataProfileParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Enable", &DMWRITE, DMT_BOOL, get_BulkDataProfile_Enable, set_BulkDataProfile_Enable, NULL, NULL, BBFDM_BOTH},
{"Alias", &DMWRITE, DMT_STRING, get_BulkDataProfile_Alias, set_BulkDataProfile_Alias, NULL, NULL, BBFDM_BOTH},
{"Name", &DMWRITE, DMT_STRING, get_BulkDataProfile_Name, set_BulkDataProfile_Name, NULL, NULL, BBFDM_BOTH},
{"NumberOfRetainedFailedReports", &DMWRITE, DMT_INT, get_BulkDataProfile_NumberOfRetainedFailedReports, set_BulkDataProfile_NumberOfRetainedFailedReports, NULL, NULL, BBFDM_BOTH},
{"Protocol", &DMWRITE, DMT_STRING, get_BulkDataProfile_Protocol, set_BulkDataProfile_Protocol, NULL, NULL, BBFDM_BOTH},
{"EncodingType", &DMWRITE, DMT_STRING, get_BulkDataProfile_EncodingType, set_BulkDataProfile_EncodingType, NULL, NULL, BBFDM_BOTH},
{"ReportingInterval", &DMWRITE, DMT_UNINT, get_BulkDataProfile_ReportingInterval, set_BulkDataProfile_ReportingInterval, NULL, NULL, BBFDM_BOTH},
{"TimeReference", &DMWRITE, DMT_TIME, get_BulkDataProfile_TimeReference, set_BulkDataProfile_TimeReference, NULL, NULL, BBFDM_BOTH},
{"ParameterNumberOfEntries", &DMREAD, DMT_UNINT, get_BulkDataProfile_ParameterNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
//{"StreamingHost", &DMWRITE, DMT_STRING, get_BulkDataProfile_StreamingHost, set_BulkDataProfile_StreamingHost, NULL, NULL, BBFDM_BOTH},
//{"StreamingPort", &DMWRITE, DMT_UNINT, get_BulkDataProfile_StreamingPort, set_BulkDataProfile_StreamingPort, NULL, NULL, BBFDM_BOTH},
//{"StreamingSessionID", &DMWRITE, DMT_UNINT, get_BulkDataProfile_StreamingSessionID, set_BulkDataProfile_StreamingSessionID, NULL, NULL, BBFDM_BOTH},
//{"FileTransferURL", &DMWRITE, DMT_STRING, get_BulkDataProfile_FileTransferURL, set_BulkDataProfile_FileTransferURL, NULL, NULL, BBFDM_BOTH},
//{"FileTransferUsername", &DMWRITE, DMT_STRING, get_BulkDataProfile_FileTransferUsername, set_BulkDataProfile_FileTransferUsername, NULL, NULL, BBFDM_BOTH},
//{"FileTransferPassword", &DMWRITE, DMT_STRING, get_BulkDataProfile_FileTransferPassword, set_BulkDataProfile_FileTransferPassword, NULL, NULL, BBFDM_BOTH},
//{"ControlFileFormat", &DMWRITE, DMT_STRING, get_BulkDataProfile_ControlFileFormat, set_BulkDataProfile_ControlFileFormat, NULL, NULL, BBFDM_BOTH},
//{"Controller", &DMREAD, DMT_STRING, get_BulkDataProfile_Controller, NULL, NULL, NULL, BBFDM_USP},
{0}
};

/* *** Device.BulkData.Profile.{i}.Parameter.{i}. *** */
DMLEAF tBulkDataProfileParameterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Name", &DMWRITE, DMT_STRING, get_BulkDataProfileParameter_Name, set_BulkDataProfileParameter_Name, NULL, NULL, BBFDM_BOTH},
{"Reference", &DMWRITE, DMT_STRING, get_BulkDataProfileParameter_Reference, set_BulkDataProfileParameter_Reference, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.BulkData.Profile.{i}.CSVEncoding. *** */
DMLEAF tBulkDataProfileCSVEncodingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"FieldSeparator", &DMWRITE, DMT_STRING, get_BulkDataProfileCSVEncoding_FieldSeparator, set_BulkDataProfileCSVEncoding_FieldSeparator, NULL, NULL, BBFDM_BOTH},
{"RowSeparator", &DMWRITE, DMT_STRING, get_BulkDataProfileCSVEncoding_RowSeparator, set_BulkDataProfileCSVEncoding_RowSeparator, NULL, NULL, BBFDM_BOTH},
{"EscapeCharacter", &DMWRITE, DMT_STRING, get_BulkDataProfileCSVEncoding_EscapeCharacter, set_BulkDataProfileCSVEncoding_EscapeCharacter, NULL, NULL, BBFDM_BOTH},
{"ReportFormat", &DMWRITE, DMT_STRING, get_BulkDataProfileCSVEncoding_ReportFormat, set_BulkDataProfileCSVEncoding_ReportFormat, NULL, NULL, BBFDM_BOTH},
{"RowTimestamp", &DMWRITE, DMT_STRING, get_BulkDataProfileCSVEncoding_RowTimestamp, set_BulkDataProfileCSVEncoding_RowTimestamp, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.BulkData.Profile.{i}.JSONEncoding. *** */
DMLEAF tBulkDataProfileJSONEncodingParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"ReportFormat", &DMWRITE, DMT_STRING, get_BulkDataProfileJSONEncoding_ReportFormat, set_BulkDataProfileJSONEncoding_ReportFormat, NULL, NULL, BBFDM_BOTH},
{"ReportTimestamp", &DMWRITE, DMT_STRING, get_BulkDataProfileJSONEncoding_ReportTimestamp, set_BulkDataProfileJSONEncoding_ReportTimestamp, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.BulkData.Profile.{i}.HTTP. *** */
DMOBJ tBulkDataProfileHTTPObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"RequestURIParameter", &DMWRITE, addObjBulkDataProfileHTTPRequestURIParameter, delObjBulkDataProfileHTTPRequestURIParameter, NULL, browseBulkDataProfileHTTPRequestURIParameterInst, NULL, NULL, NULL, NULL, tBulkDataProfileHTTPRequestURIParameterParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tBulkDataProfileHTTPParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"URL", &DMWRITE, DMT_STRING, get_BulkDataProfileHTTP_URL, set_BulkDataProfileHTTP_URL, NULL, NULL, BBFDM_BOTH},
{"Username", &DMWRITE, DMT_STRING, get_BulkDataProfileHTTP_Username, set_BulkDataProfileHTTP_Username, NULL, NULL, BBFDM_BOTH},
{"Password", &DMWRITE, DMT_STRING, get_BulkDataProfileHTTP_Password, set_BulkDataProfileHTTP_Password, NULL, NULL, BBFDM_BOTH},
{"CompressionsSupported", &DMREAD, DMT_STRING, get_BulkDataProfileHTTP_CompressionsSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"Compression", &DMWRITE, DMT_STRING, get_BulkDataProfileHTTP_Compression, set_BulkDataProfileHTTP_Compression, NULL, NULL, BBFDM_BOTH},
{"MethodsSupported", &DMREAD, DMT_STRING, get_BulkDataProfileHTTP_MethodsSupported, NULL, NULL, NULL, BBFDM_BOTH},
{"Method", &DMWRITE, DMT_STRING, get_BulkDataProfileHTTP_Method, set_BulkDataProfileHTTP_Method, NULL, NULL, BBFDM_BOTH},
{"UseDateHeader", &DMWRITE, DMT_BOOL, get_BulkDataProfileHTTP_UseDateHeader, set_BulkDataProfileHTTP_UseDateHeader, NULL, NULL, BBFDM_BOTH},
{"RetryEnable", &DMWRITE, DMT_BOOL, get_BulkDataProfileHTTP_RetryEnable, set_BulkDataProfileHTTP_RetryEnable, NULL, NULL, BBFDM_BOTH},
{"RetryMinimumWaitInterval", &DMWRITE, DMT_UNINT, get_BulkDataProfileHTTP_RetryMinimumWaitInterval, set_BulkDataProfileHTTP_RetryMinimumWaitInterval, NULL, NULL, BBFDM_BOTH},
{"RetryIntervalMultiplier", &DMWRITE, DMT_UNINT, get_BulkDataProfileHTTP_RetryIntervalMultiplier, set_BulkDataProfileHTTP_RetryIntervalMultiplier, NULL, NULL, BBFDM_BOTH},
{"RequestURIParameterNumberOfEntries", &DMREAD, DMT_UNINT, get_BulkDataProfileHTTP_RequestURIParameterNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{"PersistAcrossReboot", &DMWRITE, DMT_BOOL, get_BulkDataProfileHTTP_PersistAcrossReboot, set_BulkDataProfileHTTP_PersistAcrossReboot, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.BulkData.Profile.{i}.HTTP.RequestURIParameter.{i}. *** */
DMLEAF tBulkDataProfileHTTPRequestURIParameterParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"Name", &DMWRITE, DMT_STRING, get_BulkDataProfileHTTPRequestURIParameter_Name, set_BulkDataProfileHTTPRequestURIParameter_Name, NULL, NULL, BBFDM_BOTH},
{"Reference", &DMWRITE, DMT_STRING, get_BulkDataProfileHTTPRequestURIParameter_Reference, set_BulkDataProfileHTTPRequestURIParameter_Reference, NULL, NULL, BBFDM_BOTH},
{0}
};

/*************************************************************
* ENTRY METHOD
*************************************************************/
/*#Device.BulkData.Profile.{i}.!UCI:cwmp_bulkdata/profile/dmmap_cwmp_profile*/
int browseBulkDataProfileInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *profile = NULL, *profile_last = NULL;
	struct uci_section *s = NULL;

	uci_foreach_sections("cwmp_bulkdata", "profile", s) {
		profile = handle_update_instance(1, dmctx, &profile_last, update_instance_alias, 3, s, "profile_instance", "profile_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, profile) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.Parameter.{i}.!UCI:cwmp_bulkdata/profile_parameter/dmmap_cwmp_profile_parameter*/
int browseBulkDataProfileParameterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *profile_parameter = NULL, *profile_parameter_last = NULL, *profile_id, *prev_profile_id;
	struct uci_section *s = NULL, *prev_section = (struct uci_section *)prev_data;

	dmuci_get_value_by_section_string(prev_section, "profile_id", &prev_profile_id);
	uci_foreach_sections("cwmp_bulkdata", "profile_parameter", s) {
		dmuci_get_value_by_section_string(s, "profile_id", &profile_id);
		if(strcmp(profile_id, prev_profile_id) != 0)
			continue;
		profile_parameter = handle_update_instance(1, dmctx, &profile_parameter_last, update_instance_alias, 3, s, "parameter_instance", "parameter_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, profile_parameter) == DM_STOP)
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.RequestURIParameter.{i}.!UCI:cwmp_bulkdata/profile_http_request_uri_parameter/dmmap_cwmp_profile_http_request_uri_parameter*/
int browseBulkDataProfileHTTPRequestURIParameterInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
	char *profile_http_request_uri_parameter = NULL, *profile_http_request_uri_parameter_last = NULL, *profile_id, *prev_profile_id;
	struct uci_section *s = NULL, *prev_section = (struct uci_section *)prev_data;

	dmuci_get_value_by_section_string(prev_section, "profile_id", &prev_profile_id);
	uci_foreach_sections("cwmp_bulkdata", "profile_http_request_uri_parameter", s) {
		dmuci_get_value_by_section_string(s, "profile_id", &profile_id);
		if(strcmp(profile_id, prev_profile_id) != 0)
			continue;
		profile_http_request_uri_parameter = handle_update_instance(1, dmctx, &profile_http_request_uri_parameter_last, update_instance_alias, 3, s, "requesturiparameter_instance", "requesturiparameter_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)s, profile_http_request_uri_parameter) == DM_STOP)
			break;
	}
	return 0;
}

/*************************************************************
* ADD & DEL OBJ
*************************************************************/
int addObjBulkDataProfile(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *profile;
	char *value, *last_inst;

	last_inst = get_last_instance("cwmp_bulkdata", "profile", "profile_instance");
	dmuci_add_section_and_rename("cwmp_bulkdata", "profile", &profile, &value);
	dmasprintf(instance, "%d", last_inst ? atoi(last_inst)+1 : 1);
	dmuci_set_value_by_section(profile, "profile_instance", *instance);
	dmuci_set_value_by_section(profile, "profile_id", *instance);
	dmuci_set_value_by_section(profile, "enable", "0");
	dmuci_set_value_by_section(profile, "nbre_of_retained_failed_reports", "0");
	dmuci_set_value_by_section(profile, "protocol", "http");
	dmuci_set_value_by_section(profile, "reporting_interval", "86400");
	dmuci_set_value_by_section(profile, "time_reference", "0");
	dmuci_set_value_by_section(profile, "csv_encoding_field_separator", ",");
	dmuci_set_value_by_section(profile, "csv_encoding_row_separator", "&#10;");
	dmuci_set_value_by_section(profile, "csv_encoding_escape_character", "&quot;");
	dmuci_set_value_by_section(profile, "csv_encoding_report_format", "­column");
	dmuci_set_value_by_section(profile, "csv_encoding_row_time_stamp", "unix");
	dmuci_set_value_by_section(profile, "json_encoding_report_format", "objecthierarchy");
	dmuci_set_value_by_section(profile, "json_encoding_report_time_stamp", "unix");
	dmuci_set_value_by_section(profile, "http_compression", "none");
	dmuci_set_value_by_section(profile, "http_method", "post");
	dmuci_set_value_by_section(profile, "http_use_date_header", "1");
	dmuci_set_value_by_section(profile, "http_retry_enable", "0");
	dmuci_set_value_by_section(profile, "http_retry_minimum_wait_interval", "5");
	dmuci_set_value_by_section(profile, "http_persist_across_reboot", "0");
	return 0;
}

int delObjBulkDataProfile(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s, *ss = NULL, *profile_section = (struct uci_section *)data;
	char *prev_profile_id;

	switch (del_action) {
		case DEL_INST:
			dmuci_get_value_by_section_string(profile_section, "profile_id", &prev_profile_id);
			uci_foreach_option_eq("cwmp_bulkdata", "profile_parameter", "profile_id", prev_profile_id, s) {
				dmuci_delete_by_section(s, NULL, NULL);
				break;
			}
			uci_foreach_option_eq("cwmp_bulkdata", "profile_http_request_uri_parameter", "profile_id", prev_profile_id, s) {
				dmuci_delete_by_section(s, NULL, NULL);
				break;
			}
			dmuci_delete_by_section(profile_section, NULL, NULL);
			return 0;
		case DEL_ALL:
			uci_foreach_sections("cwmp_bulkdata", "profile_parameter", s) {
				if (found != 0)
					dmuci_delete_by_section(ss, NULL, NULL);
				ss = s;
				found++;
			}
			if (ss != NULL)
				dmuci_delete_by_section(ss, NULL, NULL);

			found = 0;
			uci_foreach_sections("cwmp_bulkdata", "profile_http_request_uri_parameter", s) {
				if (found != 0)
					dmuci_delete_by_section(ss, NULL, NULL);
				ss = s;
				found++;
			}
			if (ss != NULL)
				dmuci_delete_by_section(ss, NULL, NULL);

			found = 0;
			uci_foreach_sections("cwmp_bulkdata", "profile", s) {
				if (found != 0)
					dmuci_delete_by_section(ss, NULL, NULL);
				ss = s;
				found++;
			}
			if (ss != NULL)
				dmuci_delete_by_section(ss, NULL, NULL);

			return 0;
	}
	return 0;
}

int addObjBulkDataProfileParameter(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *profile_parameter, *profile_section = (struct uci_section *)data;
	char *value, *last_inst, *prev_profile_id;

	dmuci_get_value_by_section_string(profile_section, "profile_id", &prev_profile_id);
	last_inst = get_last_instance_lev2("cwmp_bulkdata", "profile_parameter", "parameter_instance", "profile_id", prev_profile_id);
	dmuci_add_section_and_rename("cwmp_bulkdata", "profile_parameter", &profile_parameter, &value);
	dmasprintf(instance, "%d", last_inst ? atoi(last_inst)+1 : 1);
	dmuci_set_value_by_section(profile_parameter, "parameter_instance", *instance);
	dmuci_set_value_by_section(profile_parameter, "profile_id", prev_profile_id);
	return 0;
}

int delObjBulkDataProfileParameter(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s, *ss = NULL, *profile_section = (struct uci_section *)data;
	char *prev_profile_id;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(profile_section, NULL, NULL);
			return 0;
		case DEL_ALL:
			dmuci_get_value_by_section_string(profile_section, "profile_id", &prev_profile_id);
			uci_foreach_option_eq("cwmp_bulkdata", "profile_parameter", "profile_id", prev_profile_id, s) {
				if (found != 0)
					dmuci_delete_by_section(ss, NULL, NULL);
				ss = s;
				found++;
			}
			if (ss != NULL)
				dmuci_delete_by_section(ss, NULL, NULL);
			return 0;
	}
	return 0;
}

int addObjBulkDataProfileHTTPRequestURIParameter(char *refparam, struct dmctx *ctx, void *data, char **instance)
{
	struct uci_section *profile_http_request_uri_parameter, *profile_section = (struct uci_section *)data;
	char *value, *last_inst, *prev_profile_id;

	dmuci_get_value_by_section_string(profile_section, "profile_id", &prev_profile_id);
	last_inst = get_last_instance_lev2("cwmp_bulkdata", "profile_http_request_uri_parameter", "requesturiparameter_instance", "profile_id", prev_profile_id);
	dmuci_add_section_and_rename("cwmp_bulkdata", "profile_http_request_uri_parameter", &profile_http_request_uri_parameter, &value);
	dmasprintf(instance, "%d", last_inst ? atoi(last_inst)+1 : 1);
	dmuci_set_value_by_section(profile_http_request_uri_parameter, "requesturiparameter_instance", *instance);
	dmuci_set_value_by_section(profile_http_request_uri_parameter, "profile_id", prev_profile_id);
	return 0;
}

int delObjBulkDataProfileHTTPRequestURIParameter(char *refparam, struct dmctx *ctx, void *data, char *instance, unsigned char del_action)
{
	int found = 0;
	struct uci_section *s, *ss = NULL, *profile_section = (struct uci_section *)data;
	char *prev_profile_id;

	switch (del_action) {
		case DEL_INST:
			dmuci_delete_by_section(profile_section, NULL, NULL);
			return 0;
		case DEL_ALL:
			dmuci_get_value_by_section_string(profile_section, "profile_id", &prev_profile_id);
			uci_foreach_option_eq("cwmp_bulkdata", "profile_http_request_uri_parameter", "profile_id", prev_profile_id, s) {
				if (found != 0)
					dmuci_delete_by_section(ss, NULL, NULL);
				ss = s;
				found++;
			}
			if (ss != NULL)
				dmuci_delete_by_section(ss, NULL, NULL);
			return 0;
	}
	return 0;
}

/*************************************************************
* GET & SET PARAM
*************************************************************/
/*#Device.BulkData.Enable!UCI:cwmp_bulkdata/bulkdata,bulkdata/enable*/
int get_BulkData_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_bulkdata", "bulkdata", "enable", value);
	return 0;
}

int set_BulkData_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value("cwmp_bulkdata", "bulkdata", "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.BulkData.Status!UCI:cwmp_bulkdata/bulkdata,bulkdata/enable*/
int get_BulkData_Status(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_option_value_string("cwmp_bulkdata", "bulkdata", "enable", value);
	if (strcmp(*value, "1") == 0)
		*value = "Enabled";
	else
		*value = "Disabled";
	return 0;
}

int get_BulkData_MinReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "0";
	return 0;
}

int get_BulkData_Protocols(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "HTTP";
	return 0;
}

int get_BulkData_EncodingTypes(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "JSON,CSV";
	return 0;
}

int get_BulkData_ParameterWildCardSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "1";
	return 0;
}

int get_BulkData_MaxNumberOfProfiles(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "-1";
	return 0;
}

int get_BulkData_MaxNumberOfParameterReferences(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "-1";
	return 0;
}

/*#Device.BulkData.ProfileNumberOfEntries!UCI:cwmp_bulkdata/profile/*/
int get_BulkData_ProfileNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct uci_section *s = NULL;
	int cnt = 0;

	uci_foreach_sections("cwmp_bulkdata", "profile", s) {
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.BulkData.Profile.{i}.Enable!UCI:cwmp_bulkdata/profile,@i-1/enable*/
int get_BulkDataProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "enable", value);
	return 0;
}

int set_BulkDataProfile_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.Alias!UCI:cwmp_bulkdata/profile,@i-1/profile_alias*/
int get_BulkDataProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "profile_alias", value);
	return 0;
}

int set_BulkDataProfile_Alias(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "profile_alias", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.Name!UCI:cwmp_bulkdata/profile,@i-1/name*/
int get_BulkDataProfile_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

int set_BulkDataProfile_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "255", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "name", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.NumberOfRetainedFailedReports!UCI:cwmp_bulkdata/profile,@i-1/nbre_of_retained_failed_reports*/
int get_BulkDataProfile_NumberOfRetainedFailedReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "nbre_of_retained_failed_reports", value);
	return 0;
}

int set_BulkDataProfile_NumberOfRetainedFailedReports(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_int(value, "-1", NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "nbre_of_retained_failed_reports", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.Protocol!UCI:cwmp_bulkdata/profile,@i-1/protocol*/
int get_BulkDataProfile_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "protocol", value);
	if (strcmp(*value, "http") == 0)
		*value = "HTTP";
	return 0;
}

int set_BulkDataProfile_Protocol(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, BulkDataProtocols, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "HTTP") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "protocol", "http");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.EncodingType!UCI:cwmp_bulkdata/profile,@i-1/encoding_type*/
int get_BulkDataProfile_EncodingType(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "encoding_type", value);
	if(strcmp(*value, "json") == 0)
		*value = "JSON";
	else if(strcmp(*value, "csv") == 0)
		*value = "CSV";
	return 0;
}

int set_BulkDataProfile_EncodingType(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, EncodingTypes, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "JSON") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "encoding_type", "json");
			else if(strcmp(value, "CSV") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "encoding_type", "csv");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.ReportingInterval!UCI:cwmp_bulkdata/profile,@i-1/reporting_interval*/
int get_BulkDataProfile_ReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "reporting_interval", value);
	return 0;
}

int set_BulkDataProfile_ReportingInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, "1", NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "reporting_interval", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.TimeReference!UCI:cwmp_bulkdata/profile,@i-1/time_reference*/
int get_BulkDataProfile_TimeReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	time_t time_value;

	dmuci_get_value_by_section_string((struct uci_section *)data, "time_reference", value);
	if ((*value)[0] != '0' && (*value)[0] != '\0') {
		time_value = atoi(*value);
		char s_now[sizeof "AAAA-MM-JJTHH:MM:SSZ"];
		strftime(s_now, sizeof s_now, "%Y-%m-%dT%H:%M:%SZ", localtime(&time_value));
		*value = dmstrdup(s_now);
	} else {
		*value = "0001-01-01T00:00:00Z";
	}
	return 0;
}

int set_BulkDataProfile_TimeReference(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	struct tm tm;
	char buf[16];

	switch (action) {
		case VALUECHECK:
			if (dm_validate_dateTime(value))
				return FAULT_9007;
			break;
		case VALUESET:
			if (!(strptime(value, "%Y-%m-%dT%H:%M:%S", &tm)))
				break;
			snprintf(buf, sizeof(buf), "%ld", mktime(&tm));
			dmuci_set_value_by_section((struct uci_section *)data, "time_reference", buf);
			break;
	}
	return 0;
}

int get_BulkDataProfile_StreamingHost(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_BulkDataProfile_StreamingHost(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_BulkDataProfile_StreamingPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_BulkDataProfile_StreamingPort(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, "0", "65535"))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_BulkDataProfile_StreamingSessionID(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_BulkDataProfile_StreamingSessionID(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, "65", "90"))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_BulkDataProfile_FileTransferURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_BulkDataProfile_FileTransferURL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_BulkDataProfile_FileTransferUsername(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_BulkDataProfile_FileTransferUsername(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_BulkDataProfile_FileTransferPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_BulkDataProfile_FileTransferPassword(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

int get_BulkDataProfile_ControlFileFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

int set_BulkDataProfile_ControlFileFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "128", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			//TODO
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.ParameterNumberOfEntries!UCI:cwmp_bulkdata/profile_parameter,false/false*/
int get_BulkDataProfile_ParameterNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *profile_id, *curr_profile_id;
	struct uci_section *s = NULL;
	int cnt = 0;

	dmuci_get_value_by_section_string((struct uci_section *)data, "profile_id", &curr_profile_id);
	uci_foreach_sections("cwmp_bulkdata", "profile_parameter", s) {
		dmuci_get_value_by_section_string(s, "profile_id", &profile_id);
		if(strcmp(curr_profile_id, profile_id) != 0)
			continue;
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

int get_BulkDataProfile_Controller(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	//TODO
	return 0;
}

/*#Device.BulkData.Profile.{i}.Parameter.{i}.Name!UCI:cwmp_bulkdata/profile_parameter,@i-1/name*/
int get_BulkDataProfileParameter_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

int set_BulkDataProfileParameter_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "name", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.Parameter.{i}.Reference!UCI:cwmp_bulkdata/profile_parameter,@i-1/reference*/
int get_BulkDataProfileParameter_Reference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "reference", value);
	return 0;
}

int set_BulkDataProfileParameter_Reference(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "reference", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.CSVEncoding.FieldSeparator!UCI:cwmp_bulkdata/profile,@i-1/csv_encoding_field_separator*/
int get_BulkDataProfileCSVEncoding_FieldSeparator(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "csv_encoding_field_separator", value);
	return 0;
}

int set_BulkDataProfileCSVEncoding_FieldSeparator(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "csv_encoding_field_separator", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.CSVEncoding.RowSeparator!UCI:cwmp_bulkdata/profile,@i-1/csv_encoding_row_separator*/
int get_BulkDataProfileCSVEncoding_RowSeparator(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "csv_encoding_row_separator", value);
	return 0;
}

int set_BulkDataProfileCSVEncoding_RowSeparator(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if((strcmp(value, "&#10;") == 0) || (strcmp(value, "&#13;") == 0))
				dmuci_set_value_by_section((struct uci_section *)data, "csv_encoding_row_separator", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.CSVEncoding.EscapeCharacter!UCI:cwmp_bulkdata/profile,@i-1/csv_encoding_escape_character*/
int get_BulkDataProfileCSVEncoding_EscapeCharacter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "csv_encoding_escape_character", value);
	return 0;
}

int set_BulkDataProfileCSVEncoding_EscapeCharacter(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "&quot;") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "csv_encoding_escape_character", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.CSVEncoding.ReportFormat!UCI:cwmp_bulkdata/profile,@i-1/csv_encoding_report_format*/
int get_BulkDataProfileCSVEncoding_ReportFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "csv_encoding_report_format", value);
	if(strcmp(*value, "row") == 0)
		*value = "ParameterPerRow";
	else if(strcmp(*value, "column") == 0)
		*value = "ParameterPerColumn";
	return 0;
}

int set_BulkDataProfileCSVEncoding_ReportFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, CSVReportFormat, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "ParameterPerRow") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "csv_encoding_report_format", "row");
			else if(strcmp(value, "ParameterPerColumn") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "csv_encoding_report_format", "column");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.CSVEncoding.RowTimestamp!UCI:cwmp_bulkdata/profile,@i-1/csv_encoding_row_time_stamp*/
int get_BulkDataProfileCSVEncoding_RowTimestamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "csv_encoding_row_time_stamp", value);
	if(strcmp(*value, "unix") == 0)
		*value = "Unix-Epoch";
	else if(strcmp(*value, "iso8601") == 0)
		*value = "ISO-8601";
	else if(strcmp(*value, "none") == 0)
		*value = "None";
	return 0;
}

int set_BulkDataProfileCSVEncoding_RowTimestamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, RowTimestamp, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "Unix-Epoch") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "csv_encoding_row_time_stamp", "unix");
			else if(strcmp(value, "ISO-8601") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "csv_encoding_row_time_stamp", "iso8601");
			else if(strcmp(value, "None") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "csv_encoding_row_time_stamp", "none");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.JSONEncoding.ReportFormat!UCI:cwmp_bulkdata/profile,@i-1/json_encoding_report_format*/
int get_BulkDataProfileJSONEncoding_ReportFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "json_encoding_report_format", value);
	if(strcmp(*value, "objecthierarchy") == 0)
		*value = "ObjectHierarchy";
	else if(strcmp(*value, "namevaluepair") == 0)
		*value = "NameValuePair";
	return 0;
}

int set_BulkDataProfileJSONEncoding_ReportFormat(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, JSONReportFormat, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "ObjectHierarchy") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "json_encoding_report_format", "objecthierarchy");
			else if(strcmp(value, "NameValuePair") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "json_encoding_report_format", "namevaluepair");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.JSONEncoding.ReportTimestamp!UCI:cwmp_bulkdata/profile,@i-1/json_encoding_report_time_stamp*/
int get_BulkDataProfileJSONEncoding_ReportTimestamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "json_encoding_report_time_stamp", value);
	if(strcmp(*value, "unix") == 0)
		*value = "Unix-Epoch";
	else if(strcmp(*value, "iso8601") == 0)
		*value = "ISO-8601";
	else if(strcmp(*value, "none") == 0)
		*value = "None";
	return 0;
}

int set_BulkDataProfileJSONEncoding_ReportTimestamp(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, RowTimestamp, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "Unix-Epoch") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "json_encoding_report_time_stamp", "unix");
			else if(strcmp(value, "ISO-8601") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "json_encoding_report_time_stamp", "iso8601");
			else if(strcmp(value, "None") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "json_encoding_report_time_stamp", "none");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.URL!UCI:cwmp_bulkdata/profile,@i-1/http_url*/
int get_BulkDataProfileHTTP_URL(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_url", value);
	return 0;
}

int set_BulkDataProfileHTTP_URL(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "1024", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "http_url", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.Username!UCI:cwmp_bulkdata/profile,@i-1/http_username*/
int get_BulkDataProfileHTTP_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_username", value);
	return 0;
}

int set_BulkDataProfileHTTP_Username(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "http_username", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.Password!UCI:cwmp_bulkdata/profile,@i-1/http_password*/
int get_BulkDataProfileHTTP_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
	return 0;
}

int set_BulkDataProfileHTTP_Password(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "http_password", value);
			break;
	}
	return 0;
}

int get_BulkDataProfileHTTP_CompressionsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "GZIP,Compress,Deflate";
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.Compression!UCI:cwmp_bulkdata/profile,@i-1/http_compression*/
int get_BulkDataProfileHTTP_Compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_compression", value);
	if(strcmp(*value, "gzip") == 0)
		*value = "GZIP";
	else if(strcmp(*value, "compress") == 0)
		*value = "Compress";
	else if(strcmp(*value, "deflate") == 0)
		*value = "Deflate";
	return 0;
}

int set_BulkDataProfileHTTP_Compression(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "GZIP") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "http_compression", "gzip");
			else if(strcmp(value, "Compress") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "http_compression", "compress");
			else if(strcmp(value, "Deflate") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "http_compression", "deflate");
			break;
	}
	return 0;
}

int get_BulkDataProfileHTTP_MethodsSupported(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "POST,PUT";
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.Method!UCI:cwmp_bulkdata/profile,@i-1/http_method*/
int get_BulkDataProfileHTTP_Method(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_method", value);
	if(strcmp(*value, "post") == 0)
		*value = "POST";
	else if(strcmp(*value, "put") == 0)
		*value = "PUT";
	return 0;
}

int set_BulkDataProfileHTTP_Method(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, NULL, NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			if(strcmp(value, "POST") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "http_method", "post");
			else if(strcmp(value, "PUT") == 0)
				dmuci_set_value_by_section((struct uci_section *)data, "http_method", "put");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.UseDateHeader!UCI:cwmp_bulkdata/profile,@i-1/http_use_date_header*/
int get_BulkDataProfileHTTP_UseDateHeader(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_use_date_header", value);
	return 0;
}

int set_BulkDataProfileHTTP_UseDateHeader(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "http_use_date_header", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.RetryEnable!UCI:cwmp_bulkdata/profile,@i-1/http_retry_enable*/
int get_BulkDataProfileHTTP_RetryEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_retry_enable", value);
	return 0;
}

int set_BulkDataProfileHTTP_RetryEnable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "http_retry_enable", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.RetryMinimumWaitInterval!UCI:cwmp_bulkdata/profile,@i-1/http_retry_minimum_wait_interval*/
int get_BulkDataProfileHTTP_RetryMinimumWaitInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_retry_minimum_wait_interval", value);
	return 0;
}

int set_BulkDataProfileHTTP_RetryMinimumWaitInterval(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, "1", "65535"))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "http_retry_minimum_wait_interval", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.RetryIntervalMultiplier!UCI:cwmp_bulkdata/profile,@i-1/http_retry_interval_multiplier*/
int get_BulkDataProfileHTTP_RetryIntervalMultiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_retry_interval_multiplier", value);
	return 0;
}

int set_BulkDataProfileHTTP_RetryIntervalMultiplier(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_unsignedInt(value, "1000", "65535"))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "http_retry_interval_multiplier", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.RequestURIParameterNumberOfEntries!UCI:cwmp_bulkdata/profile_http_request_uri_parameter,false/false*/
int get_BulkDataProfileHTTP_RequestURIParameterNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	char *profile_id, *curr_profile_id;
	struct uci_section *s = NULL;
	int cnt = 0;

	dmuci_get_value_by_section_string((struct uci_section *)data, "profile_id", &curr_profile_id);
	uci_foreach_sections("cwmp_bulkdata", "profile_http_request_uri_parameter", s) {
		dmuci_get_value_by_section_string(s, "profile_id", &profile_id);
		if(strcmp(curr_profile_id, profile_id) != 0)
			continue;
		cnt++;
	}
	dmasprintf(value, "%d", cnt);
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.PersistAcrossReboot!UCI:cwmp_bulkdata/profile,@i-1/http_persist_across_reboot*/
int get_BulkDataProfileHTTP_PersistAcrossReboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "http_persist_across_reboot", value);
	return 0;
}

int set_BulkDataProfileHTTP_PersistAcrossReboot(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	bool b;

	switch (action)	{
		case VALUECHECK:
			if (dm_validate_boolean(value))
				return FAULT_9007;
			break;
		case VALUESET:
			string_to_bool(value, &b);
			dmuci_set_value_by_section((struct uci_section *)data, "http_persist_across_reboot", b ? "1" : "0");
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.RequestURIParameter.{i}.Name!UCI:cwmp_bulkdata/profile_http_request_uri_parameter,@i-1/name*/
int get_BulkDataProfileHTTPRequestURIParameter_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "name", value);
	return 0;
}

int set_BulkDataProfileHTTPRequestURIParameter_Name(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "64", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "name", value);
			break;
	}
	return 0;
}

/*#Device.BulkData.Profile.{i}.HTTP.RequestURIParameter.{i}.Reference!UCI:cwmp_bulkdata/profile_http_request_uri_parameter,@i-1/reference*/
int get_BulkDataProfileHTTPRequestURIParameter_Reference(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	dmuci_get_value_by_section_string((struct uci_section *)data, "reference", value);
	return 0;
}

int set_BulkDataProfileHTTPRequestURIParameter_Reference(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	switch (action)	{
		case VALUECHECK:
			if (dm_validate_string(value, NULL, "256", NULL, NULL))
				return FAULT_9007;
			break;
		case VALUESET:
			dmuci_set_value_by_section((struct uci_section *)data, "reference", value);
			break;
	}
	return 0;
}

