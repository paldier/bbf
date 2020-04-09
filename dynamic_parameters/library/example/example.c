/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#include <libbbfdm/dmbbf.h>
#include <libbbfdm/dmcommon.h>
#include <libbbfdm/dmuci.h>
#include <libbbfdm/dmubus.h>
#include <libbbfdm/dmjson.h>
#include <libbbfdm/dmentry.h>
#include <libbbfdm/dmoperate.h>
#include "example.h"

/* ********** RootDynamicObj ********** */
LIB_MAP_OBJ tRootDynamicObj[] = {
/* parentobj, nextobject */
{"Device.IP.Diagnostics.", tdynamicIPDiagnosticsObj},
{0}
};

/* ********** RootDynamicOperate ********** */
LIB_MAP_OPERATE tRootDynamicOperate[] = {
/* pathname, operation */
{"Device.BBKSpeedTest", dynamicDeviceOperate},
{0}
};

/* *** Device.IP.Diagnostics. *** */
DMOBJ tdynamicIPDiagnosticsObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextjsonobj, nextobj, leaf, linker, bbfdm_type*/
{"X_IOPSYS_EU_BBKSpeedTest", &DMREAD, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, tdynamicIPDiagnosticsX_IOPSYS_EU_BBKSpeedTestParams, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.IP.Diagnostics.X_IOPSYS_EU_BBKSpeedTest. *** */
DMLEAF tdynamicIPDiagnosticsX_IOPSYS_EU_BBKSpeedTestParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"DiagnosticsState", &DMWRITE, DMT_STRING, getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState, setdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState, NULL, NULL, BBFDM_BOTH},
{"Latency", &DMREAD, DMT_STRING, getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Latency, NULL, NULL, NULL, BBFDM_BOTH},
{"Download", &DMREAD, DMT_STRING, getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Download, NULL, NULL, NULL, BBFDM_BOTH},
{"Upload", &DMREAD, DMT_STRING, getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Upload, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/*************************************************************
 * GET & SET PARAM
/*************************************************************/
static int execute_bbk_speedtest()
{
	json_object *res;
	char *latency, *download, *upload = NULL;

	dmubus_call("bbk", "start", UBUS_ARGS{}, 0, &res);
	if (res) {
		dmuci_set_varstate_value("cwmp", "@bbkspeedtest[0]", "DiagnosticState", "Complete");
		latency=dmjson_get_value(res, 1, "latency");
		if(latency!=NULL && strlen(latency)>0)
			dmuci_set_varstate_value("cwmp", "@bbkspeedtest[0]", "Latency", latency);
		download=dmjson_get_value(res, 1, "download");
		if(download!=NULL && strlen(latency)>0)
			dmuci_set_varstate_value("cwmp", "@bbkspeedtest[0]", "Download", download);
		upload=dmjson_get_value(res, 1, "upload");
		if(upload!=NULL && strlen(upload)>0)
			dmuci_set_varstate_value("cwmp", "@bbkspeedtest[0]", "Upload", upload);
	}
	return 0;
}

static inline char *bbk_speedtest_get(char *option, char *def)
{
	char *tmp;
	dmuci_get_varstate_string("cwmp", "@bbkspeedtest[0]", option, &tmp);
	if(tmp && tmp[0] == '\0')
		return dmstrdup(def);
	else
		return tmp;
}


int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = bbk_speedtest_get("DiagnosticState", "None");
	return 0;
}

int setdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action)
{
	char *tmp;
	struct uci_section *curr_section = NULL;

	switch (action)	{
		case VALUECHECK:
			break;
		case VALUESET:
			if (strcmp(value, "Requested") == 0) {
				curr_section = dmuci_walk_state_section("cwmp", "bbkspeedtest", NULL, NULL, CMP_SECTION, NULL, NULL, GET_FIRST_SECTION);
				if(!curr_section)
				{
					dmuci_add_state_section("cwmp", "bbkspeedtest", &curr_section, &tmp);
				}
				dmuci_set_varstate_value("cwmp", "@bbkspeedtest[0]", "DiagnosticState", value);
				execute_bbk_speedtest();
			}
			break;
	}
	return 0;
}

int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Latency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = bbk_speedtest_get("Latency", "0");
	return 0;
}

int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Download(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = bbk_speedtest_get("Download", "0");
	return 0;
}

int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Upload(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = bbk_speedtest_get("Upload", "0");
	return 0;
}

/*************************************************************
 * OPERATE
/*************************************************************/
opr_ret_t dynamicDeviceOperate(struct dmctx *dmctx, char *path, char *input)
{
	json_object *ubus_res = NULL;

	dmubus_call("bbk", "start", UBUS_ARGS{}, 0, &ubus_res);

	char *param_latency = (char *) dmjson_get_value(ubus_res, 1, "latency");
	char *param_download = (char *) dmjson_get_value(ubus_res, 1, "download");
	char *param_upload = (char *) dmjson_get_value(ubus_res, 1, "upload");

	add_list_paramameter(dmctx, dmstrdup("Latency"), param_latency, "string", NULL, 0);
	add_list_paramameter(dmctx, dmstrdup("Download"), param_download, "string", NULL, 0);
	add_list_paramameter(dmctx, dmstrdup("Upload"), param_upload, "string", NULL, 0);

	return SUCCESS;
}
