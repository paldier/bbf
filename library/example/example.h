/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 */

#ifndef __EXAMPLE_H
#define __EXAMPLE_H

DMOBJ tdynamicIPDiagnosticsObj[];
DMLEAF tdynamicIPDiagnosticsX_IOPSYS_EU_BBKSpeedTestParams[];

int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int setdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_DiagnosticsState(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Latency(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Download(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int getdynamic_IPDiagnosticsX_IOPSYS_EU_BBKSpeedTest_Upload(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
opr_ret_t dynamicDeviceOperate(struct dmctx *dmctx, char *path, char *input);

#endif //__EXAMPLE_H

