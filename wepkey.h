/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: MOHAMED Kallel <mohamed.kallel@pivasoftware.com>
 *
 */

#ifndef __WEPKEY_H__
#define __WEPKEY_H__
#include "md5.h"
void wepkey64(char *passphrase, char strk64[4][11]);
void wepkey128(char *passphrase, char strk128[27]);
#endif /*__WEPKEY_H__*/
