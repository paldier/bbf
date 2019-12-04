/*
 * Copyright (C) 2019 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libubox/list.h>

#ifndef __DMMEMJSON_H
#define __DMMEMJSON_H

struct dmmemjson {
	struct list_head list;
	char mem[0];
};

void *__dmmallocjson(size_t size);
void *__dmcallocjson(int n, size_t size);
void *__dmreallocjson(void *n, size_t size);
char *__dmstrdupjson(const char *s);
int __dmasprintfjson(char **s, const char *format, ...);
void dmfreejson(void *m);
void dmcleanmemjson();

#define dmmallocjson(x) __dmmallocjson(x)
#define dmcallocjson(n, x) __dmcallocjson(n, x)
#define dmreallocjson(x, n) __dmreallocjson(x, n)
#define dmstrdupjson(x) __dmstrdupjson(x)
#define dmasprintfjson(s, format, ...) __dmasprintfjson(s, format, ## __VA_ARGS__)

#endif //__DMMEMJSON_H
