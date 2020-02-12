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

#include "dmmemjson.h"

LIST_HEAD(memheadjson);

inline void *__dmmallocjson(size_t size)
{
	struct dmmemjson *m = malloc(sizeof(struct dmmemjson) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, &memheadjson);
	return (void *)m->mem;
}

inline void *__dmcallocjson(int n, size_t size)
{
	struct dmmemjson *m = calloc(n, sizeof(struct dmmemjson) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, &memheadjson);
	return (void *)m->mem;
}

inline void *__dmreallocjson(void *old, size_t size)
{
	struct dmmemjson *m = NULL;
	if (old != NULL) {
		m = container_of(old, struct dmmemjson, mem);
		list_del(&m->list);
	}
	struct dmmemjson *new_m = realloc(m, sizeof(struct dmmemjson) + size);
	if (new_m == NULL) {
		dmfreejson(m);
		return NULL;
	} else
		m = new_m;
	list_add(&m->list, &memheadjson);
	return (void *)m->mem;
}

inline void dmfreejson(void *m)
{
	if (m == NULL) return;
	struct dmmemjson *rm;
	rm = container_of(m, struct dmmemjson, mem);
	list_del(&rm->list);
	free(rm);
}

void dmcleanmemjson()
{
	struct dmmemjson *dmm;
	while (memheadjson.next != &memheadjson) {
		dmm = list_entry(memheadjson.next, struct dmmemjson, list);
		list_del(&dmm->list);
		free(dmm);
	}
}

char *__dmstrdupjson(const char *s)
{
	size_t len = strlen(s) + 1;
	void *new = __dmmallocjson(len);
	if (new == NULL) return NULL;
	return (char *) memcpy(new, s, len);
}

int __dmasprintfjson(char **s, const char *format, ...)
{
	char buf[512];
	va_list arg;
	va_start(arg,format);
	vsprintf(buf, format, arg);
	va_end(arg);
	*s = __dmstrdupjson(buf);
	if (*s == NULL) return -1;
	return 0;	
}
