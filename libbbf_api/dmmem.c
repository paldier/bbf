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

#include "dmmem.h"

#ifdef WITH_MEMLEACKSEC
LIST_HEAD(memhead);

inline void *__dmmalloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
size_t size
)
{
	struct dmmem *m = malloc(sizeof(struct dmmem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, &memhead);
#ifdef WITH_MEMTRACK
	m->file = (char *)file;
	m->func = (char *)func;
	m->line = line;
#endif /*WITH_MEMTRACK*/
	return (void *)m->mem;
}

inline void *__dmcalloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
int n, size_t size
)
{
	struct dmmem *m = calloc(n, sizeof(struct dmmem) + size);
	if (m == NULL) return NULL;
	list_add(&m->list, &memhead);
#ifdef WITH_MEMTRACK
	m->file = (char *)file;
	m->func = (char *)func;
	m->line = line;
#endif /*WITH_MEMTRACK*/
	return (void *)m->mem;
}

inline void *__dmrealloc
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
void *old, size_t size
)
{
	struct dmmem *m = NULL;
	if (old != NULL) {
		m = container_of(old, struct dmmem, mem);
		list_del(&m->list);
	}
	struct dmmem *new_m = realloc(m, sizeof(struct dmmem) + size);
	if (new_m == NULL) {
		dmfree(m);
		return NULL;
	} else
		m = new_m;
	list_add(&m->list, &memhead);
#ifdef WITH_MEMTRACK
	m->file = (char *)file;
	m->func = (char *)func;
	m->line = line;
#endif /*WITH_MEMTRACK*/
	return (void *)m->mem;
}

inline void dmfree(void *m)
{
	if (m == NULL) return;
	struct dmmem *rm;
	rm = container_of(m, struct dmmem, mem);
	list_del(&rm->list);
	free(rm);
}

void dmcleanmem()
{
	struct dmmem *dmm;
	while (memhead.next != &memhead) {
		dmm = list_entry(memhead.next, struct dmmem, list);
#ifdef WITH_MEMTRACK
		fprintf(stderr, "Allocated memory in {%s, %s(), line %d} is not freed\n", dmm->file, dmm->func, dmm->line);
#endif /*WITH_MEMTRACK*/
		list_del(&dmm->list);
		free(dmm);
	}
}

char *__dmstrdup
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
const char *s
)
{
	size_t len = strlen(s) + 1;
#ifdef WITH_MEMTRACK
	void *new = __dmmalloc(file, func, line, len);
#else
	void *new = __dmmalloc(len);
#endif /*WITH_MEMTRACK*/
	if (new == NULL) return NULL;
	return (char *) memcpy(new, s, len);
}
#endif /*WITH_MEMLEACKSEC*/

int __dmasprintf
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
char **s, const char *format, ...
)
{
	int size;
	char *str = NULL;
	va_list arg, argcopy;

	va_start(arg,format);
	va_copy(argcopy, arg);
	size = vsnprintf(NULL, 0, format, argcopy);
	va_end(argcopy);
#ifdef WITH_MEMTRACK
	str = (char *)__dmcalloc(file, func, line, sizeof(char), size+1);
#else
	str = (char *)__dmcalloc(sizeof(char), size+1);
#endif
	vsnprintf(str, size+1, format, arg);
	va_end(arg);
#ifdef WITH_MEMTRACK
	*s = __dmstrdup(file, func, line, str);
#else
	*s = __dmstrdup(str);
#endif /*WITH_MEMTRACK*/
	if (*s == NULL)
		return -1;
	return 0;	
}

int __dmastrcat
(
#ifdef WITH_MEMTRACK
const char *file, const char *func, int line,
#endif /*WITH_MEMTRACK*/
char **s, char *obj, char *lastname
)
{
	char buf[2048];
	int olen = strlen(obj);
	memcpy(buf, obj, olen);
	int llen = strlen(lastname) + 1;
	memcpy(buf + olen, lastname, llen);
#ifdef WITH_MEMTRACK
	*s = __dmstrdup(file, func, line, buf);
#else
	*s = __dmstrdup(buf);
#endif /*WITH_MEMTRACK*/
	if (*s == NULL) return -1;
	return 0;	
}
