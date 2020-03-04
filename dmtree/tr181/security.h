/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#ifndef __SECURITY_H
#define __SECURITY_H

#include <libbbf_api/dmcommon.h>
#ifdef LOPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>
#elif LMBEDTLS
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#endif

#define DATE_LEN 128

struct certificate_profile {
	char *path;
#ifdef LOPENSSL
	X509 *openssl_cert;
#elif LMBEDTLS
	mbedtls_x509_crt mbdtls_cert;
#endif
	struct uci_section *dmmap_sect;
};

extern DMOBJ tSecurityObj[];
extern DMLEAF tSecurityParams[];
extern DMLEAF tSecurityCertificateParams[];

int browseSecurityCertificateInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance);

int get_Security_CertificateNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SecurityCertificate_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int set_SecurityCertificate_Enable(char *refparam, struct dmctx *ctx, void *data, char *instance, char *value, int action);
int get_SecurityCertificate_LastModif(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SecurityCertificate_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SecurityCertificate_Issuer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SecurityCertificate_NotBefore(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SecurityCertificate_NotAfter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SecurityCertificate_Subject(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SecurityCertificate_SubjectAlt(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
int get_SecurityCertificate_SignatureAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value);
#endif //__SECURITY_H

