/*
 * Copyright (C) 2020 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	Author: Omar Kallel <omar.kallel@pivasoftware.com>
 */

#include "security.h"

#define DATE_LEN 128
#define MAX_CERT 32

static char certifcates_paths[MAX_CERT][256];

struct certificate_profile {
	char *path;
#ifdef LOPENSSL
	X509 *openssl_cert;
#elif LMBEDTLS
	mbedtls_x509_crt mbdtls_cert;
#endif
	struct uci_section *dmmap_sect;
};

/************************************************************
 * Init function
 *************************************************************/
void init_certificate(char *path,
#ifdef LOPENSSL
X509 *cert,
#elif LMBEDTLS
mbedtls_x509_crt cert,
#endif
struct uci_section *dmsect, struct certificate_profile *certprofile)
{
	certprofile->path = path;
#ifdef LOPENSSL
	certprofile->openssl_cert = cert;
#elif LMBEDTLS
	certprofile->mbdtls_cert = cert;
#endif
	certprofile->dmmap_sect = dmsect;
}

#ifdef LOPENSSL
static char *get_certificate_sig_alg(int sig_nid)
{
	switch(sig_nid) {
	case NID_sha256WithRSAEncryption:
		return LN_sha256WithRSAEncryption;
	case NID_sha384WithRSAEncryption:
		return LN_sha384WithRSAEncryption;
	case NID_sha512WithRSAEncryption:
		return LN_sha512WithRSAEncryption;
	case NID_sha224WithRSAEncryption:
		return LN_sha224WithRSAEncryption;
	case NID_sha512_224WithRSAEncryption:
		return LN_sha512_224WithRSAEncryption;
	case NID_sha512_256WithRSAEncryption:
		return LN_sha512_224WithRSAEncryption;
	case NID_pbeWithMD2AndDES_CBC:
		return LN_pbeWithMD2AndDES_CBC;
	case NID_pbeWithMD5AndDES_CBC:
		return LN_pbeWithMD5AndDES_CBC;
	case NID_pbeWithMD2AndRC2_CBC:
		return LN_pbeWithMD5AndDES_CBC;
	case NID_pbeWithMD5AndRC2_CBC:
		return LN_pbeWithMD5AndRC2_CBC;
	case NID_pbeWithSHA1AndDES_CBC:
		return LN_pbeWithSHA1AndDES_CBC;
	case NID_pbeWithSHA1AndRC2_CBC:
		return LN_pbeWithSHA1AndDES_CBC;
	case NID_pbe_WithSHA1And128BitRC4:
		return LN_pbe_WithSHA1And128BitRC4;
	case NID_pbe_WithSHA1And40BitRC4:
		return LN_pbe_WithSHA1And40BitRC4;
	case NID_pbe_WithSHA1And3_Key_TripleDES_CBC:
		return LN_pbe_WithSHA1And3_Key_TripleDES_CBC;
	case NID_pbe_WithSHA1And2_Key_TripleDES_CBC:
		return LN_pbe_WithSHA1And2_Key_TripleDES_CBC;
	case NID_pbe_WithSHA1And128BitRC2_CBC:
		return LN_pbe_WithSHA1And128BitRC2_CBC;
	case NID_pbe_WithSHA1And40BitRC2_CBC:
		return LN_pbe_WithSHA1And40BitRC2_CBC;
	case NID_sm3WithRSAEncryption:
		return LN_sm3WithRSAEncryption;
	case NID_shaWithRSAEncryption:
		return LN_shaWithRSAEncryption;
	case NID_md2WithRSAEncryption:
		return LN_md2WithRSAEncryption;
	case NID_md4WithRSAEncryption:
		return LN_md4WithRSAEncryption;
	case NID_md5WithRSAEncryption:
		return LN_md5WithRSAEncryption;
	case NID_sha1WithRSAEncryption:
		return LN_sha1WithRSAEncryption;
	default:
		return "";
	}
}
#elif LMBEDTLS
static char *get_certificate_md(mbedtls_md_type_t sig_md)
{
	switch(sig_md) {
	case MBEDTLS_MD_MD2:
		return "md2";
	case MBEDTLS_MD_MD4:
		return "md4";
	case MBEDTLS_MD_MD5:
		return "md5";
	case MBEDTLS_MD_SHA1:
		return "sha1";
	case MBEDTLS_MD_SHA224:
		return "sha224";
	case MBEDTLS_MD_SHA256:
		return "sha256";
	case MBEDTLS_MD_SHA384:
		return "sha384";
	case MBEDTLS_MD_SHA512:
		return "sha512";
	case MBEDTLS_MD_RIPEMD160:
		return "ripemd160";
	default:
		return "";
	}
	return "";
}

static char *get_certificate_pk(mbedtls_pk_type_t sig_pk)
{
	switch(sig_pk) {
	case MBEDTLS_PK_RSA:
		return "RSA";
	case MBEDTLS_PK_ECKEY:
		return "ECKEY";
	case MBEDTLS_PK_ECKEY_DH:
		return "ECKEYDH";
	case MBEDTLS_PK_ECDSA:
		return "ECDSA";
	case MBEDTLS_PK_RSA_ALT:
		return "RSAALT";
	case MBEDTLS_PK_RSASSA_PSS:
		return "RSASSAPSS";
	default:
		return "";
	}
	return "";
}
#endif


/*************************************************************
* ENTRY METHOD
**************************************************************/

static void get_certificate_paths(void)
{
	struct uci_section *s;
	int cidx;

	for (cidx=0; cidx<MAX_CERT; cidx++)
		memset(certifcates_paths[cidx], '\0', 256);

	cidx = 0;

	uci_foreach_sections("owsd", "owsd-listen", s) {
		char *cert;
		dmuci_get_value_by_section_string(s, "cert", &cert);
		if (*cert == '\0')
			continue;
		if (cidx >= MAX_CERT)
			break;
		if(!file_exists(cert) || !is_regular_file(cert))
			continue;
		strncpy(certifcates_paths[cidx], cert, 256);
		cidx++;
	}

	uci_foreach_sections("openvpn", "openvpn", s) {
		char *cert;
		dmuci_get_value_by_section_string(s, "cert", &cert);
		if (*cert == '\0')
			continue;
		if (cidx >= MAX_CERT)
			break;
		if(!file_exists(cert) || !is_regular_file(cert))
			continue;
		strncpy(certifcates_paths[cidx], cert, 256);
		cidx++;
	}

	uci_foreach_sections("obuspa", "obuspa", s) {
		char *cert;
		dmuci_get_value_by_section_string(s, "cert", &cert);
		if (*cert == '\0')
			continue;
		if (cidx >= MAX_CERT)
			break;
		if(!file_exists(cert) || !is_regular_file(cert))
			continue;
		strncpy(certifcates_paths[cidx], cert, 256);
		cidx++;
	}
}

static int browseSecurityCertificateInst(struct dmctx *dmctx, DMNODE *parent_node, void *prev_data, char *prev_instance)
{
#if defined(LOPENSSL) || defined(LMBEDTLS)
	char *cert_inst= NULL, *cert_inst_last= NULL, *v = NULL;
	struct uci_section *dmmap_sect = NULL;
	struct certificate_profile certificateprofile = {};

	check_create_dmmap_package("dmmap_security");
	get_certificate_paths();
	int i;
	for (i=0; i < MAX_CERT; i++) {
		if(!strlen(certifcates_paths[i]))
			break;
#ifdef LOPENSSL
		FILE *fp = NULL;
		fp = fopen(certifcates_paths[i], "r");
		if (fp == NULL)
			continue;
		X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (!cert) {
			fclose(fp);
			continue;
		}
		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_security", "security_certificate", "path", certifcates_paths[i])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_security", "security_certificate", &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "path", certifcates_paths[i]);
		}
		init_certificate(certifcates_paths[i], cert, dmmap_sect, &certificateprofile);
		cert_inst = handle_update_instance(1, dmctx, &cert_inst_last, update_instance_alias, 3, dmmap_sect, "security_certificate_instance", "security_certificate_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&certificateprofile, cert_inst) == DM_STOP)
			break;

		X509_free(cert);
		cert = NULL;
		fclose(fp);
		fp = NULL;
#elif LMBEDTLS
		mbedtls_x509_crt cacert;
		mbedtls_x509_crt_init( &cacert );
		int ret = mbedtls_x509_crt_parse_file( &cacert, certifcates_paths[i]);
		if (ret < 0)
			continue;
		if ((dmmap_sect = get_dup_section_in_dmmap_opt("dmmap_security", "security_certificate", "path", certifcates_paths[i])) == NULL) {
			dmuci_add_section_bbfdm("dmmap_security", "security_certificate", &dmmap_sect, &v);
			DMUCI_SET_VALUE_BY_SECTION(bbfdm, dmmap_sect, "path", certifcates_paths[i]);
		}
		init_certificate(certifcates_paths[i], cacert, dmmap_sect, &certificateprofile);
		cert_inst = handle_update_instance(1, dmctx, &cert_inst_last, update_instance_alias, 3, dmmap_sect, "security_certificate_instance", "security_certificate_alias");
		if (DM_LINK_INST_OBJ(dmctx, parent_node, (void *)&certificateprofile, cert_inst) == DM_STOP)
			break;
#endif
	}
#endif
	return 0;
}

/*************************************************************
* GET & SET PARAM
**************************************************************/
static int get_Security_CertificateNumberOfEntries(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	int number = 0;

#if defined(LOPENSSL) || defined(LMBEDTLS)

	get_certificate_paths();
	int i;
	for (i=0; i < MAX_CERT; i++) {
		if(!strlen(certifcates_paths[i]))
			break;
#ifdef LOPENSSL
		FILE *fp = NULL;
		fp = fopen(certifcates_paths[i], "r");
		if (fp == NULL)
			continue;
		X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (!cert) {
			fclose(fp);
			continue;
		}
		number++;
		X509_free(cert);
		cert = NULL;
		fclose(fp);
		fp = NULL;
#elif LMBEDTLS
		mbedtls_x509_crt cacert;
		mbedtls_x509_crt_init( &cacert );

		int ret = mbedtls_x509_crt_parse_file( &cacert, certifcates_paths[i]);
		if (ret < 0)
			continue;
		number++;
#endif
	}
#endif
	dmasprintf(value, "%d", number);
	return 0;
}

static int get_SecurityCertificate_LastModif(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	struct stat b;
	char t[ 100 ] = "";
	if (!stat(cert_profile->path, &b))
		strftime(t, 100, "%Y-%m-%dT%H:%M:%SZ", localtime( &b.st_mtime));
	*value = dmstrdup(t);
	return 0;
}

static int get_SecurityCertificate_SerialNumber(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
#ifdef LOPENSSL
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	ASN1_INTEGER *serial = X509_get_serialNumber(cert_profile->openssl_cert);
	*value = stringToHex((char *)serial->data, serial->length);
#elif LMBEDTLS
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	*value = stringToHex(cert_profile->mbdtls_cert.serial.p, cert_profile->mbdtls_cert.serial.len);
#endif
	return 0;
}

static int get_SecurityCertificate_Issuer(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
#ifdef LOPENSSL
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	*value = X509_NAME_oneline(X509_get_issuer_name(cert_profile->openssl_cert), NULL, 0);
	if (*value[0] == '/')
		(*value)++;
	*value = replace_char(*value, '/', ' ');
#elif LMBEDTLS
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	size_t olen;
	unsigned char issuer[4096];
	int ret2 = mbedtls_base64_encode(issuer, 4096, &olen, cert_profile->mbdtls_cert.issuer.val.p, cert_profile->mbdtls_cert.issuer.val.len );
	if(ret2 != 0)
		return 0;
	*value = decode64(issuer);
#endif
	return 0;
}

static int get_SecurityCertificate_NotBefore(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
#ifdef LOPENSSL
	struct tm not_before_time;
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	char not_before_str[DATE_LEN];
	ASN1_TIME *not_before = X509_get_notBefore(cert_profile->openssl_cert);
	ASN1_TIME_to_tm(not_before, &not_before_time);
	strftime(not_before_str, sizeof(not_before_str), "%Y-%m-%dT%H:%M:%SZ", &not_before_time);
	*value = dmstrdup(not_before_str);
#elif LMBEDTLS
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	dmasprintf(value, "%d-%d-%dT%d:%d:%dZ", cert_profile->mbdtls_cert.valid_from.year, cert_profile->mbdtls_cert.valid_from.mon, cert_profile->mbdtls_cert.valid_from.day, cert_profile->mbdtls_cert.valid_from.hour,    cert_profile->mbdtls_cert.valid_from.min, cert_profile->mbdtls_cert.valid_from.sec);
#endif
	return 0;
}

static int get_SecurityCertificate_NotAfter(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
#ifdef LOPENSSL
	struct tm not_after_time;
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	char not_after_str[DATE_LEN];
	ASN1_TIME *not_after = X509_get_notAfter(cert_profile->openssl_cert);
	ASN1_TIME_to_tm(not_after, &not_after_time);
	strftime(not_after_str, sizeof(not_after_str), "%Y-%m-%dT%H:%M:%SZ", &not_after_time);
	*value = dmstrdup(not_after_str);
#elif LMBEDTLS
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	dmasprintf(value, "%d-%d-%dT%d:%d:%dZ", cert_profile->mbdtls_cert.valid_to.year, cert_profile->mbdtls_cert.valid_to.mon, cert_profile->mbdtls_cert.valid_to.day, cert_profile->mbdtls_cert.valid_to.hour,    cert_profile->mbdtls_cert.valid_to.min, cert_profile->mbdtls_cert.valid_to.sec);
#endif
	return 0;
}

static int get_SecurityCertificate_Subject(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
#ifdef LOPENSSL
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	*value = X509_NAME_oneline(X509_get_subject_name(cert_profile->openssl_cert), NULL, 0);
	if (*value[0] == '/')
		(*value)++;
	*value = replace_char(*value, '/', ' ');
#elif LMBEDTLS
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	size_t olen;
	unsigned char issuer[4096];
	int ret2 = mbedtls_base64_encode(issuer, 4096, &olen, cert_profile->mbdtls_cert.subject.val.p, cert_profile->mbdtls_cert.subject.val.len );
	if(ret2 != 0)
		return 0;
	*value = decode64(issuer);
#endif
	return 0;
}

static int get_SecurityCertificate_SignatureAlgorithm(char *refparam, struct dmctx *ctx, void *data, char *instance, char **value)
{
	*value = "";
#ifdef LOPENSSL
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	*value = dmstrdup(get_certificate_sig_alg(X509_get_signature_nid(cert_profile->openssl_cert)));
#elif LMBEDTLS
	struct certificate_profile *cert_profile = (struct certificate_profile*)data;
	dmasprintf(value, "%sWith%sEncryptionn", get_certificate_md(cert_profile->mbdtls_cert.sig_md), get_certificate_pk(cert_profile->mbdtls_cert.sig_pk));
#endif
	return 0;
}

/* *** Device.Security. *** */
DMOBJ tSecurityObj[] = {
/* OBJ, permission, addobj, delobj, checkobj, browseinstobj, forced_inform, notification, nextdynamicobj, nextobj, leaf, linker, bbfdm_type*/
{"Certificate", &DMREAD, NULL, NULL, NULL, browseSecurityCertificateInst, NULL, NULL, NULL, NULL, tSecurityCertificateParams, NULL, BBFDM_BOTH},
{0}
};

DMLEAF tSecurityParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
{"CertificateNumberOfEntries", &DMREAD, DMT_UNINT, get_Security_CertificateNumberOfEntries, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};

/* *** Device.Security.Certificate.{i}. *** */
DMLEAF tSecurityCertificateParams[] = {
/* PARAM, permission, type, getvalue, setvalue, forced_inform, notification, bbfdm_type*/
//{"Enable", &DMWRITE, DMT_BOOL, get_SecurityCertificate_Enable, set_SecurityCertificate_Enable, NULL, NULL, BBFDM_BOTH},
{"LastModif", &DMREAD, DMT_TIME, get_SecurityCertificate_LastModif, NULL, NULL, NULL, BBFDM_BOTH},
{"SerialNumber", &DMREAD, DMT_STRING, get_SecurityCertificate_SerialNumber, NULL, NULL, NULL, BBFDM_BOTH},
{"Issuer", &DMREAD, DMT_STRING, get_SecurityCertificate_Issuer, NULL, NULL, NULL, BBFDM_BOTH},
{"NotBefore", &DMREAD, DMT_TIME, get_SecurityCertificate_NotBefore, NULL, NULL, NULL, BBFDM_BOTH},
{"NotAfter", &DMREAD, DMT_TIME, get_SecurityCertificate_NotAfter, NULL, NULL, NULL, BBFDM_BOTH},
{"Subject", &DMREAD, DMT_STRING, get_SecurityCertificate_Subject, NULL, NULL, NULL, BBFDM_BOTH},
//{"SubjectAlt", &DMREAD, DMT_STRING, get_SecurityCertificate_SubjectAlt, NULL, NULL, NULL, BBFDM_BOTH},
{"SignatureAlgorithm", &DMREAD, DMT_STRING, get_SecurityCertificate_SignatureAlgorithm, NULL, NULL, NULL, BBFDM_BOTH},
{0}
};
