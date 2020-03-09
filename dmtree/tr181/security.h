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

extern DMOBJ tSecurityObj[];
extern DMLEAF tSecurityParams[];
extern DMLEAF tSecurityCertificateParams[];

#endif //__SECURITY_H

