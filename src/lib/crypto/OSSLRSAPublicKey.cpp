/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLRSAPublicKey.cpp

 OpenSSL RSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLComp.h"
#include "OSSLRSAPublicKey.h"
#include "OSSLUtil.h"
#include <string.h>
#include <openssl/bn.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#endif
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif

// Constructors
OSSLRSAPublicKey::OSSLRSAPublicKey()
{
	rsa = NULL;
}

OSSLRSAPublicKey::OSSLRSAPublicKey(const EVP_PKEY *inRSA)
{
	rsa = NULL;

	setFromOSSL(inRSA);
}

// Destructor
OSSLRSAPublicKey::~OSSLRSAPublicKey()
{
	EVP_PKEY_free(rsa);
}

// The type
/*static*/ const char *OSSLRSAPublicKey::type = "OpenSSL RSA Public Key";

// Check if the key is of the given type
bool OSSLRSAPublicKey::isOfType(const char *inType)
{
	return !strcmp(type, inType);
}

// Set from OpenSSL representation
void OSSLRSAPublicKey::setFromOSSL(const EVP_PKEY *inRSA)
{
	BIGNUM *bn_n = NULL;
	BIGNUM *bn_e = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY_get_bn_param(inRSA, "n", &bn_n);
	EVP_PKEY_get_bn_param(inRSA, "e", &bn_e);
#endif
	if (bn_n)
	{
		ByteString inN = OSSL::bn2ByteString(bn_n);
		setN(inN);
		BN_free(bn_n);
	}
	if (bn_e)
	{
		ByteString inE = OSSL::bn2ByteString(bn_e);
		setE(inE);
		BN_free(bn_e);
	}
}

// Setters for the RSA public key components
void OSSLRSAPublicKey::setN(const ByteString &inN)
{
	RSAPublicKey::setN(inN);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPublicKey::setE(const ByteString &inE)
{
	RSAPublicKey::setE(inE);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY *OSSLRSAPublicKey::getOSSLKey()
{
	if (rsa == NULL)
		createOSSLKey();

	return rsa;
}

// Create the OpenSSL representation of the key
void OSSLRSAPublicKey::createOSSLKey()
{
	if (rsa != NULL)
		return;


	BIGNUM* bn_n = OSSL::byteString2bn(n);
	BIGNUM* bn_e = OSSL::byteString2bn(e);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();

	if ((param_bld == NULL) ||
	(bn_n == NULL) ||
	(bn_e == NULL) ||
	(OSSL_PARAM_BLD_push_BN(param_bld,"n",bn_n) <= 0 ) ||
	(OSSL_PARAM_BLD_push_BN(param_bld,"e",bn_e) <= 0 ))
	{
		OSSL_PARAM_BLD_free(param_bld);
		BN_free(bn_n);
		BN_free(bn_e);
		ERROR_MSG("Could not build RSA public key parameters");
		return;
	}
	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
	OSSL_PARAM_BLD_free(param_bld);
	BN_free(bn_n);
	BN_free(bn_e);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Could not create RSA public key creation context");
		OSSL_PARAM_free(params);
		return;
	}
	if ((EVP_PKEY_fromdata_init(ctx) <= 0) ||
		(EVP_PKEY_fromdata(ctx, &rsa, EVP_PKEY_PUBLIC_KEY, params) <= 0))
	{
		ERROR_MSG("Could not create public RSA key object");
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(ctx);
		rsa = NULL;
		return;
	}
    OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(ctx);
	
#else
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
// Use the OpenSSL implementation and not any engine
#ifdef WITH_FIPS
	if (FIPS_mode())
		RSA_set_method(rsa, FIPS_rsa_pkcs1_ssleay());
	else
		RSA_set_method(rsa, RSA_PKCS1_SSLeay());
#else
	RSA_set_method(rsa, RSA_PKCS1_SSLeay());
#endif

#else
	RSA_set_method(rsa, RSA_PKCS1_OpenSSL());
#endif
#endif
}
