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
 OSSLDHPublicKey.cpp

 OpenSSL Diffie-Hellman public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLComp.h"
#include "OSSLDHPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#else
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#endif
#include <string.h>

// The type
/*static*/ const char* OSSLDHPublicKey::type = "OpenSSL DH Public Key";

// Constructors
OSSLDHPublicKey::OSSLDHPublicKey()
{
	dh = NULL;
}

// Check if the key is of the given type
bool OSSLDHPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

OSSLDHPublicKey::OSSLDHPublicKey(
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	const DH* inDH
#else
	const EVP_PKEY *inDH
#endif
)
{
	dh = NULL;

	setFromOSSL(inDH);
}

// Destructor
OSSLDHPublicKey::~OSSLDHPublicKey()
{
	resetOSSLKey();
}


// Setters for the DH public key components
void OSSLDHPublicKey::setP(const ByteString& inP)
{
	DHPublicKey::setP(inP);

	resetOSSLKey();
}

void OSSLDHPublicKey::setG(const ByteString& inG)
{
	DHPublicKey::setG(inG);

	resetOSSLKey();
}

void OSSLDHPublicKey::setY(const ByteString& inY)
{
	DHPublicKey::setY(inY);

	resetOSSLKey();
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
// Retrieve the OpenSSL representation of the key
DH* OSSLDHPublicKey::getOSSLKey()
{
	if (dh == NULL) createOSSLKey();

	return dh;
}

// Set from OpenSSL representation
void OSSLDHPublicKey::setFromOSSL(const DH* inDH)
{
	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_g = NULL;
	const BIGNUM* bn_pub_key = NULL;

	DH_get0_pqg(inDH, &bn_p, NULL, &bn_g);
	DH_get0_key(inDH, &bn_pub_key, NULL);

	if (bn_p)
	{
		ByteString inP = OSSL::bn2ByteString(bn_p);
		setP(inP);
	}
	if (bn_g)
	{
		ByteString inG = OSSL::bn2ByteString(bn_g);
		setG(inG);
	}
	if (bn_pub_key)
	{
		ByteString inY = OSSL::bn2ByteString(bn_pub_key);
		setY(inY);
	}
}

void OSSLDHPublicKey::resetOSSLKey()
{
	if (dh)
	{
		DH_free(dh);
		dh = NULL;
	}
}

// Create the OpenSSL representation of the key
void OSSLDHPublicKey::createOSSLKey()
{
	if (dh != NULL) return;

	dh = DH_new();
	if (dh == NULL)
	{
		ERROR_MSG("Could not create DH object");
		return;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

#ifdef WITH_FIPS
	if (FIPS_mode())
		DH_set_method(dh, FIPS_dh_openssl());
	else
		DH_set_method(dh, DH_OpenSSL());
#else
	DH_set_method(dh, DH_OpenSSL());
#endif

#else
	DH_set_method(dh, DH_OpenSSL());
#endif

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_g = OSSL::byteString2bn(g);
	BIGNUM* bn_pub_key = OSSL::byteString2bn(y);

	DH_set0_pqg(dh, bn_p, NULL, bn_g);
	DH_set0_key(dh, bn_pub_key, NULL);
}
#else

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLDHPublicKey::getOSSLKey()
{
	if (dh == NULL) createOSSLKey();
	return dh;
}

// Set from OpenSSL representation
void OSSLDHPublicKey::setFromOSSL(const EVP_PKEY* inDH)
{
	BIGNUM *bn_p = NULL, *bn_g = NULL, *bn_pub_key = NULL;
	EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_FFC_P, &bn_p);
	EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_FFC_G, &bn_g);
	EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_PUB_KEY, &bn_pub_key);

	if (bn_p)
	{
		ByteString inP = OSSL::bn2ByteString(bn_p);
		setP(inP);
		BN_free(bn_p);
	}
	if (bn_g)
	{
		ByteString inG = OSSL::bn2ByteString(bn_g);
		setG(inG);
		BN_free(bn_g);
	}
	if (bn_pub_key)
	{
		ByteString inY = OSSL::bn2ByteString(bn_pub_key);
		setY(inY);
		BN_free(bn_pub_key);
	}
}

void OSSLDHPublicKey::resetOSSLKey()
{
	if (dh)
	{
		EVP_PKEY_free(dh);
		dh = NULL;
	}
}

// Create the OpenSSL representation of the key using OSSL_PARAM_BLD
void OSSLDHPublicKey::createOSSLKey()
{
	if (dh != NULL) return;

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_g = OSSL::byteString2bn(g);
	BIGNUM* bn_pub_key = OSSL::byteString2bn(y);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!ctx)
	{
		ERROR_MSG("Could not create EVP_PKEY_CTX object");
		BN_free(bn_p);
		BN_free(bn_g);
		BN_free(bn_pub_key);
		return;
	}

	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	if (!bld)
	{
		ERROR_MSG("Could not create OSSL_PARAM_BLD");
		EVP_PKEY_CTX_free(ctx);
		BN_free(bn_p);
		BN_free(bn_g);
		BN_free(bn_pub_key);
		return;
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
		!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g) ||
		!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bn_pub_key))
	{
		ERROR_MSG("Failed to push DH params to OSSL_PARAM_BLD");
		OSSL_PARAM_BLD_free(bld);
		EVP_PKEY_CTX_free(ctx);
		BN_free(bn_p);
		BN_free(bn_g);
		BN_free(bn_pub_key);
		return;
	}

	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
	if (!params)
	{
		ERROR_MSG("OSSL_PARAM_BLD_to_param failed");
		OSSL_PARAM_BLD_free(bld);
		EVP_PKEY_CTX_free(ctx);
		BN_free(bn_p);
		BN_free(bn_g);
		BN_free(bn_pub_key);
		return;
	}

	if (EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &dh, EVP_PKEY_PUBLIC_KEY, params) <= 0)
	{
		ERROR_MSG("EVP_PKEY_fromdata failed");
		dh = NULL;
	}

	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);
	BN_free(bn_p);
	BN_free(bn_g);
	BN_free(bn_pub_key);
}

#endif