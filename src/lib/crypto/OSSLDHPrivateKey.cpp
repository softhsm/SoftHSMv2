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
 OSSLDHPrivateKey.cpp

 OpenSSL Diffie-Hellman private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLComp.h"
#include "OSSLDHPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
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

// Constructors
OSSLDHPrivateKey::OSSLDHPrivateKey()
{
	dh = NULL;
}

OSSLDHPrivateKey::OSSLDHPrivateKey(
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
OSSLDHPrivateKey::~OSSLDHPrivateKey()
{
	resetOSSLKey();
}

// The type
/*static*/ const char* OSSLDHPrivateKey::type = "OpenSSL DH Private Key";


// Check if the key is of the given type
bool OSSLDHPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the DH private key components
void OSSLDHPrivateKey::setX(const ByteString& inX)
{
	DHPrivateKey::setX(inX);

	resetOSSLKey();
}


// Setters for the DH public key components
void OSSLDHPrivateKey::setP(const ByteString& inP)
{
	DHPrivateKey::setP(inP);

	resetOSSLKey();
}

void OSSLDHPrivateKey::setG(const ByteString& inG)
{
	DHPrivateKey::setG(inG);

	resetOSSLKey();
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
// Encode into PKCS#8 DER
ByteString OSSLDHPrivateKey::PKCS8Encode()
{
	ByteString der;
	if (dh == NULL) createOSSLKey();
	if (dh == NULL) return der;
	EVP_PKEY* pkey = EVP_PKEY_new();
	if (pkey == NULL) return der;
	if (!EVP_PKEY_set1_DH(pkey, dh))
	{
		EVP_PKEY_free(pkey);
		return der;
	}
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(pkey);
	EVP_PKEY_free(pkey);
	if (p8inf == NULL) return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char* priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len) der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLDHPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* pkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (pkey == NULL) return false;
	DH* key = EVP_PKEY_get1_DH(pkey);
	EVP_PKEY_free(pkey);
	if (key == NULL) return false;
	setFromOSSL(key);
	DH_free(key);
	return true;
}

// Retrieve the OpenSSL representation of the key
DH* OSSLDHPrivateKey::getOSSLKey()
{
	if (dh == NULL) createOSSLKey();

	return dh;
}

// Set from OpenSSL representation
void OSSLDHPrivateKey::setFromOSSL(const DH* inDH)
{
	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_g = NULL;
	const BIGNUM* bn_priv_key = NULL;

	DH_get0_pqg(inDH, &bn_p, NULL, &bn_g);
	DH_get0_key(inDH, NULL, &bn_priv_key);

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
	if (bn_priv_key)
	{
		ByteString inX = OSSL::bn2ByteString(bn_priv_key);
		setX(inX);
	}
}

void OSSLDHPrivateKey::resetOSSLKey()
{
	if (dh)
	{
		DH_free(dh);
		dh = NULL;
	}
}

// Create the OpenSSL representation of the key
void OSSLDHPrivateKey::createOSSLKey()
{
	if (dh != NULL) return;

	BN_CTX *ctx = BN_CTX_new();
	if (ctx == NULL)
	{
		ERROR_MSG("Could not create BN_CTX");
		return;
	}

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
	BIGNUM* bn_priv_key = OSSL::byteString2bn(x);
	BIGNUM* bn_pub_key = BN_new();

	BN_mod_exp(bn_pub_key, bn_g, bn_priv_key, bn_p, ctx);
	BN_CTX_free(ctx);

	DH_set0_pqg(dh, bn_p, NULL, bn_g);
	DH_set0_key(dh, bn_pub_key, bn_priv_key);
}

#else

// Encode into PKCS#8 DER
ByteString OSSLDHPrivateKey::PKCS8Encode()
{
	ByteString der;
	if (dh == NULL) createOSSLKey();
	if (dh == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(dh);
	if (p8inf == NULL) return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char* priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len) der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLDHPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* pkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (pkey == NULL) return false;
	setFromOSSL(pkey);
	EVP_PKEY_free(pkey);
	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLDHPrivateKey::getOSSLKey()
{
	if (dh == NULL) createOSSLKey();
	return dh;
}

// Set from OpenSSL representation
void OSSLDHPrivateKey::setFromOSSL(const EVP_PKEY* inDH)
{
	BIGNUM *bn_p = NULL, *bn_g = NULL, *bn_priv_key = NULL;
	EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_FFC_P, &bn_p);
	EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_FFC_G, &bn_g);
	EVP_PKEY_get_bn_param(inDH, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv_key);

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
	if (bn_priv_key)
	{
		ByteString inX = OSSL::bn2ByteString(bn_priv_key);
		setX(inX);
		BN_free(bn_priv_key);
	}
}

void OSSLDHPrivateKey::resetOSSLKey()
{
	if (dh)
	{
		EVP_PKEY_free(dh);
		dh = NULL;
	}
}

// Create the OpenSSL representation of the key using OSSL_PARAM_BLD
void OSSLDHPrivateKey::createOSSLKey()
{
	if (dh != NULL) return;

	BIGNUM* bn_p = OSSL::byteString2bn(p);
	BIGNUM* bn_g = OSSL::byteString2bn(g);
	BIGNUM* bn_priv_key = OSSL::byteString2bn(x);

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!ctx)
	{
		ERROR_MSG("Could not create EVP_PKEY_CTX object");
		BN_free(bn_p);
		BN_free(bn_g);
		BN_free(bn_priv_key);
		return;
	}

	OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
	if (!bld)
	{
		ERROR_MSG("Could not create OSSL_PARAM_BLD");
		BN_free(bn_p);
		BN_free(bn_g);
		BN_free(bn_priv_key);
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
		!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g) ||
		!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv_key))
	{
		ERROR_MSG("Failed to push DH params to OSSL_PARAM_BLD");
		OSSL_PARAM_BLD_free(bld);
		EVP_PKEY_CTX_free(ctx);
		BN_free(bn_p);
		BN_free(bn_g);
		BN_free(bn_priv_key);
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
		BN_free(bn_priv_key);
		return;
	}

	if (EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &dh, EVP_PKEY_KEYPAIR, params) <= 0)
	{
		ERROR_MSG("EVP_PKEY_fromdata failed");
		dh = NULL;
	}

	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);
	BN_free(bn_p);
	BN_free(bn_g);
	BN_free(bn_priv_key);
}

#endif
