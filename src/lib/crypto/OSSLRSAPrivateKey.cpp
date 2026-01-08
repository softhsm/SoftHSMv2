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
 OSSLRSAPrivateKey.cpp

 OpenSSL RSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLComp.h"
#include "OSSLRSAPrivateKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#else
#include <openssl/rsa.h>
#endif
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>

// Constructors
OSSLRSAPrivateKey::OSSLRSAPrivateKey()
{
	rsa = NULL;
}

OSSLRSAPrivateKey::OSSLRSAPrivateKey(const EVP_PKEY *inRSA)
{
	rsa = NULL;

	setFromOSSL(inRSA);
}

// Destructor
OSSLRSAPrivateKey::~OSSLRSAPrivateKey()
{
	EVP_PKEY_free(rsa);
}

// The type
/*static*/ const char *OSSLRSAPrivateKey::type = "OpenSSL RSA Private Key";

// Set from OpenSSL representation
void OSSLRSAPrivateKey::setFromOSSL(const EVP_PKEY *inRSA)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	BIGNUM *bn_p = NULL;
	BIGNUM *bn_q = NULL;
	BIGNUM *bn_dmp1 = NULL;
	BIGNUM *bn_dmq1 = NULL;
	BIGNUM *bn_iqmp = NULL;
	BIGNUM *bn_n = NULL;
	BIGNUM *bn_e = NULL;
	BIGNUM *bn_d = NULL;

	EVP_PKEY_get_bn_param(inRSA, "rsa-factor1", &bn_p);
	EVP_PKEY_get_bn_param(inRSA, "rsa-factor2", &bn_q);
	EVP_PKEY_get_bn_param(inRSA, "rsa-exponent1", &bn_dmp1);
	EVP_PKEY_get_bn_param(inRSA, "rsa-exponent2", &bn_dmq1);
	EVP_PKEY_get_bn_param(inRSA, "rsa-coefficient1", &bn_iqmp);
	EVP_PKEY_get_bn_param(inRSA, "n", &bn_n);
	EVP_PKEY_get_bn_param(inRSA, "e", &bn_e);
	EVP_PKEY_get_bn_param(inRSA, "d", &bn_d);
	if (bn_p)
	{
		setP(OSSL::bn2ByteString(bn_p));
		BN_free(bn_p);
	}
	if (bn_q)
	{
		setQ(OSSL::bn2ByteString(bn_q));
		BN_free(bn_q);
	}
	if (bn_dmp1)
	{
		setDP1(OSSL::bn2ByteString(bn_dmp1));
		BN_free(bn_dmp1);
	}
	if (bn_dmq1)
	{
		setDQ1(OSSL::bn2ByteString(bn_dmq1));
		BN_free(bn_dmq1);
	}
	if (bn_iqmp)
	{
		setPQ(OSSL::bn2ByteString(bn_iqmp));
		BN_free(bn_iqmp);
	}
	if (bn_n)
	{
		setN(OSSL::bn2ByteString(bn_n));
		BN_free(bn_n);
	}
	if (bn_e)
	{
		setE(OSSL::bn2ByteString(bn_e));
		BN_free(bn_e);
	}
	if (bn_d)
	{
		setD(OSSL::bn2ByteString(bn_d));
		BN_free(bn_d);
	}
#else
	const BIGNUM *bn_p = NULL;
	const BIGNUM *bn_q = NULL;
	const BIGNUM *bn_dmp1 = NULL;
	const BIGNUM *bn_dmq1 = NULL;
	const BIGNUM *bn_iqmp = NULL;
	const BIGNUM *bn_n = NULL;
	const BIGNUM *bn_e = NULL;
	const BIGNUM *bn_d = NULL;
	const RSA *inRSA1 = EVP_PKEY_get0_RSA(const_cast<EVP_PKEY *>(inRSA));
	RSA_get0_factors(inRSA1, &bn_p, &bn_q);
	RSA_get0_crt_params(inRSA1, &bn_dmp1, &bn_dmq1, &bn_iqmp);
	RSA_get0_key(inRSA1, &bn_n, &bn_e, &bn_d);
	if (bn_p)
	{
		setP(OSSL::bn2ByteString(bn_p));
	}
	if (bn_q)
	{
		setQ(OSSL::bn2ByteString(bn_q));
	}
	if (bn_dmp1)
	{
		setDP1(OSSL::bn2ByteString(bn_dmp1));
	}
	if (bn_dmq1)
	{
		setDQ1(OSSL::bn2ByteString(bn_dmq1));
	}
	if (bn_iqmp)
	{
		setPQ(OSSL::bn2ByteString(bn_iqmp));
	}
	if (bn_n)
	{
		setN(OSSL::bn2ByteString(bn_n));
	}
	if (bn_e)
	{
		setE(OSSL::bn2ByteString(bn_e));
	}
	if (bn_d)
	{
		setD(OSSL::bn2ByteString(bn_d));
	}
#endif
}

// Check if the key is of the given type
bool OSSLRSAPrivateKey::isOfType(const char *inType)
{
	return !strcmp(type, inType);
}

// Setters for the RSA private key components
void OSSLRSAPrivateKey::setP(const ByteString &inP)
{
	RSAPrivateKey::setP(inP);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setQ(const ByteString &inQ)
{
	RSAPrivateKey::setQ(inQ);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setPQ(const ByteString &inPQ)
{
	RSAPrivateKey::setPQ(inPQ);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setDP1(const ByteString &inDP1)
{
	RSAPrivateKey::setDP1(inDP1);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setDQ1(const ByteString &inDQ1)
{
	RSAPrivateKey::setDQ1(inDQ1);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setD(const ByteString &inD)
{
	RSAPrivateKey::setD(inD);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

// Setters for the RSA public key components
void OSSLRSAPrivateKey::setN(const ByteString &inN)
{
	RSAPrivateKey::setN(inN);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}

void OSSLRSAPrivateKey::setE(const ByteString &inE)
{
	RSAPrivateKey::setE(inE);

	if (rsa)
	{
		EVP_PKEY_free(rsa);
		rsa = NULL;
	}
}
// Encode into PKCS#8 DER
ByteString OSSLRSAPrivateKey::PKCS8Encode()
{
	ByteString der;

	if (rsa == NULL)
		createOSSLKey();
	if (rsa == NULL)
		return der;
	PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(rsa);
	if (p8inf == NULL)
		return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char *priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len)
		der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLRSAPrivateKey::PKCS8Decode(const ByteString &ber)
{
	int len = ber.size();
	if (len <= 0)
		return false;
	const unsigned char *priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL)
		return false;
	EVP_PKEY *pkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (pkey == NULL)
		return false;
	setFromOSSL(pkey);
	EVP_PKEY_free(pkey);
	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY *OSSLRSAPrivateKey::getOSSLKey()
{
	if (rsa == NULL)
		createOSSLKey();

	return rsa;
}

// Create the OpenSSL representation of the key
void OSSLRSAPrivateKey::createOSSLKey()
{
	if (rsa != NULL)
		return;

	BIGNUM *bn_p = OSSL::byteString2bn(p);
	BIGNUM *bn_q = OSSL::byteString2bn(q);
	BIGNUM *bn_dmp1 = OSSL::byteString2bn(dp1);
	BIGNUM *bn_dmq1 = OSSL::byteString2bn(dq1);
	BIGNUM *bn_iqmp = OSSL::byteString2bn(pq);
	BIGNUM *bn_n = OSSL::byteString2bn(n);
	BIGNUM *bn_d = OSSL::byteString2bn(d);
	BIGNUM *bn_e = OSSL::byteString2bn(e);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
	bool bBuildErr = false;
	if ((param_bld == NULL) ||
		(bn_n == NULL) ||
		(bn_e == NULL) ||
		(bn_d == NULL) ||
		(OSSL_PARAM_BLD_push_BN(param_bld, "n", bn_n) <= 0) ||
		(OSSL_PARAM_BLD_push_BN(param_bld, "e", bn_e) <= 0) ||
		(OSSL_PARAM_BLD_push_BN(param_bld, "d", bn_d) <= 0))
	{
		bBuildErr = true;
	}
	if ((!bBuildErr) && (bn_p != NULL))
		bBuildErr |= (OSSL_PARAM_BLD_push_BN(param_bld, "rsa-factor1", bn_p) <= 0);
	if ((!bBuildErr) && (bn_q != NULL))
		bBuildErr |= (OSSL_PARAM_BLD_push_BN(param_bld, "rsa-factor2", bn_q) <= 0);
	if ((!bBuildErr) && (bn_dmp1 != NULL))
		bBuildErr |= (OSSL_PARAM_BLD_push_BN(param_bld, "rsa-exponent1", bn_dmp1) <= 0);
	if ((!bBuildErr) && (bn_dmq1 != NULL))
		bBuildErr |= (OSSL_PARAM_BLD_push_BN(param_bld, "rsa-exponent2", bn_dmq1) <= 0);
	if ((!bBuildErr) && (bn_iqmp != NULL))
		bBuildErr |= (OSSL_PARAM_BLD_push_BN(param_bld, "rsa-coefficient1", bn_iqmp) <= 0);

	OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
	OSSL_PARAM_BLD_free(param_bld);
	BN_free(bn_n);
	BN_free(bn_e);
	BN_free(bn_d);
	BN_free(bn_p);
	BN_free(bn_q);
	BN_free(bn_dmp1);
	BN_free(bn_dmq1);
	BN_free(bn_iqmp);
	if ((bBuildErr) || (params == NULL))
	{
		ERROR_MSG("Could not build RSA key parameters");
		return;
	}
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Could not create RSA key creation context");
		OSSL_PARAM_free(params);
		return;
	}
	if ((EVP_PKEY_fromdata_init(ctx) <= 0) ||
		(EVP_PKEY_fromdata(ctx, &rsa, EVP_PKEY_KEYPAIR, params) <= 0))
	{
		ERROR_MSG("Could not create RSA key object");
		OSSL_PARAM_free(params);
		EVP_PKEY_CTX_free(ctx);
		rsa = NULL;
		return;
	}
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(ctx);

#else
	RSA *rsa1 = RSA_new();
	if (rsa1 == NULL)
	{
		ERROR_MSG("Could not build RSA object");
		return;
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	// Use the OpenSSL implementation and not any engine

#ifdef WITH_FIPS
	if (FIPS_mode())
		RSA_set_method(rsa1, FIPS_rsa_pkcs1_ssleay());
	else
		RSA_set_method(rsa1, RSA_PKCS1_SSLeay());
#else
	RSA_set_method(rsa1, RSA_PKCS1_SSLeay());
#endif

#else
	RSA_set_method(rsa1, RSA_PKCS1_OpenSSL());
#endif
	RSA_set0_factors(rsa1, bn_p, bn_q);
	RSA_set0_crt_params(rsa1, bn_dmp1, bn_dmq1, bn_iqmp);
	RSA_set0_key(rsa1, bn_n, bn_e, bn_d);
	rsa = EVP_PKEY_new();
	if (rsa == NULL)
	{
		ERROR_MSG("Could not build RSA PKEY");
		RSA_free(rsa1);
		return;
	}
	if (EVP_PKEY_assign_RSA(rsa, rsa1) <= 0)
	{
		ERROR_MSG("Could not assign RSA PKEY");
		RSA_free(rsa1);
		EVP_PKEY_free(rsa);
		rsa = NULL;
		return;
	}
#endif
}
