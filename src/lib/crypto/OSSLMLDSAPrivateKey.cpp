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
 OSSLMLDSAPrivateKey.cpp

 OpenSSL ML-DSA private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_MLDSA
#include "log.h"
#include "OSSLMLDSAPrivateKey.h"
#include "MLDSAParameters.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

// Constructors
OSSLMLDSAPrivateKey::OSSLMLDSAPrivateKey()
{
	mldsaKey = EVP_PKEY_new();
}

OSSLMLDSAPrivateKey::OSSLMLDSAPrivateKey(const EVP_PKEY* inMLDSAKEY)
{
	mldsaKey = EVP_PKEY_new();

	setFromOSSL(inMLDSAKEY);
}

// Destructor
OSSLMLDSAPrivateKey::~OSSLMLDSAPrivateKey()
{
	EVP_PKEY_free(mldsaKey);
}

// The type
/*static*/ const char* OSSLMLDSAPrivateKey::type = "OpenSSL ML-DSA Private Key";

// Set from OpenSSL representation
void OSSLMLDSAPrivateKey::setFromOSSL(const EVP_PKEY* inMLDSAKEY)
{
	// let's use max priv length
	//unsigned char priv[MLDSAParameters::ML_DSA_87_PARAMETER_SET];
    size_t priv_len;
    EVP_PKEY_get_octet_string_param(inMLDSAKEY, OSSL_PKEY_PARAM_PRIV_KEY,
									priv, sizeof(priv), &priv_len);

	if (priv_len != 0)
	{
		if (priv_len == MLDSAParameters::ML_DSA_44_PRIV_LENGTH) {
			setParameterSet(MLDSAParameters::ML_DSA_44_PARAMETER_SET);
		}
		if (priv_len == MLDSAParameters::ML_DSA_65_PRIV_LENGTH) {
			setParameterSet(MLDSAParameters::ML_DSA_65_PARAMETER_SET);
		}
		if (priv_len == MLDSAParameters::ML_DSA_87_PRIV_LENGTH) {
			setParameterSet(MLDSAParameters::ML_DSA_87_PARAMETER_SET);
		}

		std::tuple<unsigned long, unsigned long, unsigned long> privateKeyParameters = MLDSAParameters::getPrivateKeyParametersLengths(priv_len);
		unsigned long lLength = std::get<0>(privateKeyParameters);
		unsigned long kLength = std::get<1>(privateKeyParameters);
		unsigned long polyEtaPackedBytes = std::get<2>(privateKeyParameters);

		ByteString inPriv = ByteString(priv, priv_len);
		ByteString rho = inPriv.substr(0, 32);
		ByteString K = inPriv.substr(rho.size(), 32);
		ByteString tr = inPriv.substr(rho.size() + K.size(), 64);
		ByteString s1 = inPriv.substr(rho.size() + K.size() + tr.size(), lLength * polyEtaPackedBytes);
		ByteString s2 = inPriv.substr(rho.size() + K.size() + tr.size() + s1.size(), kLength * polyEtaPackedBytes);
		ByteString t0 = inPriv.substr(rho.size() + K.size() + tr.size() + s1.size() + s2.size(), kLength * MLDSAParameters::ML_DSA_POLY_T0_PACKED_BYTES);
		ByteString t1 = inPriv.substr(rho.size() + K.size() + tr.size() + s1.size() + s2.size() + t0.size(), kLength * MLDSAParameters::ML_DSA_POLY_T1_PACKED_BYTES);

		setRho(rho);
		setK(K);
		setTr(tr);
		setS1(s1);
		setS2(s2);
		setT0(t0);
		setT1(t1);
	}
}

// Check if the key is of the given type
bool OSSLMLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EC private key components
void OSSLMLDSAPrivateKey::setRho(const ByteString& inRho)
{
	MLDSAPrivateKey::setRho(inRho);

	if (mldsaKey)
	{
		EVP_PKEY_free(mldsaKey);
		mldsaKey = NULL;
	}
}

void OSSLMLDSAPrivateKey::setK(const ByteString& inK)
{
	MLDSAPrivateKey::setK(inK);

	if (mldsaKey)
	{
		EVP_PKEY_free(mldsaKey);
		mldsaKey = NULL;
	}
}

void OSSLMLDSAPrivateKey::setTr(const ByteString& inTr)
{
	MLDSAPrivateKey::setTr(inTr);

	if (mldsaKey)
	{
		EVP_PKEY_free(mldsaKey);
		mldsaKey = NULL;
	}
}

void OSSLMLDSAPrivateKey::setS1(const ByteString& inS1)
{
	MLDSAPrivateKey::setS1(inS1);

	if (mldsaKey)
	{
		EVP_PKEY_free(mldsaKey);
		mldsaKey = NULL;
	}
}

void OSSLMLDSAPrivateKey::setS2(const ByteString& inS2)
{
	MLDSAPrivateKey::setS2(inS2);

	if (mldsaKey)
	{
		EVP_PKEY_free(mldsaKey);
		mldsaKey = NULL;
	}
}

void OSSLMLDSAPrivateKey::setT0(const ByteString& inT0)
{
	MLDSAPrivateKey::setT0(inT0);

	if (mldsaKey)
	{
		EVP_PKEY_free(mldsaKey);
		mldsaKey = NULL;
	}
}

void OSSLMLDSAPrivateKey::setT1(const ByteString& inT1)
{
	MLDSAPrivateKey::setT1(inT1);

	if (mldsaKey)
	{
		EVP_PKEY_free(mldsaKey);
		mldsaKey = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString OSSLMLDSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	if (mldsaKey == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(mldsaKey);
	EVP_PKEY_free(mldsaKey);
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
bool OSSLMLDSAPrivateKey::PKCS8Decode(const ByteString& ber)
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
	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLMLDSAPrivateKey::getOSSLKey()
{
	return mldsaKey;
}
#endif
