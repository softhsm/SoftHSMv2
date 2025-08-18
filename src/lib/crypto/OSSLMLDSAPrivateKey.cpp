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
#ifdef WITH_ML_DSA
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
	pkey = NULL;
}

OSSLMLDSAPrivateKey::OSSLMLDSAPrivateKey(const EVP_PKEY* inMLDSAKEY)
{
	pkey = NULL;

	setFromOSSL(inMLDSAKEY);
}

// Destructor
OSSLMLDSAPrivateKey::~OSSLMLDSAPrivateKey()
{
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// The type
const char* OSSLMLDSAPrivateKey::type = "OpenSSL ML-DSA Private Key";

// Set from OpenSSL representation
void OSSLMLDSAPrivateKey::setFromOSSL(const EVP_PKEY* inMLDSAKEY)
{
	uint8_t seed[32];
	size_t seed_len;
	int rv = EVP_PKEY_get_octet_string_param(inMLDSAKEY, OSSL_PKEY_PARAM_ML_DSA_SEED,
								seed, sizeof(seed), &seed_len);
	if(rv && seed_len == 32) {
		// seed is not mandatory for OSSL key reconstruction
		ByteString seedBS = ByteString(seed, seed_len);
		setSeed(seedBS);
	}
	
	// let's use max priv length
	uint8_t priv[MLDSAParameters::ML_DSA_87_PRIV_LENGTH];
	size_t priv_len;
	rv = EVP_PKEY_get_octet_string_param(inMLDSAKEY, OSSL_PKEY_PARAM_PRIV_KEY,
									priv, sizeof(priv), &priv_len);
	if(!rv) {
		ERROR_MSG("Could not get private key private, rv: %d", rv);
		return;
	}

	ByteString valueBS = ByteString(priv, priv_len);

	setValue(valueBS);
}

// Check if the key is of the given type
bool OSSLMLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLMLDSAPrivateKey::setValue(const ByteString& inValue)
{
	MLDSAPrivateKey::setValue(inValue);
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

void OSSLMLDSAPrivateKey::setSeed(const ByteString& inSeed)
{
	MLDSAPrivateKey::setSeed(inSeed);
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString OSSLMLDSAPrivateKey::PKCS8Encode()
{
	ByteString der;
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(key);
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
	EVP_PKEY* localPKey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (localPKey == NULL) return false;
	setFromOSSL(localPKey);
	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLMLDSAPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLMLDSAPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;

	pkey = EVP_PKEY_new();

	ByteString localValue = getValue();

	const char* name = OSSL::mldsaParameterSet2Name(getParameterSet());

	int selection = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3], *p = params;

	*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
												localValue.byte_str(), localValue.size());
	selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

	*p = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL) {
		ERROR_MSG("Could not create context");
		return;
	}
	int rv = EVP_PKEY_fromdata_init(ctx);
	if (!rv) {
		ERROR_MSG("Could not EVP_PKEY_fromdata_init:%d", rv);
		EVP_PKEY_CTX_free(ctx);
		return;
	}
	rv = EVP_PKEY_fromdata(ctx, &pkey, selection, params);
	if (!rv) {
		ERROR_MSG("Could not EVP_PKEY_fromdata:%d", rv);
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	EVP_PKEY_CTX_free(ctx);

}

#endif
