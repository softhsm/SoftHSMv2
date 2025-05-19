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
 OSSLMLDSAPublicKey.cpp

 OpenSSL ML-DSA public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "log.h"
#include "OSSLMLDSAPublicKey.h"
#include "MLDSAParameters.h"
#include "OSSLUtil.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string.h>

// Constructors
OSSLMLDSAPublicKey::OSSLMLDSAPublicKey()
{
	pkey = NULL;
}

OSSLMLDSAPublicKey::OSSLMLDSAPublicKey(const EVP_PKEY* inEVPPKEY)
{
	pkey = NULL;

	setFromOSSL(inEVPPKEY);
}

// Destructor
OSSLMLDSAPublicKey::~OSSLMLDSAPublicKey()
{
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// The type
/*static*/ const char* OSSLMLDSAPublicKey::type = "OpenSSL ML-DSA Public Key";

// Set from OpenSSL representation
void OSSLMLDSAPublicKey::setFromOSSL(const EVP_PKEY* inEVPPKEY)
{
	// let's use max pub length
	uint8_t localPub[MLDSAParameters::ML_DSA_87_PUB_LENGTH];
    size_t pub_len;
    int rv = EVP_PKEY_get_octet_string_param(inEVPPKEY, OSSL_PKEY_PARAM_PUB_KEY,
                                    localPub, sizeof(localPub), &pub_len);

	if(!rv) {
		ERROR_MSG("Could not get private key private, rv: %d", rv);
		return;
	}

	ByteString pubBS = ByteString(localPub, pub_len);
	setValue(pubBS);
	
}

// Check if the key is of the given type
bool OSSLMLDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLMLDSAPublicKey::setValue(const ByteString& inValue)
{
	MLDSAPublicKey::setValue(inValue);
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLMLDSAPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLMLDSAPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;

	pkey = EVP_PKEY_new();

	ByteString localValue = getValue();

	const char* name = OSSL::mldsaParameterSet2Name(getParameterSet());

	int selection = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3], *p = params;

	*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
												localValue.byte_str(), localValue.size());
	selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

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
