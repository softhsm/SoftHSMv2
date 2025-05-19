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
#ifdef WITH_MLDSA
#include "log.h"
#include "OSSLMLDSAPublicKey.h"
#include "MLDSAParameters.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <string.h>

// Constructors
OSSLMLDSAPublicKey::OSSLMLDSAPublicKey()
{
	mldsakey = EVP_PKEY_new();
}

OSSLMLDSAPublicKey::OSSLMLDSAPublicKey(const EVP_PKEY* inEVPPKEY)
{
	mldsakey = EVP_PKEY_new();

	setFromOSSL(inEVPPKEY);
}

// Destructor
OSSLMLDSAPublicKey::~OSSLMLDSAPublicKey()
{
	EVP_PKEY_free(mldsakey);
}

// The type
/*static*/ const char* OSSLMLDSAPublicKey::type = "OpenSSL ML-DSA Public Key";

// Set from OpenSSL representation
void OSSLMLDSAPublicKey::setFromOSSL(const EVP_PKEY* inEVPPKEY)
{
	// let's use max pub length
    size_t pub_len;
    EVP_PKEY_get_octet_string_param(inEVPPKEY, OSSL_PKEY_PARAM_PUB_KEY,
                                    pub, sizeof(pub), &pub_len);

	if (pub_len != 0)
	{
		if (pub_len == MLDSAParameters::ML_DSA_44_PUB_LENGTH) {
			setParameterSet(MLDSAParameters::ML_DSA_44_PARAMETER_SET);
		}
		if (pub_len == MLDSAParameters::ML_DSA_65_PUB_LENGTH) {
			setParameterSet(MLDSAParameters::ML_DSA_65_PARAMETER_SET);
		}
		if (pub_len == MLDSAParameters::ML_DSA_87_PUB_LENGTH) {
			setParameterSet(MLDSAParameters::ML_DSA_87_PARAMETER_SET);
		}

		ByteString inPub = ByteString(pub, pub_len);
		ByteString rho = inPub.substr(0, 32);
		ByteString t1 = inPub.substr(32, pub_len);
		setRho(rho);
		setT1(t1);
	}
}

// Check if the key is of the given type
bool OSSLMLDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the ML-DSA public key components
void OSSLMLDSAPublicKey::setRho(const ByteString& inRho)
{
	MLDSAPublicKey::setRho(inRho);

	if (mldsakey)
	{
		EVP_PKEY_free(mldsakey);
		mldsakey = NULL;
	}
}

void OSSLMLDSAPublicKey::setT1(const ByteString& inT1)
{
	MLDSAPublicKey::setT1(inT1);

	if (mldsakey)
	{
		EVP_PKEY_free(mldsakey);
		mldsakey = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLMLDSAPublicKey::getOSSLKey()
{
	return mldsakey;
}
#endif
