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
 OSSLMLDSA.cpp

 OpenSSL ML-DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_MLDSA
#include "log.h"
#include "OSSLMLDSA.h"
#include "CryptoFactory.h"
#include "MLDSAParameters.h"
#include "OSSLMLDSAKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

// Signing functions
bool OSSLMLDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLMLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLMLDSAPrivateKey* pk = (OSSLMLDSAPrivateKey*) privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}

	// Perform the signature operation
	size_t len = pk->getOutputLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the signature length");
		return false;
	}
	signature.resize(len);
	memset(&signature[0], 0, len);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("ML-DSA sign init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	if (!EVP_DigestSign(ctx, &signature[0], &len, dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("ML-DSA sign failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	return true;
}

bool OSSLMLDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ML-DSA does not support multi part signing");

	return false;
}

bool OSSLMLDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("ML-DSA does not support multi part signing");

	return false;
}

bool OSSLMLDSA::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("ML-DSA does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLMLDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLMLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLMLDSAPublicKey* pk = (OSSLMLDSAPublicKey*) publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}

	// Perform the verify operation
	// Perform the signature operation
	size_t len = pk->getOutputLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the signature length");
		return false;
	}
	if (signature.size() != len)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("ML-DSA verify init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	int ret = EVP_DigestVerify(ctx, signature.const_byte_str(), len, originalData.const_byte_str(), originalData.size());
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("ML-DSA verify failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	return true;
}

bool OSSLMLDSA::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ML-DSA does not support multi part verifying");

	return false;
}

bool OSSLMLDSA::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("ML-DSA does not support multi part verifying");

	return false;
}

bool OSSLMLDSA::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("ML-DSA does not support multi part verifying");

	return false;
}

// Key factory
bool OSSLMLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(MLDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-DSA key generation");

		return false;
	}

	MLDSAParameters* params = (MLDSAParameters*) parameters;
	int nid = OSSL::parameterSet2Nid(params->getParameterSet());

	// Generate the key-pair
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(nid, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL ML-DSA context");

		return false;
	}
	int ret = EVP_PKEY_keygen_init(ctx);
	if (ret != 1)
	{
		ERROR_MSG("ML-DSA key generation init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	ret = EVP_PKEY_keygen(ctx, &pkey);
	if (ret != 1)
	{
		ERROR_MSG("ML-DSA key generation failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// Create an asymmetric key-pair object to return
	OSSLMLDSAKeyPair* kp = new OSSLMLDSAKeyPair();

	((OSSLMLDSAPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLMLDSAPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}


bool OSSLMLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLMLDSAKeyPair* kp = new OSSLMLDSAKeyPair();

	bool rv = true;

	if (!((MLDSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((MLDSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
	{
		rv = false;
	}

	if (!rv)
	{
		delete kp;

		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool OSSLMLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLMLDSAPublicKey* pub = new OSSLMLDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLMLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLMLDSAPrivateKey* priv = new OSSLMLDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLMLDSA::newPublicKey()
{
	return (PublicKey*) new OSSLMLDSAPublicKey();
}

PrivateKey* OSSLMLDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLMLDSAPrivateKey();
}

AsymmetricParameters* OSSLMLDSA::newParameters()
{
	return (AsymmetricParameters*) new MLDSAParameters();
}

bool OSSLMLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	MLDSAParameters* params = new MLDSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
