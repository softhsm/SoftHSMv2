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
 OSSLSLHDSA.cpp

 OpenSSL SLHDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLHDSA
#include "log.h"
#include "OSSLSLHDSA.h"
#include "CryptoFactory.h"
#include "SLHParameters.h"
#include "OSSLSLHKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

// Signing functions
bool OSSLSLHDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::SLHDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLSLHPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLSLHPrivateKey* pk = (OSSLSLHPrivateKey*) privateKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}

	// Perform the signature operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	signature.resize(len);
	memset(&signature[0], 0, len);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey))
	{
		ERROR_MSG("SLHDSA sign init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	if (!EVP_DigestSign(ctx, &signature[0], &len, dataToSign.const_byte_str(), dataToSign.size()))
	{
		ERROR_MSG("SLHDSA sign failed (0x%08X)", ERR_get_error());

		unsigned long err = ERR_get_error();
		char buf[256];
		ERR_error_string_n(err, buf, sizeof(buf));
		ERROR_MSG("SLHDSA sign failed: %s\n", buf);
		ERROR_MSG("Key type: %s\n", EVP_PKEY_get0_type_name(pkey));

		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	return true;
}

bool OSSLSLHDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("SLHDSA does not support multi part signing");

	return false;
}

bool OSSLSLHDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("SLHDSA does not support multi part signing");

	return false;
}

bool OSSLSLHDSA::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("SLHDSA does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLSLHDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::SLHDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLSLHPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLSLHPublicKey* pk = (OSSLSLHPublicKey*) publicKey;
	EVP_PKEY* pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}

	// Perform the verify operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
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
		ERROR_MSG("SLHDSA verify init failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	int ret = EVP_DigestVerify(ctx, signature.const_byte_str(), len, originalData.const_byte_str(), originalData.size());
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("SLHDSA verify failed (0x%08X)", ERR_get_error());
		EVP_MD_CTX_free(ctx);
		return false;
	}
	EVP_MD_CTX_free(ctx);
	return true;
}

bool OSSLSLHDSA::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("SLHDSA does not support multi part verifying");

	return false;
}

bool OSSLSLHDSA::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("SLHDSA does not support multi part verifying");

	return false;
}

bool OSSLSLHDSA::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("SLHDSA does not support multi part verifying");

	return false;
}

// Encryption functions
bool OSSLSLHDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("SLHDSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLSLHDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("SLHDSA does not support decryption");

	return false;
}

// Key factory
bool OSSLSLHDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(SLHParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for SLHDSA key generation");

		return false;
	}

	SLHParameters* params = (SLHParameters*) parameters;

	const unsigned char* name = params->getName().const_byte_str();

	// Generate the key-pair
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, reinterpret_cast<const char*>(name), NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL SLHDSA context");
		return false;
	}
	int ret = EVP_PKEY_keygen_init(ctx);
	if (ret != 1)
	{
		ERROR_MSG("SLHDSA key generation init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	ret = EVP_PKEY_keygen(ctx, &pkey);
	if (ret != 1)
	{
		ERROR_MSG("SLHDSA key generation failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// Create an asymmetric key-pair object to return
	OSSLSLHKeyPair* kp = new OSSLSLHKeyPair();

	((OSSLSLHPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);
	((OSSLSLHPrivateKey*) kp->getPrivateKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;

	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

bool OSSLSLHDSA::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Get keys
	EVP_PKEY *pub = ((OSSLSLHPublicKey *)publicKey)->getOSSLKey();
	EVP_PKEY *priv = ((OSSLSLHPrivateKey *)privateKey)->getOSSLKey();
	if (pub == NULL || priv == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL ECDH keys");

		return false;
	}

	// Get and set context
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
	if (ctx == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL ECDH context");

		return false;
	}
	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		ERROR_MSG("Failed to init OpenSSL key derive");

		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0)
	{
		ERROR_MSG("Failed to set OpenSSL ECDH public key");

		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Derive the secret
	size_t len;
	if (EVP_PKEY_derive(ctx, NULL, &len) <= 0)
	{
		ERROR_MSG("Failed to get OpenSSL ECDH key length");

		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	ByteString secret;
	secret.resize(len);
	if (EVP_PKEY_derive(ctx, &secret[0], &len) <= 0)
	{
		ERROR_MSG("Failed to derive OpenSSL ECDH secret");

		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	EVP_PKEY_CTX_free(ctx);

	// Create derived key
	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
		return false;
	if (!(*ppSymmetricKey)->setKeyBits(secret))
	{
		delete *ppSymmetricKey;
		*ppSymmetricKey = NULL;
		return false;
	}

	return true;
}

unsigned long OSSLSLHDSA::getMinKeySize()
{
	return 7856;
}

unsigned long OSSLSLHDSA::getMaxKeySize()
{
	return 49856;
}

bool OSSLSLHDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLSLHKeyPair* kp = new OSSLSLHKeyPair();

	bool rv = true;

	if (!((SLHPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((SLHPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool OSSLSLHDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLSLHPublicKey* pub = new OSSLSLHPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLSLHDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLSLHPrivateKey* priv = new OSSLSLHPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLSLHDSA::newPublicKey()
{
	return (PublicKey*) new OSSLSLHPublicKey();
}

PrivateKey* OSSLSLHDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLSLHPrivateKey();
}

AsymmetricParameters* OSSLSLHDSA::newParameters()
{
	return (AsymmetricParameters*) new SLHParameters();
}

bool OSSLSLHDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SLHParameters* params = new SLHParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
