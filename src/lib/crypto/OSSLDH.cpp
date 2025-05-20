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
 OSSLDH.cpp

 OpenSSL Diffie-Hellman asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLDH.h"
#include "CryptoFactory.h"
#include "DHParameters.h"
#include "OSSLComp.h"
#include "OSSLDHKeyPair.h"
#include "OSSLUtil.h"
#include <algorithm>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/dh.h>
#else
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#endif
#include <openssl/pem.h>
#include <openssl/err.h>

// Signing functions
bool OSSLDH::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
		      const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

bool OSSLDH::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

bool OSSLDH::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("DH does not support signing");

	return false;
}

// Verification functions
bool OSSLDH::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

bool OSSLDH::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

bool OSSLDH::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("DH does not support verifying");

	return false;
}

// Encryption functions
bool OSSLDH::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
		     ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DH does not support encryption");

	return false;
}

// Decryption functions
bool OSSLDH::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
		     ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("DH does not support decryption");

	return false;
}

// Key factory
bool OSSLDH::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(DHParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for DH key generation");

		return false;
	}

	DHParameters* params = (DHParameters*) parameters;

	BIGNUM* bn_p = OSSL::byteString2bn(params->getP());
	BIGNUM* bn_g = OSSL::byteString2bn(params->getG());

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	// Generate the key-pair
	DH* dh = DH_new();
	if (dh == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL DH object");
		BN_free(bn_p);
		BN_free(bn_g);

		return false;
	}

	if (!DH_set0_pqg(dh, bn_p, NULL, bn_g))
	{
		ERROR_MSG("DH set pqg failed (0x%08X)", ERR_get_error());

		BN_free(bn_p);
		BN_free(bn_g);
		DH_free(dh);

		return false;
	}

	if (params->getXBitLength() > 0)
	{
		if (!DH_set_length(dh, params->getXBitLength()))
		{
			ERROR_MSG("DH set length failed (0x%08X)", ERR_get_error());

			DH_free(dh);

			return false;
		}
	}

	if (DH_generate_key(dh) != 1)
	{
		ERROR_MSG("DH key generation failed (0x%08X)", ERR_get_error());

		DH_free(dh);

		return false;
	}
#else
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!ctx)
	{
		ERROR_MSG("Failed to create EVP_PKEY_CTX");
		BN_free(bn_p);
		BN_free(bn_g);
		return false;
	}

	OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
	if (!bld)
	{
		ERROR_MSG("Failed to create OSSL_PARAM_BLD");
		BN_free(bn_p);
		BN_free(bn_g);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
		!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g) ||
		(params->getXBitLength() > 0 && !OSSL_PARAM_BLD_push_uint(
			bld, OSSL_PKEY_PARAM_DH_PRIV_LEN, params->getXBitLength())))
	{
		ERROR_MSG("Failed to push DH params to OSSL_PARAM_BLD");
		BN_free(bn_p);
		BN_free(bn_g);
		OSSL_PARAM_BLD_free(bld);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	OSSL_PARAM* params_built = OSSL_PARAM_BLD_to_param(bld);
	if (!params_built)
	{
		ERROR_MSG("Failed to build OSSL_PARAM");
		BN_free(bn_p);
		BN_free(bn_g);
		OSSL_PARAM_BLD_free(bld);
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	EVP_PKEY* dh = NULL, *new_dh = NULL;
	if (EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &dh, EVP_PKEY_KEY_PARAMETERS, params_built) <= 0)
	{
		ERROR_MSG("EVP_PKEY_fromdata failed");
		BN_free(bn_p);
		BN_free(bn_g);
		OSSL_PARAM_free(params_built);
		OSSL_PARAM_BLD_free(bld);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(dh);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);
	ctx = EVP_PKEY_CTX_new(dh, NULL);
	if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &new_dh) <= 0) {
		ERROR_MSG("DH key generation failed");
		BN_free(bn_p);
		BN_free(bn_g);
		OSSL_PARAM_free(params_built);
		OSSL_PARAM_BLD_free(bld);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(dh);
		return false;
	}

	BN_free(bn_p);
	BN_free(bn_g);
	OSSL_PARAM_free(params_built);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(dh);
	dh = new_dh;

#endif

	// Create an asymmetric key-pair object to return
	OSSLDHKeyPair* kp = new OSSLDHKeyPair();

	((OSSLDHPublicKey*) kp->getPublicKey())->setFromOSSL(dh);
	((OSSLDHPrivateKey*) kp->getPrivateKey())->setFromOSSL(dh);

	*ppKeyPair = kp;

	// Release the key
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	DH_free(dh);
#else
	EVP_PKEY_free(dh);
#endif

	return true;
}

bool OSSLDH::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	// Get keys
	DH *pub = ((OSSLDHPublicKey *)publicKey)->getOSSLKey();
	DH *priv = ((OSSLDHPrivateKey *)privateKey)->getOSSLKey();
	if (pub == NULL || priv == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL DH keys");

		return false;
	}
	const BIGNUM* bn_pub_key = NULL;
	DH_get0_key(pub, &bn_pub_key, NULL);
	if (bn_pub_key == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL DH keys");

		return false;
	}

	// Derive the secret
	ByteString secret, derivedSecret;
	int size = DH_size(priv);
	secret.wipe(size);
	derivedSecret.wipe(size);
	int keySize = DH_compute_key(&derivedSecret[0], bn_pub_key, priv);

	if (keySize <= 0)
	{
		ERROR_MSG("DH key derivation failed (0x%08X)", ERR_get_error());

		return false;
	}

	// We compensate that OpenSSL removes leading zeros
	memcpy(&secret[0] + size - keySize, &derivedSecret[0], keySize);
#else
	// Get keys
	EVP_PKEY *pub = ((OSSLDHPublicKey *)publicKey)->getOSSLKey();
	EVP_PKEY *priv = ((OSSLDHPrivateKey *)privateKey)->getOSSLKey();
	if (pub == NULL || priv == NULL)
	{
		ERROR_MSG("Failed to get OpenSSL DH keys");
		return false;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
	if (!ctx)
	{
		ERROR_MSG("Failed to create EVP_PKEY_CTX");
		return false;
	}

	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		ERROR_MSG("EVP_PKEY_derive_init failed");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0)
	{
		ERROR_MSG("EVP_PKEY_derive_set_peer failed");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (EVP_PKEY_CTX_set_dh_pad(ctx, 1) <= 0)
	{
		ERROR_MSG("EVP_PKEY_CTX_set_dh_pad failed");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	// Determine buffer length
	size_t secretLen = 0;
	if (EVP_PKEY_derive(ctx, NULL, &secretLen) <= 0)
	{
		ERROR_MSG("EVP_PKEY_derive size query failed");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	ByteString secret;
	secret.wipe(secretLen);

	if (EVP_PKEY_derive(ctx, &secret[0], &secretLen) <= 0)
	{
		ERROR_MSG("EVP_PKEY_derive failed");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);
#endif

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

unsigned long OSSLDH::getMinKeySize()
{
#ifdef WITH_FIPS
	// OPENSSL_DH_FIPS_MIN_MODULUS_BITS is 1024
	return 1024;
#else
	return 512;
#endif
}

unsigned long OSSLDH::getMaxKeySize()
{
	return OPENSSL_DH_MAX_MODULUS_BITS;
}

bool OSSLDH::generateParameters(AsymmetricParameters** ppParams, void* parameters /* = NULL */, RNG* /*rng = NULL*/)
{
	if ((ppParams == NULL) || (parameters == NULL))
	{
		return false;
	}

	size_t bitLen = (size_t) parameters;

	if (bitLen < getMinKeySize() || bitLen > getMaxKeySize())
	{
		ERROR_MSG("This DH key size is not supported");

		return false;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	DH* dh = DH_new();
	if (dh == NULL)
	{
		ERROR_MSG("Failed to create DH object");

		return false;
	}

	if (!DH_generate_parameters_ex(dh, bitLen, 2, NULL))
	{
		ERROR_MSG("Failed to generate %d bit DH parameters", bitLen);

		DH_free(dh);

		return false;
	}

	const BIGNUM* bn_p = NULL;
	const BIGNUM* bn_g = NULL;
	DH_get0_pqg(dh, &bn_p, NULL, &bn_g);
#else
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
	if (!ctx)
	{
		ERROR_MSG("Failed to create EVP_PKEY_CTX");
		return false;
	}

	if (EVP_PKEY_paramgen_init(ctx) <= 0)
	{
		ERROR_MSG("EVP_PKEY_paramgen_init failed");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, bitLen) <= 0)
	{
		ERROR_MSG("EVP_PKEY_CTX_set_dh_paramgen_prime_len failed");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, 2) <= 0)
	{
		ERROR_MSG("EVP_PKEY_CTX_set_dh_paramgen_generator failed");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	EVP_PKEY* dh_params = NULL;
	if (EVP_PKEY_paramgen(ctx, &dh_params) <= 0)
	{
		ERROR_MSG("Failed to generate DH parameters");
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);

	BIGNUM* bn_p = NULL;
	BIGNUM* bn_g = NULL;

	if (!EVP_PKEY_get_bn_param(dh_params, OSSL_PKEY_PARAM_FFC_P, &bn_p)) {
		ERROR_MSG("Failed to get DH domain parameter p");
		EVP_PKEY_free(dh_params);
		return false;
	}
	if (!EVP_PKEY_get_bn_param(dh_params, OSSL_PKEY_PARAM_FFC_G, &bn_g)) {
		ERROR_MSG("Failed to get DH domain parameter g");
		BN_free(bn_p);
		EVP_PKEY_free(dh_params);
		return false;
	}
#endif

	// Store the DH parameters
	DHParameters* params = new DHParameters();
	ByteString p = OSSL::bn2ByteString(bn_p); params->setP(p);
	ByteString g = OSSL::bn2ByteString(bn_g); params->setG(g);

	*ppParams = params;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	DH_free(dh);
#else
	EVP_PKEY_free(dh_params);
	BN_free(bn_p);
	BN_free(bn_g);
#endif

	return true;
}

bool OSSLDH::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLDHKeyPair* kp = new OSSLDHKeyPair();

	bool rv = true;

	if (!((DHPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((DHPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool OSSLDH::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDHPublicKey* pub = new OSSLDHPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLDH::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLDHPrivateKey* priv = new OSSLDHPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLDH::newPublicKey()
{
	return (PublicKey*) new OSSLDHPublicKey();
}

PrivateKey* OSSLDH::newPrivateKey()
{
	return (PrivateKey*) new OSSLDHPrivateKey();
}

AsymmetricParameters* OSSLDH::newParameters()
{
	return (AsymmetricParameters*) new DHParameters();
}

bool OSSLDH::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	DHParameters* params = new DHParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}

