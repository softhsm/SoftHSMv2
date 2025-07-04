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
 OSSLMLKEM.cpp

 OpenSSL ML-KEM asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "log.h"
#include "OSSLMLKEM.h"
#include "CryptoFactory.h"
#include "MLKEMParameters.h"
#include "OSSLMLKEMKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

// Signing functions
bool OSSLMLKEM::sign(PrivateKey * /* privateKey */, const ByteString & /*dataToSign*/,
					 ByteString & /*signature*/ , const AsymMech::Type /*mechanism*/,
					 const void * /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ML-KEM does not support signing");

	return false;
}

bool OSSLMLKEM::signInit(PrivateKey * /*privateKey*/, const AsymMech::Type /*mechanism*/,
						 const void * /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ML-KEM does not support multi part signing");

	return false;
}

bool OSSLMLKEM::signUpdate(const ByteString & /*dataToSign*/)
{
	ERROR_MSG("ML-KEM does not support multi part signing");

	return false;
}

bool OSSLMLKEM::signFinal(ByteString & /*signature*/)
{
	ERROR_MSG("ML-KEM does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLMLKEM::verify(PublicKey * /*publicKey*/, const ByteString & /*originalData*/,
					   const ByteString & /*signature*/, const AsymMech::Type /*mechanism*/,
					   const void * /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ML-KEM does not support verifying");

	return false;
}

bool OSSLMLKEM::verifyInit(PublicKey * /*publicKey*/, const AsymMech::Type /*mechanism*/,
						   const void * /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ML-KEM does not support multi part verifying");

	return false;
}

bool OSSLMLKEM::verifyUpdate(const ByteString & /*originalData*/)
{
	ERROR_MSG("ML-KEM does not support multi part verifying");

	return false;
}

bool OSSLMLKEM::verifyFinal(const ByteString & /*signature*/)
{
	ERROR_MSG("ML-KEM does not support multi part verifying");

	return false;
}

// Encryption functions
bool OSSLMLKEM::encrypt(PublicKey * /*publicKey*/, const ByteString & /*data*/,
						ByteString & /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ML-KEM does not support encryption");

	return false;
}

// Decryption functions
bool OSSLMLKEM::decrypt(PrivateKey * /*privateKey*/, const ByteString & /*encryptedData*/,
						ByteString & /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ML-KEM does not support decryption");

	return false;
}

unsigned long OSSLMLKEM::getMinKeySize()
{
	return MLKEMParameters::ML_KEM_512_PRIV_LENGTH;
}

unsigned long OSSLMLKEM::getMaxKeySize()
{
	return MLKEMParameters::ML_KEM_1024_PRIV_LENGTH;
}

bool OSSLMLKEM::checkEncryptedDataSize(PrivateKey */*privateKey*/, const ByteString &/*encryptedData*/, int */*errorCode*/)
{
	ERROR_MSG("ML-KEM does not support encryption");

	return false;
}

// Key factory
bool OSSLMLKEM::generateKeyPair(AsymmetricKeyPair **ppKeyPair, AsymmetricParameters *parameters, RNG * /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
		(parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(MLKEMParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-KEM key generation");

		return false;
	}

	MLKEMParameters *params = (MLKEMParameters *)parameters;
	unsigned long parameterSet = params->getParameterSet();
	const char* name = OSSL::mlkemParameterSet2Name(parameterSet);

	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL) {
		ERROR_MSG("ML-KEM keygen context failed (0x%08X)", ERR_get_error());
		return false;
	}
	int initRV = EVP_PKEY_keygen_init(ctx);
	if (!initRV) {
		ERROR_MSG("ML-KEM keygen init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	int keygenRV = EVP_PKEY_generate(ctx, &pkey);
	if (!keygenRV) {
		ERROR_MSG("ML-KEM keygen failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	// Create an asymmetric key-pair object to return
	OSSLMLKEMKeyPair *kp = new OSSLMLKEMKeyPair();

	((OSSLMLKEMPrivateKey *)kp->getPrivateKey())->setFromOSSL(pkey);
	((OSSLMLKEMPublicKey *)kp->getPublicKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;
	
	// Release the context
	EVP_PKEY_CTX_free(ctx);
	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

bool OSSLMLKEM::reconstructKeyPair(AsymmetricKeyPair **ppKeyPair, ByteString &serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLMLKEMKeyPair *kp = new OSSLMLKEMKeyPair();

	bool rv = true;

	if (!((MLKEMPublicKey *)kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((MLKEMPrivateKey *)kp->getPrivateKey())->deserialise(dPriv))
	{
		ERROR_MSG("ML-KEM deserialise dPriv failed");
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

bool OSSLMLKEM::encapsulate(PublicKey* publicKey, ByteString& cipherText, SymmetricKey** secretKey, CK_KEY_TYPE keyType, const AsymMech::Type /*mechanism*/) 
{
	EVP_PKEY_CTX *vctx = NULL;
    size_t cipherTextLen;
	size_t secretKeyLen;

	OSSLMLKEMPublicKey *pk = (OSSLMLKEMPublicKey *)publicKey;
	EVP_PKEY *pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}


	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (vctx == NULL) {
		ERROR_MSG("ML-KEM EVP_PKEY_CTX_new_from_pkey failed (0x%08X)", ERR_get_error());
		return false;
	}

	if (EVP_PKEY_encapsulate_init(vctx, NULL) <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_encapsulate_init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		return false;
	}
	
	if (EVP_PKEY_encapsulate(vctx, NULL, &cipherTextLen, NULL,
                                          &secretKeyLen) <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_encapsulate size determination failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		return false;
	}

	if (cipherTextLen <= 0 || secretKeyLen <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_encapsulate size not positive");
		EVP_PKEY_CTX_free(vctx);
		return false;
	}

	ByteString secretKeyValue;

	cipherText.resize(cipherTextLen);
	memset(&cipherText[0], 0, cipherTextLen);

	secretKeyValue.resize(secretKeyLen);
	memset(&secretKeyValue[0], 0, secretKeyLen);

	/* Determine buffer length */
	if (EVP_PKEY_encapsulate(vctx, &cipherText[0], &cipherTextLen, &secretKeyValue[0],
                                          &secretKeyLen) <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_encapsulate failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		return false;
	}
	
	if (keyType == CKK_AES) {
		*secretKey = new AESKey(secretKeyLen * 8);
	} else {
		*secretKey = new SymmetricKey(secretKeyLen * 8);
	}

	if (!(*secretKey)->setKeyBits(secretKeyValue))
	{
		delete secretKey;
		secretKey = NULL;
		return false;
	}

	return true;
}
	
bool OSSLMLKEM::decapsulate(PrivateKey* privateKey, const ByteString& cipherText, SymmetricKey** secretKey, CK_KEY_TYPE keyType, const AsymMech::Type /*mechanism*/) 
{
	EVP_PKEY_CTX *vctx = NULL;
	size_t secretKeyLen;

	OSSLMLKEMPrivateKey *pk = (OSSLMLKEMPrivateKey *)privateKey;
	EVP_PKEY *pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}


	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (vctx == NULL) {
		ERROR_MSG("ML-KEM EVP_PKEY_CTX_new_from_pkey failed (0x%08X)", ERR_get_error());
		return false;
	}

	if (EVP_PKEY_decapsulate_init(vctx, NULL) <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_decapsulate_init failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		return false;
	}
	
	if (EVP_PKEY_decapsulate(vctx, NULL, &secretKeyLen, cipherText.const_byte_str(),
                                          cipherText.size()) <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_decapsulate size determination failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		return false;
	}

	if (secretKeyLen <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_decapsulate size not positive");
		EVP_PKEY_CTX_free(vctx);
		return false;
	}

	ByteString secretKeyValue;
	secretKeyValue.resize(secretKeyLen);
	memset(&secretKeyValue[0], 0, secretKeyLen);

	/* Determine buffer length */
	if (EVP_PKEY_decapsulate(vctx, &secretKeyValue[0], &secretKeyLen, cipherText.const_byte_str(),
                                          cipherText.size()) <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_decapsulate failed (0x%08X)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		return false;
	}

	if (secretKeyValue.size() <= 0) {
		ERROR_MSG("ML-KEM EVP_PKEY_decapsulate size not positive");
		EVP_PKEY_CTX_free(vctx);
		return false;
	}

	if (keyType == CKK_AES) {
		*secretKey = new AESKey(secretKeyLen * 8);
	} else {
		*secretKey = new SymmetricKey(secretKeyLen * 8);
	}

	if (!(*secretKey)->setKeyBits(secretKeyValue))
	{
		delete secretKey;
		secretKey = NULL;
		return false;
	}

	return true;
}

bool OSSLMLKEM::reconstructPublicKey(PublicKey **ppPublicKey, ByteString &serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	OSSLMLKEMPublicKey *pub = new OSSLMLKEMPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLMLKEM::reconstructPrivateKey(PrivateKey **ppPrivateKey, ByteString &serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	OSSLMLKEMPrivateKey *priv = new OSSLMLKEMPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey *OSSLMLKEM::newPublicKey()
{
	return (PublicKey *)new OSSLMLKEMPublicKey();
}

PrivateKey *OSSLMLKEM::newPrivateKey()
{
	return (PrivateKey *)new OSSLMLKEMPrivateKey();
}

AsymmetricParameters *OSSLMLKEM::newParameters()
{
	return (AsymmetricParameters *)new MLKEMParameters();
}

bool OSSLMLKEM::reconstructParameters(AsymmetricParameters **ppParams, ByteString &serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	MLKEMParameters *params = new MLKEMParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
