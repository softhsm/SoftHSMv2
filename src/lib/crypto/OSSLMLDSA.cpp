/*****************************************************************************
 OSSLMLDSA.cpp

 OpenSSL ML-DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "log.h"
#include "OSSLMLDSA.h"
#include "CryptoFactory.h"
#include "MLDSAParameters.h"
#include "OSSLMLDSAKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

int OSSLMLDSA::OSSL_RANDOM = 0;
int OSSLMLDSA::OSSL_DETERMINISTIC = 1;

// Signing functions
bool OSSLMLDSA::sign(PrivateKey *privateKey, const ByteString &dataToSign,
					 ByteString &signature, const AsymMech::Type mechanism,
					 const void * param /* = NULL*/, const size_t paramLen /* = 0 */)
{
	if (mechanism != AsymMech::MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	if (privateKey == NULL)
    {
        ERROR_MSG("No private key supplied");
        return false;
    }

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLMLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLMLDSAPrivateKey *pk = (OSSLMLDSAPrivateKey *)privateKey;

	EVP_PKEY *pkey = pk->getOSSLKey();

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

	if (param != NULL && paramLen != sizeof(SIGN_ADDITIONAL_CONTEXT))
	{
		ERROR_MSG("Invalid parameters supplied");

		return false;
	}

	OSSL_PARAM params[4], *p = params;
	SIGN_ADDITIONAL_CONTEXT* additionalContext = (SIGN_ADDITIONAL_CONTEXT*) param;
	if (additionalContext != NULL) {
		Hedge::Type type = additionalContext->hedgeType;
		size_t contextSize = additionalContext->contextData.size();
		if (contextSize > 0) {
			if (contextSize > 255) {
				ERROR_MSG("Invalid parameters, context length > 255");
				return false;
			}
			const unsigned char* contextAsChars = additionalContext->contextData.data();
			*p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (unsigned char*)contextAsChars, contextSize);
		}
		switch (type) {
			case Hedge::Type::DETERMINISTIC_REQUIRED:
				*p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &OSSL_DETERMINISTIC);
				break;
			default:
				*p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &OSSL_RANDOM);
				break;
		}
		*p = OSSL_PARAM_construct_end();
	}
	
	EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (sctx == NULL)
    {
        ERROR_MSG("ML-DSA sign sctx alloc failed");
        return false;
    }

	unsigned long parameterSet = pk->getParameterSet();
	const char* name = OSSL::mldsaParameterSet2Name(parameterSet);
	if (name == NULL) 
	{
        ERROR_MSG("Unknown ML-DSA parameter set (%lu)", parameterSet);
        EVP_PKEY_CTX_free(sctx);
        return false;
    }

	EVP_SIGNATURE *sig_alg = EVP_SIGNATURE_fetch(NULL, name, NULL);
	if (sig_alg == NULL) {
		ERROR_MSG("ML-DSA EVP_SIGNATURE_fetch failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(sctx);
		return false;
	}
	int initRv;
	if (param != NULL) {
		initRv = EVP_PKEY_sign_message_init(sctx, sig_alg, params);
	} 
	else 
	{
		initRv = EVP_PKEY_sign_message_init(sctx, sig_alg, NULL);
	}
	if (!initRv) {
		ERROR_MSG("ML-DSA sign_message_init failed (0x%08lX)", ERR_get_error());
		EVP_SIGNATURE_free(sig_alg);
		EVP_PKEY_CTX_free(sctx);
		return false;
	}
    /* Calculate the required size for the signature by passing a NULL buffer. */
    if (EVP_PKEY_sign(sctx, NULL, &len, dataToSign.const_byte_str(), dataToSign.size()) <= 0) {
		ERROR_MSG("ML-DSA sign size query failed (0x%08lX)", ERR_get_error());
		EVP_SIGNATURE_free(sig_alg);
		EVP_PKEY_CTX_free(sctx);
		return false;
	}
	signature.resize(len);
    if (EVP_PKEY_sign(sctx, &signature[0], &len, dataToSign.const_byte_str(), dataToSign.size()) <= 0) {
		ERROR_MSG("ML-DSA sign failed (0x%08lX)", ERR_get_error());
		EVP_SIGNATURE_free(sig_alg);
		EVP_PKEY_CTX_free(sctx);
		return false;
	}
	
	EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_CTX_free(sctx);

	return true;
}

bool OSSLMLDSA::signInit(PrivateKey * /*privateKey*/, const AsymMech::Type /*mechanism*/,
						 const void * /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ML-DSA does not support multi part signing");

	return false;
}

bool OSSLMLDSA::signUpdate(const ByteString & /*dataToSign*/)
{
	ERROR_MSG("ML-DSA does not support multi part signing");

	return false;
}

bool OSSLMLDSA::signFinal(ByteString & /*signature*/)
{
	ERROR_MSG("ML-DSA does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLMLDSA::verify(PublicKey *publicKey, const ByteString &originalData,
					   const ByteString &signature, const AsymMech::Type mechanism,
					   const void * param /* = NULL */, const size_t paramLen /* = 0 */)
{
	if (mechanism != AsymMech::MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	if (publicKey == NULL)
    {
        ERROR_MSG("No public key supplied");
        return false;
    }

	// Check if the public key is the right type
	if (!publicKey->isOfType(OSSLMLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLMLDSAPublicKey *pk = (OSSLMLDSAPublicKey *)publicKey;
	EVP_PKEY *pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}

	// Perform the verify operation
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

	if (param != NULL && paramLen != sizeof(SIGN_ADDITIONAL_CONTEXT))
	{
		ERROR_MSG("Invalid parameters supplied");

		return false;
	}

	OSSL_PARAM params[4], *p = params;
	SIGN_ADDITIONAL_CONTEXT* additionalContext = (SIGN_ADDITIONAL_CONTEXT*) param;
	if (additionalContext != NULL) {
		Hedge::Type type = additionalContext->hedgeType;
		size_t contextSize = additionalContext->contextData.size();
		if (contextSize > 0) {
			if (contextSize > 255) {
				ERROR_MSG("Invalid parameters, context length > 255");
				return false;
			}
			const unsigned char* contextAsChars = additionalContext->contextData.data();
			*p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (unsigned char*)contextAsChars, contextSize);
		}
		switch (type) {
			case Hedge::Type::DETERMINISTIC_REQUIRED:
				*p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &OSSL_DETERMINISTIC);
				break;
			default:
				*p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &OSSL_RANDOM);
				break;
		}
		*p = OSSL_PARAM_construct_end();
	}

	EVP_PKEY_CTX *vctx = NULL;
	EVP_SIGNATURE *sig_alg = NULL;

	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (vctx == NULL) {
		ERROR_MSG("ML-DSA EVP_PKEY_CTX_new_from_pkey failed (0x%08lX)", ERR_get_error());
		return false;
	}

	unsigned long parameterSet = pk->getParameterSet();
	const char* name = OSSL::mldsaParameterSet2Name(parameterSet);
	
	if (name == NULL) 
	{
        ERROR_MSG("Unknown ML-DSA parameter set (%lu)", parameterSet);
        EVP_PKEY_CTX_free(vctx);
        return false;
    }

	sig_alg = EVP_SIGNATURE_fetch(NULL, name, NULL);
	if (sig_alg == NULL) {
		ERROR_MSG("ML-DSA EVP_SIGNATURE_fetch failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		return false;
	}

	int initRv;
	if (param != NULL) {
		initRv = EVP_PKEY_verify_message_init(vctx, sig_alg, params);
	} 
	else 
	{
		initRv = EVP_PKEY_verify_message_init(vctx, sig_alg, NULL);
	}

	if (!initRv) {
		ERROR_MSG("ML-DSA verify init failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		EVP_SIGNATURE_free(sig_alg);
		return false;
	}
	int verifyRV = EVP_PKEY_verify(vctx, signature.const_byte_str(), signature.size(),
                                            originalData.const_byte_str(), originalData.size());
	EVP_PKEY_CTX_free(vctx);
	EVP_SIGNATURE_free(sig_alg);
	if (verifyRV != 1) 
	{
        if (verifyRV != 0) 
		{
            ERROR_MSG("ML-DSA verify error (0x%08lX)", ERR_get_error());
        }
        return false;
	}
	return true;
}

bool OSSLMLDSA::verifyInit(PublicKey * /*publicKey*/, const AsymMech::Type /*mechanism*/,
						   const void * /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ML-DSA does not support multi part verifying");

	return false;
}

bool OSSLMLDSA::verifyUpdate(const ByteString & /*originalData*/)
{
	ERROR_MSG("ML-DSA does not support multi part verifying");

	return false;
}

bool OSSLMLDSA::verifyFinal(const ByteString & /*signature*/)
{
	ERROR_MSG("ML-DSA does not support multi part verifying");

	return false;
}

// Encryption functions
bool OSSLMLDSA::encrypt(PublicKey * /*publicKey*/, const ByteString & /*data*/,
						ByteString & /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ML-DSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLMLDSA::decrypt(PrivateKey * /*privateKey*/, const ByteString & /*encryptedData*/,
						ByteString & /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ML-DSA does not support decryption");

	return false;
}

unsigned long OSSLMLDSA::getMinKeySize()
{
	return MLDSAParameters::ML_DSA_44_PRIV_LENGTH;
}

unsigned long OSSLMLDSA::getMaxKeySize()
{
	return MLDSAParameters::ML_DSA_87_PRIV_LENGTH;
}

bool OSSLMLDSA::checkEncryptedDataSize(PrivateKey * /* privateKey*/, const ByteString & /*encryptedData*/, int * /* errorCode*/)
{
	ERROR_MSG("ML-DSA does not support encryption");

	return false;
}

// Key factory
bool OSSLMLDSA::generateKeyPair(AsymmetricKeyPair **ppKeyPair, AsymmetricParameters *parameters, RNG * /*rng = NULL */)
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

	MLDSAParameters *params = (MLDSAParameters *)parameters;
	unsigned long parameterSet = params->getParameterSet();
	const char* name = OSSL::mldsaParameterSet2Name(parameterSet);

	if (name == NULL) 
	{
        ERROR_MSG("Unknown ML-DSA parameter set (%lu)", parameterSet);
        return false;
    }

	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL) {
		ERROR_MSG("ML-DSA keygen context failed (0x%08lX)", ERR_get_error());
		return false;
	}
	int initRV = EVP_PKEY_keygen_init(ctx);
	if (initRV <= 0) {
		ERROR_MSG("ML-DSA keygen init failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	int keygenRV = EVP_PKEY_generate(ctx, &pkey);
	if (keygenRV <= 0) {
		ERROR_MSG("ML-DSA keygen failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	// Create an asymmetric key-pair object to return
	OSSLMLDSAKeyPair *kp = new OSSLMLDSAKeyPair();

	((OSSLMLDSAPrivateKey*)kp->getPrivateKey())->setFromOSSL(pkey);
	((OSSLMLDSAPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;
	
	// Release the context
	EVP_PKEY_CTX_free(ctx);
	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

bool OSSLMLDSA::reconstructKeyPair(AsymmetricKeyPair **ppKeyPair, ByteString &serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLMLDSAKeyPair *kp = new OSSLMLDSAKeyPair();

	bool rv = true;

	if (!((MLDSAPublicKey *)kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((MLDSAPrivateKey *)kp->getPrivateKey())->deserialise(dPriv))
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

bool OSSLMLDSA::reconstructPublicKey(PublicKey **ppPublicKey, ByteString &serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	OSSLMLDSAPublicKey *pub = new OSSLMLDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLMLDSA::reconstructPrivateKey(PrivateKey **ppPrivateKey, ByteString &serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	OSSLMLDSAPrivateKey *priv = new OSSLMLDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey *OSSLMLDSA::newPublicKey()
{
	return (PublicKey *)new OSSLMLDSAPublicKey();
}

PrivateKey *OSSLMLDSA::newPrivateKey()
{
	return (PrivateKey *)new OSSLMLDSAPrivateKey();
}

AsymmetricParameters *OSSLMLDSA::newParameters()
{
	return (AsymmetricParameters *)new MLDSAParameters();
}

bool OSSLMLDSA::reconstructParameters(AsymmetricParameters **ppParams, ByteString &serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	MLDSAParameters *params = new MLDSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
