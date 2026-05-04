/*****************************************************************************
 OSSLSLHDSA.cpp

 OpenSSL SLH-DSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLH_DSA
#include "log.h"
#include "OSSLSLHDSA.h"
#include "CryptoFactory.h"
#include "SLHDSAParameters.h"
#include "SLHDSAMechanismParam.h"
#include "OSSLSLHDSAKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>


// Signing functions
/** \brief sign */
bool OSSLSLHDSA::sign(PrivateKey *privateKey, const ByteString &dataToSign,
					 ByteString &signature, const AsymMech::Type mechanism,
					 const void * /* param  = NULL*/, const size_t  /* paramLen = 0 */,
					 const MechanismParam* mechanismParam)
{
	if (mechanism != AsymMech::SLHDSA)
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
	if (!privateKey->isOfType(OSSLSLHDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLSLHDSAPrivateKey *pk = (OSSLSLHDSAPrivateKey *)privateKey;

	EVP_PKEY *pkey = pk->getOSSLKey();

	if (pkey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}

	if (mechanismParam != NULL && !mechanismParam->isOfType(SLHDSAMechanismParam::type))
	{
		ERROR_MSG("Invalid mechanism parameter type supplied");

		return false;
	}

	// Perform the signature operation
	size_t len = 0;

	OSSL_PARAM params[4], *p = params;
	
	int local_deterministic = 1;
	int local_random = 0;
	const SLHDSAMechanismParam* slhdsaSignatureParam = dynamic_cast<const SLHDSAMechanismParam*>(mechanismParam);
	ByteString context;
	if (slhdsaSignatureParam != NULL) {
		Hedge::Type type = slhdsaSignatureParam->hedgeType;
		if (slhdsaSignatureParam->additionalContext.size() > 0) {
			context = slhdsaSignatureParam->additionalContext;
			size_t contextSize = context.size();
			if (contextSize > 255) {
				ERROR_MSG("Invalid parameters, context length > 255");
				return false;
			}
			*p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context.byte_str(), contextSize);
		}
		switch (type) {
			case Hedge::Type::DETERMINISTIC_REQUIRED:
				*p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &local_deterministic);
				break;
			case Hedge::Type::HEDGE_REQUIRED:
			default:
				*p++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &local_random);
				break;
		}
		*p = OSSL_PARAM_construct_end();
	}
	
	EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (sctx == NULL)
    {
        ERROR_MSG("SLH-DSA sign sctx alloc failed");
        return false;
    }

	unsigned long parameterSet = pk->getParameterSet();
	const char* name = OSSL::slhdsaParameterSet2Name(parameterSet);
	if (name == NULL) 
	{
        ERROR_MSG("Unknown SLH-DSA parameter set (%lu)", parameterSet);
        EVP_PKEY_CTX_free(sctx);
        return false;
    }

	EVP_SIGNATURE *sig_alg = EVP_SIGNATURE_fetch(NULL, name, NULL);
	if (sig_alg == NULL) {
		ERROR_MSG("SLH-DSA EVP_SIGNATURE_fetch failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(sctx);
		return false;
	}
	int initRv;
	if (mechanismParam != NULL) {
		initRv = EVP_PKEY_sign_message_init(sctx, sig_alg, params);
	} 
	else 
	{
		initRv = EVP_PKEY_sign_message_init(sctx, sig_alg, NULL);
	}
	if (initRv <= 0) {
		ERROR_MSG("SLH-DSA sign_message_init failed (0x%08lX)", ERR_get_error());
		EVP_SIGNATURE_free(sig_alg);
		EVP_PKEY_CTX_free(sctx);
		return false;
	}
    /* Calculate the required size for the signature by passing a NULL buffer. */
    if (EVP_PKEY_sign(sctx, NULL, &len, dataToSign.const_byte_str(), dataToSign.size()) <= 0) {
		ERROR_MSG("SLH-DSA sign size query failed (0x%08lX)", ERR_get_error());
		EVP_SIGNATURE_free(sig_alg);
		EVP_PKEY_CTX_free(sctx);
		return false;
	}
	signature.resize(len);
    if (EVP_PKEY_sign(sctx, &signature[0], &len, dataToSign.const_byte_str(), dataToSign.size()) <= 0) {
		ERROR_MSG("SLH-DSA sign failed (0x%08lX)", ERR_get_error());
		EVP_SIGNATURE_free(sig_alg);
		EVP_PKEY_CTX_free(sctx);
		return false;
	}
	
	EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_CTX_free(sctx);

	return true;
}

/** \brief signInit */
bool OSSLSLHDSA::signInit(PrivateKey * /*privateKey*/, const AsymMech::Type /*mechanism*/,
						 const void * /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("SLH-DSA does not support multi part signing");

	return false;
}

/** \brief signUpdate */
bool OSSLSLHDSA::signUpdate(const ByteString & /*dataToSign*/)
{
	ERROR_MSG("SLH-DSA does not support multi part signing");

	return false;
}

/** \brief signFinal */
bool OSSLSLHDSA::signFinal(ByteString & /*signature*/)
{
	ERROR_MSG("SLH-DSA does not support multi part signing");

	return false;
}

// Verification functions
/** \brief verify */
bool OSSLSLHDSA::verify(PublicKey *publicKey, const ByteString &originalData,
					   const ByteString &signature, const AsymMech::Type mechanism,
					   const void * /* param  = NULL*/, const size_t  /* paramLen = 0 */,
					   const MechanismParam* mechanismParam)
{
	if (mechanism != AsymMech::SLHDSA)
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
	if (!publicKey->isOfType(OSSLSLHDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLSLHDSAPublicKey *pk = (OSSLSLHDSAPublicKey *)publicKey;
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

	if (mechanismParam != NULL && !mechanismParam->isOfType(SLHDSAMechanismParam::type))
	{
		ERROR_MSG("Invalid mechanism parameter type supplied");

		return false;
	}

	OSSL_PARAM params[3], *p = params;
	const SLHDSAMechanismParam* slhdsaSignatureParam = dynamic_cast<const SLHDSAMechanismParam*>(mechanismParam);
	ByteString context;
	if (slhdsaSignatureParam != NULL) {
		if (slhdsaSignatureParam->additionalContext.size() > 0) {
			context = slhdsaSignatureParam->additionalContext;
			size_t contextSize = context.size();
			if (contextSize > 255) {
				ERROR_MSG("Invalid parameters, context length > 255");
				return false;
			}
			*p++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context.byte_str(), contextSize);
		}
		*p = OSSL_PARAM_construct_end();
	}

	EVP_PKEY_CTX *vctx = NULL;
	EVP_SIGNATURE *sig_alg = NULL;

	vctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	if (vctx == NULL) {
		ERROR_MSG("SLH-DSA EVP_PKEY_CTX_new_from_pkey failed (0x%08lX)", ERR_get_error());
		return false;
	}

	unsigned long parameterSet = pk->getParameterSet();
	const char* name = OSSL::slhdsaParameterSet2Name(parameterSet);
	
	if (name == NULL) 
	{
        ERROR_MSG("Unknown SLH-DSA parameter set (%lu)", parameterSet);
        EVP_PKEY_CTX_free(vctx);
        return false;
    }

	sig_alg = EVP_SIGNATURE_fetch(NULL, name, NULL);
	if (sig_alg == NULL) {
		ERROR_MSG("SLH-DSA EVP_SIGNATURE_fetch failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(vctx);
		return false;
	}

	int initRv;
	if (mechanismParam != NULL) {
		initRv = EVP_PKEY_verify_message_init(vctx, sig_alg, params);
	} 
	else 
	{
		initRv = EVP_PKEY_verify_message_init(vctx, sig_alg, NULL);
	}

	if (initRv <= 0) {
		ERROR_MSG("SLH-DSA verify init failed (0x%08lX)", ERR_get_error());
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
            ERROR_MSG("SLH-DSA verify error (0x%08lX)", ERR_get_error());
        }
        return false;
	}
	return true;
}

/** \brief verifyInit */
bool OSSLSLHDSA::verifyInit(PublicKey * /*publicKey*/, const AsymMech::Type /*mechanism*/,
						   const void * /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("SLH-DSA does not support multi part verifying");

	return false;
}

/** \brief verifyUpdate */
bool OSSLSLHDSA::verifyUpdate(const ByteString & /*originalData*/)
{
	ERROR_MSG("SLH-DSA does not support multi part verifying");

	return false;
}

/** \brief verifyFinal */
bool OSSLSLHDSA::verifyFinal(const ByteString & /*signature*/)
{
	ERROR_MSG("SLH-DSA does not support multi part verifying");

	return false;
}

// Encryption functions
/** \brief encrypt */
bool OSSLSLHDSA::encrypt(PublicKey * /*publicKey*/, const ByteString & /*data*/,
						ByteString & /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("SLH-DSA does not support encryption");

	return false;
}

// Decryption functions
/** \brief decrypt */
bool OSSLSLHDSA::decrypt(PrivateKey * /*privateKey*/, const ByteString & /*encryptedData*/,
						ByteString & /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("SLH-DSA does not support decryption");

	return false;
}

/** \brief getMinKeySize */
unsigned long OSSLSLHDSA::getMinKeySize()
{
	return SLHDSAParameters::SLH_DSA_SHA2_128S_PUB_LENGTH;
}

/** \brief getMaxKeySize */
unsigned long OSSLSLHDSA::getMaxKeySize()
{
	return SLHDSAParameters::SLH_DSA_SHA2_256F_PUB_LENGTH;
}

/** \brief checkEncryptedDataSize */
bool OSSLSLHDSA::checkEncryptedDataSize(PrivateKey * /* privateKey*/, const ByteString & /*encryptedData*/, int * /* errorCode*/)
{
	ERROR_MSG("SLH-DSA does not support encryption");

	return false;
}

// Key factory
/** \brief generateKeyPair */
bool OSSLSLHDSA::generateKeyPair(AsymmetricKeyPair **ppKeyPair, AsymmetricParameters *parameters, RNG * /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
		(parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(SLHDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for SLH-DSA key generation");

		return false;
	}

	SLHDSAParameters *params = (SLHDSAParameters *)parameters;
	unsigned long parameterSet = params->getParameterSet();
	const char* name = OSSL::slhdsaParameterSet2Name(parameterSet);

	if (name == NULL) 
	{
        ERROR_MSG("Unknown SLH-DSA parameter set (%lu)", parameterSet);
        return false;
    }

	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL) {
		ERROR_MSG("SLH-DSA keygen context failed (0x%08lX)", ERR_get_error());
		return false;
	}
	int initRV = EVP_PKEY_keygen_init(ctx);
	if (initRV <= 0) {
		ERROR_MSG("SLH-DSA keygen init failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	int keygenRV = EVP_PKEY_generate(ctx, &pkey);
	if (keygenRV <= 0) {
		ERROR_MSG("SLH-DSA keygen failed (0x%08lX)", ERR_get_error());
		EVP_PKEY_CTX_free(ctx);
		return false;
	}
	// Create an asymmetric key-pair object to return
	OSSLSLHDSAKeyPair *kp = new OSSLSLHDSAKeyPair();

	((OSSLSLHDSAPrivateKey*)kp->getPrivateKey())->setFromOSSL(pkey);
	((OSSLSLHDSAPublicKey*) kp->getPublicKey())->setFromOSSL(pkey);

	*ppKeyPair = kp;
	
	// Release the context
	EVP_PKEY_CTX_free(ctx);
	// Release the key
	EVP_PKEY_free(pkey);

	return true;
}

/** \brief reconstructKeyPair */
bool OSSLSLHDSA::reconstructKeyPair(AsymmetricKeyPair **ppKeyPair, ByteString &serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLSLHDSAKeyPair *kp = new OSSLSLHDSAKeyPair();

	bool rv = true;

	if (!((SLHDSAPublicKey *)kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((SLHDSAPrivateKey *)kp->getPrivateKey())->deserialise(dPriv))
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

/** \brief reconstructPublicKey */
bool OSSLSLHDSA::reconstructPublicKey(PublicKey **ppPublicKey, ByteString &serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	OSSLSLHDSAPublicKey *pub = new OSSLSLHDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

/** \brief reconstructPrivateKey */
bool OSSLSLHDSA::reconstructPrivateKey(PrivateKey **ppPrivateKey, ByteString &serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
		(serialisedData.size() == 0))
	{
		return false;
	}

	OSSLSLHDSAPrivateKey *priv = new OSSLSLHDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

/** \brief newPublicKey */
PublicKey *OSSLSLHDSA::newPublicKey()
{
	return (PublicKey *)new OSSLSLHDSAPublicKey();
}

/** \brief newPrivateKey */
PrivateKey *OSSLSLHDSA::newPrivateKey()
{
	return (PrivateKey *)new OSSLSLHDSAPrivateKey();
}

/** \brief newParameters */
AsymmetricParameters *OSSLSLHDSA::newParameters()
{
	return (AsymmetricParameters *)new SLHDSAParameters();
}

/** \brief reconstructParameters */
bool OSSLSLHDSA::reconstructParameters(AsymmetricParameters **ppParams, ByteString &serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SLHDSAParameters *params = new SLHDSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}
#endif
