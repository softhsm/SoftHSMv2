/*****************************************************************************
 MLDSAUtil.cpp

 ML-DSA convenience functions
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "MLDSAUtil.h"

/*static*/ CK_RV MLDSAUtil::getMLDSAPrivateKey(MLDSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-DSA Private Key Attributes
	ByteString value;
	ByteString seed;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_SEED), seed);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
		seed = key->getByteStringValue(CKA_SEED);
	}

	privateKey->setValue(value);
	privateKey->setSeed(seed);

	return CKR_OK;
}

/*static*/ CK_RV MLDSAUtil::getMLDSAPublicKey(MLDSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-DSA Public Key Attributes
	ByteString value;
	if (isKeyPrivate)
	{
		bool bOK = true;
		bOK = bOK && token->decrypt(key->getByteStringValue(CKA_VALUE), value);
		if (!bOK)
			return CKR_GENERAL_ERROR;
	}
	else
	{
		value = key->getByteStringValue(CKA_VALUE);
	}

	publicKey->setValue(value);

	return CKR_OK;
}

/*static*/ bool MLDSAUtil::setMLDSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate)
{
	AsymmetricAlgorithm* mldsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);
	if (mldsa == NULL)
	{
		return false;
	}
	PrivateKey* priv = mldsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		mldsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
		return false;
	}
	// ML-DSA Private Key Attributes
	ByteString seed;
	ByteString value;
	if (isPrivate)
	{
		if (token == NULL)
		{
			mldsa->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
			return false;
		}
		if (!token->encrypt(((MLDSAPrivateKey*)priv)->getSeed(), seed))
		{
			mldsa->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
			return false;
		}
		if (!token->encrypt(((MLDSAPrivateKey*)priv)->getValue(), value))
		{
			mldsa->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
			return false;
		}
	}
	else
	{
		seed = ((MLDSAPrivateKey*)priv)->getSeed();
		value = ((MLDSAPrivateKey*)priv)->getValue();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_PARAMETER_SET, ((MLDSAPrivateKey*)priv)->getParameterSet());
	bOK = bOK && key->setAttribute(CKA_SEED, seed);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	mldsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);

	return bOK;
}

/*static*/ CK_RV MLDSAUtil::copyMLDSAContext(const CK_SIGN_ADDITIONAL_CONTEXT* ckSignAdditionalContext, SIGN_ADDITIONAL_CONTEXT** additionalContext)
{

	if (ckSignAdditionalContext == NULL || additionalContext == NULL) {
		return CKR_ARGUMENTS_BAD;
	}
	// Always initialize context fields
	size_t contextLength = 0;
	unsigned char* contextAsChar = NULL;
	Hedge::Type hedgeType = Hedge::HEDGE_PREFERRED;

	if (ckSignAdditionalContext->ulContextLen > 0)
	{
		if (ckSignAdditionalContext->pContext == NULL)
		{
			ERROR_MSG("ML-DSA: Invalid parameters, pContext is NULL");
			return CKR_ARGUMENTS_BAD;
		}
		if (ckSignAdditionalContext->ulContextLen > 255)
		{
			ERROR_MSG("ML-DSA: Invalid parameters, context length > 255");
			return CKR_ARGUMENTS_BAD;
		}

		// total = struct + optional context bytes
		contextLength = ckSignAdditionalContext->ulContextLen;
		contextAsChar = ckSignAdditionalContext->pContext;
	}
	switch (ckSignAdditionalContext->hedgeVariant) {
		case CKH_HEDGE_REQUIRED:
			hedgeType = Hedge::HEDGE_REQUIRED;
			break;
		case CKH_DETERMINISTIC_REQUIRED:
			hedgeType = Hedge::DETERMINISTIC_REQUIRED;
			break;
		case CKH_HEDGE_PREFERRED:
		// Per PKCS11v3.2 section 6.67.5
		// "If no parameter is supplied the hedgeVariant will be CKH_HEDGE_PREFERRED"
			hedgeType = Hedge::HEDGE_PREFERRED;
			break;
		default:
			ERROR_MSG("ML-DSA: Invalid parameters, unknown hedgeVariant");
			return CKR_ARGUMENTS_BAD;
	}
	try
	{
		*additionalContext = new SIGN_ADDITIONAL_CONTEXT(hedgeType, contextAsChar, contextLength);
		return CKR_OK;
	}
	catch (...)
	{
		return CKR_HOST_MEMORY;
	}
}

#endif