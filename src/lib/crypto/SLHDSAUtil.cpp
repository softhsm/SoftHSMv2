/*****************************************************************************
 SLHDSAUtil.cpp

 SLH-DSA convenience functions
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAUtil.h"
#include "SLHDSAMechanismParam.h"

/*static*/ CK_RV SLHDSAUtil::getSLHDSAPrivateKey(SLHDSAPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// SLH-DSA Private Key Attributes
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

	if (key->attributeExists(CKA_PARAMETER_SET))
	{
		unsigned long parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, 0);
		privateKey->setParameterSet(parameterSet);
	}
	privateKey->setValue(value);

	return CKR_OK;
}

/*static*/ CK_RV SLHDSAUtil::getSLHDSAPublicKey(SLHDSAPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// SLH-DSA Public Key Attributes
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

	if (key->attributeExists(CKA_PARAMETER_SET))
	{
		unsigned long parameterSet = key->getUnsignedLongValue(CKA_PARAMETER_SET, 0);
		publicKey->setParameterSet(parameterSet);
	}
	publicKey->setValue(value);

	return CKR_OK;
}

/*static*/ CK_RV SLHDSAUtil::setSLHDSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate)
{
	if (key == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	AsymmetricAlgorithm* slhdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);
	if (slhdsa == NULL)
	{
		return CKR_GENERAL_ERROR;
	}
	PrivateKey* priv = slhdsa->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
		return CKR_HOST_MEMORY;
	}
	if (!priv->PKCS8Decode(ber))
	{
		slhdsa->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	// SLH-DSA Private Key Attributes
	ByteString value;
	if (isPrivate)
	{
		if (token == NULL)
		{
			slhdsa->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
			return CKR_ARGUMENTS_BAD;
		}
		if (!token->encrypt(((SLHDSAPrivateKey*)priv)->getValue(), value))
		{
			slhdsa->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
			return CKR_GENERAL_ERROR;
		}
	}
	else
	{
		value = ((SLHDSAPrivateKey*)priv)->getValue();
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_PARAMETER_SET, ((SLHDSAPrivateKey*)priv)->getParameterSet());
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	slhdsa->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);

	return bOK ? CKR_OK : CKR_GENERAL_ERROR;
}

/*static*/ CK_RV SLHDSAUtil::setHedge(CK_HEDGE_TYPE inHedgeType, Hedge::Type* outHedgeType)
{

	if (outHedgeType == NULL) {
		ERROR_MSG("Invalid parameters, outHedgeType is NULL");
		return CKR_ARGUMENTS_BAD;
	}

	Hedge::Type hedgeType = Hedge::HEDGE_PREFERRED;

	switch (inHedgeType) {
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
			ERROR_MSG("SLH-DSA: Invalid parameters, unknown hedgeVariant");
			return CKR_ARGUMENTS_BAD;
	}
	*outHedgeType = hedgeType;
	return CKR_OK;
}

#endif