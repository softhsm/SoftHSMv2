/*****************************************************************************
 MLKEMUtil.cpp

 ML-KEM convenience functions
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "MLKEMUtil.h"

/*static*/ CK_RV MLKEMUtil::getMLKEMPrivateKey(MLKEMPrivateKey* privateKey, Token* token, OSObject* key)
{
	if (privateKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-KEM Private Key Attributes
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
	if (privateKey->getParameterSet() == 0UL || seed.size() == 0)
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	return CKR_OK;
}

/*static*/ CK_RV MLKEMUtil::getMLKEMPublicKey(MLKEMPublicKey* publicKey, Token* token, OSObject* key)
{
	if (publicKey == NULL) return CKR_ARGUMENTS_BAD;
	if (token == NULL) return CKR_ARGUMENTS_BAD;
	if (key == NULL) return CKR_ARGUMENTS_BAD;

	// Get the CKA_PRIVATE attribute, when the attribute is not present use default false
	bool isKeyPrivate = key->getBooleanValue(CKA_PRIVATE, false);

	// ML-KEM Public Key Attributes
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
	if (publicKey->getParameterSet() == 0UL)
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	return CKR_OK;
}

/*static*/ bool MLKEMUtil::setMLKEMPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate)
{
	if (key == NULL)
	{
		return false;
	}

	AsymmetricAlgorithm* mlkem = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);
	if (mlkem == NULL)
	{
		return false;
	}
	PrivateKey* priv = mlkem->newPrivateKey();
	if (priv == NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}
	if (!priv->PKCS8Decode(ber))
	{
		mlkem->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}
	// ML-KEM Private Key Attributes
	ByteString seed;
	ByteString value;
	if (isPrivate)
	{
		if (token == NULL)
		{
			mlkem->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
			return false;
		}
		if (!token->encrypt(((MLKEMPrivateKey*)priv)->getSeed(), seed))
		{
			mlkem->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
			return false;
		}
		if (!token->encrypt(((MLKEMPrivateKey*)priv)->getValue(), value))
		{
			mlkem->recyclePrivateKey(priv);
			CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
			return false;
		}
	}
	else
	{
		seed = ((MLKEMPrivateKey*)priv)->getSeed();
		value = ((MLKEMPrivateKey*)priv)->getValue();
	}
	const unsigned long parameterSet = ((MLKEMPrivateKey*)priv)->getParameterSet();
	if (parameterSet == 0UL)
	{
		mlkem->recyclePrivateKey(priv);
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);
		return false;
	}
	bool bOK = true;
	bOK = bOK && key->setAttribute(CKA_PARAMETER_SET, parameterSet);
	bOK = bOK && key->setAttribute(CKA_SEED, seed);
	bOK = bOK && key->setAttribute(CKA_VALUE, value);

	mlkem->recyclePrivateKey(priv);
	CryptoFactory::i()->recycleAsymmetricAlgorithm(mlkem);

	return bOK;
}

#endif