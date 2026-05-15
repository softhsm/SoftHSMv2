/*****************************************************************************
 MLKEMPrivateKey.cpp

 ML-KEM private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLKEMParameters.h"
#include "MLKEMPrivateKey.h"
#include <string.h>

// Set the type
/*static*/ const char* MLKEMPrivateKey::type = "Abstract ML-KEM private key";

// Check if the key is of the given type
bool MLKEMPrivateKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		 return false;
	}
	return !strcmp(type, inType);
}

unsigned long MLKEMPrivateKey::getBitLength() const
{
	return getValue().bits();
}

// Get the bit length
unsigned long MLKEMPrivateKey::getParameterSet() const
{
	switch(value.size()) {
		case MLKEMParameters::ML_KEM_512_PRIV_LENGTH:
			return MLKEMParameters::ML_KEM_512_PARAMETER_SET;
		case MLKEMParameters::ML_KEM_768_PRIV_LENGTH:
			return MLKEMParameters::ML_KEM_768_PARAMETER_SET;
		case MLKEMParameters::ML_KEM_1024_PRIV_LENGTH:
			return MLKEMParameters::ML_KEM_1024_PARAMETER_SET;
	}
	return 0UL;
}

// Get the signatureLength length
unsigned long MLKEMPrivateKey::getOutputLength() const
{
	switch(value.size()) {
		case MLKEMParameters::ML_KEM_512_PRIV_LENGTH:
			return MLKEMParameters::ML_KEM_512_CIPHERTEXT_LENGTH;
		case MLKEMParameters::ML_KEM_768_PRIV_LENGTH:
			return MLKEMParameters::ML_KEM_768_CIPHERTEXT_LENGTH;
		case MLKEMParameters::ML_KEM_1024_PRIV_LENGTH:
			return MLKEMParameters::ML_KEM_1024_CIPHERTEXT_LENGTH;
	}
	return 0UL;
}

void MLKEMPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& MLKEMPrivateKey::getValue() const
{
	return value;
}

void MLKEMPrivateKey::setSeed(const ByteString& inSeed)
{
	seed = inSeed;
}

const ByteString& MLKEMPrivateKey::getSeed() const
{
	return seed;
}

// Serialisation
ByteString MLKEMPrivateKey::serialise() const
{
	return seed.serialise() +
	       value.serialise();
}

bool MLKEMPrivateKey::deserialise(ByteString& serialised)
{
	ByteString deserializedSeed = ByteString::chainDeserialise(serialised);
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);

	const size_t valueLen = deserializedValue.size();
	if (deserializedSeed.size() == 0 ||
	    (valueLen != MLKEMParameters::ML_KEM_512_PRIV_LENGTH &&
	     valueLen != MLKEMParameters::ML_KEM_768_PRIV_LENGTH &&
	     valueLen != MLKEMParameters::ML_KEM_1024_PRIV_LENGTH))
	{
		return false;
	}

	setSeed(deserializedSeed);
	setValue(deserializedValue);
	
	return true;
}

