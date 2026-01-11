/*****************************************************************************
 MLDSAPrivateKey.cpp

 ML-DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLDSAParameters.h"
#include "MLDSAPrivateKey.h"
#include <string.h>

// Set the type
/*static*/ const char* MLDSAPrivateKey::type = "Abstract ML-DSA private key";

// Check if the key is of the given type
bool MLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long MLDSAPrivateKey::getBitLength() const
{
	return getValue().bits();
}

// Get the parameter set
unsigned long MLDSAPrivateKey::getParameterSet() const
{
	switch(value.size()) {
		case MLDSAParameters::ML_DSA_44_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_44_PARAMETER_SET;
		case MLDSAParameters::ML_DSA_65_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_65_PARAMETER_SET;
		case MLDSAParameters::ML_DSA_87_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_87_PARAMETER_SET;
	}
	return 0UL;
}

// Get the signatureLength length
unsigned long MLDSAPrivateKey::getOutputLength() const
{
	switch(value.size()) {
		case MLDSAParameters::ML_DSA_44_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_44_SIGNATURE_LENGTH;
		case MLDSAParameters::ML_DSA_65_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_65_SIGNATURE_LENGTH;
		case MLDSAParameters::ML_DSA_87_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_87_SIGNATURE_LENGTH;
	}
	return 0UL;
}

void MLDSAPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& MLDSAPrivateKey::getValue() const
{
	return value;
}

void MLDSAPrivateKey::setSeed(const ByteString& inSeed)
{
	seed = inSeed;
}

const ByteString& MLDSAPrivateKey::getSeed() const
{
	return seed;
}

// Serialisation
ByteString MLDSAPrivateKey::serialise() const
{
	return seed.serialise() +
	       value.serialise();
}

bool MLDSAPrivateKey::deserialise(ByteString& serialised)
{
	ByteString deserializedSeed = ByteString::chainDeserialise(serialised);
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);

	if ((deserializedSeed.size() == 0) || (deserializedValue.size() == 0))
	{
		return false;
	}

	setSeed(deserializedSeed);
	setValue(deserializedValue);
	
	return true;
}

