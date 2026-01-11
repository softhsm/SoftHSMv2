/*****************************************************************************
 MLDSAPublicKey.cpp

 ML-DSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLDSAParameters.h"
#include "MLDSAPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* MLDSAPublicKey::type = "Abstract ML-DSA public key";

// Check if the key is of the given type
bool MLDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long MLDSAPublicKey::getBitLength() const
{
	return getValue().bits();
}

// Get the bit length
unsigned long MLDSAPublicKey::getParameterSet() const
{
	switch(value.size()) {
		case MLDSAParameters::ML_DSA_44_PUB_LENGTH:
			return MLDSAParameters::ML_DSA_44_PARAMETER_SET;
		case MLDSAParameters::ML_DSA_65_PUB_LENGTH:
			return MLDSAParameters::ML_DSA_65_PARAMETER_SET;
		case MLDSAParameters::ML_DSA_87_PUB_LENGTH:
			return MLDSAParameters::ML_DSA_87_PARAMETER_SET;
	}
	return 0UL;
}

// Get the signatureLength length
unsigned long MLDSAPublicKey::getOutputLength() const
{
	switch(value.size()) {
		case MLDSAParameters::ML_DSA_44_PUB_LENGTH:
			return MLDSAParameters::ML_DSA_44_SIGNATURE_LENGTH;
		case MLDSAParameters::ML_DSA_65_PUB_LENGTH:
			return MLDSAParameters::ML_DSA_65_SIGNATURE_LENGTH;
		case MLDSAParameters::ML_DSA_87_PUB_LENGTH:
			return MLDSAParameters::ML_DSA_87_SIGNATURE_LENGTH;
	}
	return 0UL;
}

const ByteString& MLDSAPublicKey::getValue() const
{
	return value;
}

void MLDSAPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

// Serialisation
ByteString MLDSAPublicKey::serialise() const
{
	return value.serialise();
}

bool MLDSAPublicKey::deserialise(ByteString& serialised)
{
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);

	if ((deserializedValue.size() == 0))
	{
		return false;
	}

	setValue(deserializedValue);

	return true;
}

