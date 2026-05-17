/*****************************************************************************
 MLKEMPublicKey.cpp

 ML-KEM public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLKEMParameters.h"
#include "MLKEMPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* MLKEMPublicKey::type = "Abstract ML-KEM public key";

// Check if the key is of the given type
bool MLKEMPublicKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}

unsigned long MLKEMPublicKey::getBitLength() const
{
	return getValue().bits();
}

// Get the ML-KEM parameter set
unsigned long MLKEMPublicKey::getParameterSet() const
{
	switch(value.size()) {
		case MLKEMParameters::ML_KEM_512_PUB_LENGTH:
			return MLKEMParameters::ML_KEM_512_PARAMETER_SET;
		case MLKEMParameters::ML_KEM_768_PUB_LENGTH:
			return MLKEMParameters::ML_KEM_768_PARAMETER_SET;
		case MLKEMParameters::ML_KEM_1024_PUB_LENGTH:
			return MLKEMParameters::ML_KEM_1024_PARAMETER_SET;
	}
	return 0UL;
}

// Get the ciphertext length
unsigned long MLKEMPublicKey::getOutputLength() const
{
	switch(value.size()) {
		case MLKEMParameters::ML_KEM_512_PUB_LENGTH:
			return MLKEMParameters::ML_KEM_512_CIPHERTEXT_LENGTH;
		case MLKEMParameters::ML_KEM_768_PUB_LENGTH:
			return MLKEMParameters::ML_KEM_768_CIPHERTEXT_LENGTH;
		case MLKEMParameters::ML_KEM_1024_PUB_LENGTH:
			return MLKEMParameters::ML_KEM_1024_CIPHERTEXT_LENGTH;
	}
	return 0UL;
}

const ByteString& MLKEMPublicKey::getValue() const
{
	return value;
}

void MLKEMPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

// Serialisation
ByteString MLKEMPublicKey::serialise() const
{
	return value.serialise();
}

bool MLKEMPublicKey::deserialise(ByteString& serialised)
{
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);

	const size_t valueLen = deserializedValue.size();
	if (valueLen != MLKEMParameters::ML_KEM_512_PUB_LENGTH &&
	    valueLen != MLKEMParameters::ML_KEM_768_PUB_LENGTH &&
	    valueLen != MLKEMParameters::ML_KEM_1024_PUB_LENGTH)
	{
		return false;
	}

	setValue(deserializedValue);

	return true;
}

