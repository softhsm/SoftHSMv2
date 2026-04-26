/*****************************************************************************
 SLHDSAPublicKey.cpp

 SLH-DSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SLHDSAParameters.h"
#include "SLHDSAPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* SLHDSAPublicKey::type = "Abstract SLH-DSA public key";

// Constructor
SLHDSAPublicKey::SLHDSAPublicKey()
{
	parameterSet = 0;
}

// Check if the key is of the given type
bool SLHDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long SLHDSAPublicKey::getBitLength() const
{
	return getValue().bits();
}

// Get the parameter set length
unsigned long SLHDSAPublicKey::getParameterSet() const
{
	return parameterSet;
}

// Get the signature length
unsigned long SLHDSAPublicKey::getOutputLength() const
{
	switch(parameterSet) {
		case SLHDSAParameters::SLH_DSA_SHA2_128S_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHA2_128S_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHAKE_128S_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHAKE_128S_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHA2_128F_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHA2_128F_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHAKE_128F_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHAKE_128F_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHA2_192S_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHA2_192S_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHAKE_192S_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHAKE_192S_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHA2_192F_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHA2_192F_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHAKE_192F_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHAKE_192F_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHA2_256S_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHA2_256S_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHAKE_256S_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHAKE_256S_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHA2_256F_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHA2_256F_SIGNATURE_LENGTH;
		case SLHDSAParameters::SLH_DSA_SHAKE_256F_PARAMETER_SET:
			return SLHDSAParameters::SLH_DSA_SHAKE_256F_SIGNATURE_LENGTH;
	}
	return 0UL;
}

const ByteString& SLHDSAPublicKey::getValue() const
{
	return value;
}

void SLHDSAPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

ByteString SLHDSAPublicKey::serialise() const
{
	return value.serialise() + ByteString((const unsigned char*)&parameterSet, sizeof(unsigned long)).serialise();
}

bool SLHDSAPublicKey::deserialise(ByteString& serialised)
{
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);
	ByteString deserializedParam = ByteString::chainDeserialise(serialised);

	if ((deserializedValue.size() == 0) || (deserializedParam.size() == 0))
	{
		return false;
	}

	unsigned long paramSet = 0;
	if (deserializedParam.size() == sizeof(unsigned long)) {
		memcpy(&paramSet, deserializedParam.const_byte_str(), sizeof(unsigned long));
	}

	setValue(deserializedValue);
	setParameterSet(paramSet);

	return true;
}

void SLHDSAPublicKey::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}
