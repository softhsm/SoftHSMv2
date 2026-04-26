/*****************************************************************************
 SLHDSAPrivateKey.cpp

 SLH-DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SLHDSAParameters.h"
#include "SLHDSAPrivateKey.h"
#include <string.h>

// Set the type
/*static*/ const char* SLHDSAPrivateKey::type = "Abstract SLH-DSA private key";

// Constructor
SLHDSAPrivateKey::SLHDSAPrivateKey()
{
	parameterSet = 0;
}

// Check if the key is of the given type
bool SLHDSAPrivateKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		 return false;
	}
	return !strcmp(type, inType);
}

unsigned long SLHDSAPrivateKey::getBitLength() const
{
	return getValue().bits();
}

// Get the parameter set
unsigned long SLHDSAPrivateKey::getParameterSet() const
{
	return parameterSet;
}

// Get the signatureLength length
unsigned long SLHDSAPrivateKey::getOutputLength() const
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

void SLHDSAPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& SLHDSAPrivateKey::getValue() const
{
	return value;
}

ByteString SLHDSAPrivateKey::serialise() const
{
	return value.serialise() + ByteString((const unsigned char*)&parameterSet, sizeof(unsigned long)).serialise();
}

bool SLHDSAPrivateKey::deserialise(ByteString& serialised)
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


void SLHDSAPrivateKey::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}
