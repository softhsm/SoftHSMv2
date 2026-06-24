/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SLHDSAPublicKey.cpp

 SLH-DSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SLHDSAParameters.h"
#include "SLHDSAPublicKey.h"
#include <string.h>
#include <cstdint>

// Set the type
/*static*/ const char* SLHDSAPublicKey::type = "Abstract SLH-DSA public key";

// Constructor
/** \brief SLHDSAPublicKey */
SLHDSAPublicKey::SLHDSAPublicKey()
{
	parameterSet = 0;
}

// Check if the key is of the given type
/** \brief isOfType */
bool SLHDSAPublicKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}

/** \brief getBitLength */
unsigned long SLHDSAPublicKey::getBitLength() const
{
	return getValue().bits();
}

// Get the parameter set length
/** \brief getParameterSet */
unsigned long SLHDSAPublicKey::getParameterSet() const
{
	return parameterSet;
}

// Get the signature length
/** \brief getOutputLength */
unsigned long SLHDSAPublicKey::getOutputLength() const
{
	return SLHDSAParameters::signatureLength(parameterSet);
}

/** \brief getValue */
const ByteString& SLHDSAPublicKey::getValue() const
{
	return value;
}

/** \brief setValue */
void SLHDSAPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

/** \brief serialise */
ByteString SLHDSAPublicKey::serialise() const
{
	uint64_t paramVal = (uint64_t)parameterSet;
	return value.serialise() + ByteString((const unsigned char*)&paramVal, sizeof(uint64_t)).serialise();
}

/** \brief deserialise */
bool SLHDSAPublicKey::deserialise(ByteString& serialised)
{
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);
	ByteString deserializedParam = ByteString::chainDeserialise(serialised);

	if (deserializedValue.size() == 0 || deserializedParam.size() != sizeof(uint64_t))
	{
		return false;
	}

	uint64_t paramSet64 = 0;
	memcpy(&paramSet64, deserializedParam.const_byte_str(), sizeof(uint64_t));
	unsigned long paramSet = (unsigned long)paramSet64;

	if (!SLHDSAParameters::isSupported(paramSet))
	{
		return false;
	}

	setValue(deserializedValue);
	setParameterSet(paramSet);

	return true;
}

/** \brief setParameterSet */
void SLHDSAPublicKey::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}
