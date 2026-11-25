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
#include <climits>

// Set the type
/*static*/ const char* SLHDSAPublicKey::type = "Abstract SLH-DSA public key";

// Constructor
/** \brief SLHDSAPublicKey */
SLHDSAPublicKey::SLHDSAPublicKey()
{
	parameterSet = 0;
}

// Check if the key is of the given type
/** Recognize the SLH-DSA public-key type or a supported base-class type. */
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
	// The parameter set is stored big-endian
	return value.serialise() + ByteString(parameterSet).serialise();
}

/** Decode a public key only if its parameter identifier and raw-key length are valid. */
bool SLHDSAPublicKey::deserialise(ByteString& serialised)
{
	ByteString deserializedValue = ByteString::chainDeserialise(serialised);
	ByteString deserializedParam = ByteString::chainDeserialise(serialised);

	if (deserializedValue.size() == 0 || deserializedParam.size() != 8)
	{
		return false;
	}

	uint64_t paramSet64 = 0;
	for (size_t i = 0; i < 8; i++)
	{
		paramSet64 = (paramSet64 << 8) + deserializedParam.const_byte_str()[i];
	}
	if (paramSet64 > ULONG_MAX) return false;
	unsigned long paramSet = static_cast<unsigned long>(paramSet64);

	if (!SLHDSAParameters::isSupported(paramSet) ||
	    deserializedValue.size() != SLHDSAParameters::publicKeyLength(paramSet))
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
