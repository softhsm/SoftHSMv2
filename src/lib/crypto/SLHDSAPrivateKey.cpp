/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SLHDSAPrivateKey.cpp

 SLH-DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SLHDSAParameters.h"
#include "SLHDSAPrivateKey.h"
#include <string.h>
#include <cstdint>

// Set the type
/*static*/ const char* SLHDSAPrivateKey::type = "Abstract SLH-DSA private key";

// Constructor
/** \brief SLHDSAPrivateKey */
SLHDSAPrivateKey::SLHDSAPrivateKey()
{
	parameterSet = 0;
}

// Check if the key is of the given type
/** \brief isOfType */
bool SLHDSAPrivateKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}

/** \brief getBitLength */
unsigned long SLHDSAPrivateKey::getBitLength() const
{
	return getValue().bits();
}

// Get the parameter set
/** \brief getParameterSet */
unsigned long SLHDSAPrivateKey::getParameterSet() const
{
	return parameterSet;
}

// Get the signatureLength length
/** \brief getOutputLength */
unsigned long SLHDSAPrivateKey::getOutputLength() const
{
	return SLHDSAParameters::signatureLength(parameterSet);
}

/** \brief setValue */
void SLHDSAPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

/** \brief getValue */
const ByteString& SLHDSAPrivateKey::getValue() const
{
	return value;
}

/** \brief serialise */
ByteString SLHDSAPrivateKey::serialise() const
{
	uint64_t paramVal = (uint64_t)parameterSet;
	return value.serialise() + ByteString((const unsigned char*)&paramVal, sizeof(uint64_t)).serialise();
}

/** \brief deserialise */
bool SLHDSAPrivateKey::deserialise(ByteString& serialised)
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
void SLHDSAPrivateKey::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}
