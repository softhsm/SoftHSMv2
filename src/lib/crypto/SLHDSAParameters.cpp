/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SLHDSAParameters.cpp

 SLH-DSA parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SLHDSAParameters.h"
#include <string.h>
#include <cstdint>

// The type
/*static*/ const char* SLHDSAParameters::type = "SLH-DSA parameters";

// Constructor
/** \brief SLHDSAParameters */
SLHDSAParameters::SLHDSAParameters()
{
	parameterSet = 0;
}

// Set the parameter set
/** \brief setParameterSet */
void SLHDSAParameters::setParameterSet(const unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the parameter set
/** \brief getParameterSet */
unsigned long SLHDSAParameters::getParameterSet() const
{
	return parameterSet;
}

// Are the parameters of the given type?
/** \brief areOfType */
bool SLHDSAParameters::areOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return (strcmp(type, inType) == 0);
}

// Serialisation
/** \brief serialise */
ByteString SLHDSAParameters::serialise() const
{
	return ByteString(getParameterSet());
}

/** \brief deserialise */
bool SLHDSAParameters::deserialise(ByteString& serialised)
{
	if (serialised.size() != 8)
	{
		return false;
	}

	uint64_t parameter = 0;
	for (size_t i = 0; i < 8; i++)
	{
		parameter = (parameter << 8) + serialised.const_byte_str()[i];
	}

	if (!isSupported(parameter))
	{
		return false;
	}

	setParameterSet(parameter);

	return true;
}

// Check if the parameter set is supported
/*static*/ bool SLHDSAParameters::isSupported(const unsigned long parameterSet)
{
	return (parameterSet == SLH_DSA_SHA2_128S_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHAKE_128S_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHA2_128F_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHAKE_128F_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHA2_192S_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHAKE_192S_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHA2_192F_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHAKE_192F_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHA2_256S_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHAKE_256S_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHA2_256F_PARAMETER_SET ||
		parameterSet == SLH_DSA_SHAKE_256F_PARAMETER_SET);
}

// Get the signature length for a parameter set
/*static*/ unsigned long SLHDSAParameters::signatureLength(const unsigned long parameterSet)
{
	switch (parameterSet)
	{
		case SLH_DSA_SHA2_128S_PARAMETER_SET:
			return SLH_DSA_SHA2_128S_SIGNATURE_LENGTH;
		case SLH_DSA_SHAKE_128S_PARAMETER_SET:
			return SLH_DSA_SHAKE_128S_SIGNATURE_LENGTH;
		case SLH_DSA_SHA2_128F_PARAMETER_SET:
			return SLH_DSA_SHA2_128F_SIGNATURE_LENGTH;
		case SLH_DSA_SHAKE_128F_PARAMETER_SET:
			return SLH_DSA_SHAKE_128F_SIGNATURE_LENGTH;
		case SLH_DSA_SHA2_192S_PARAMETER_SET:
			return SLH_DSA_SHA2_192S_SIGNATURE_LENGTH;
		case SLH_DSA_SHAKE_192S_PARAMETER_SET:
			return SLH_DSA_SHAKE_192S_SIGNATURE_LENGTH;
		case SLH_DSA_SHA2_192F_PARAMETER_SET:
			return SLH_DSA_SHA2_192F_SIGNATURE_LENGTH;
		case SLH_DSA_SHAKE_192F_PARAMETER_SET:
			return SLH_DSA_SHAKE_192F_SIGNATURE_LENGTH;
		case SLH_DSA_SHA2_256S_PARAMETER_SET:
			return SLH_DSA_SHA2_256S_SIGNATURE_LENGTH;
		case SLH_DSA_SHAKE_256S_PARAMETER_SET:
			return SLH_DSA_SHAKE_256S_SIGNATURE_LENGTH;
		case SLH_DSA_SHA2_256F_PARAMETER_SET:
			return SLH_DSA_SHA2_256F_SIGNATURE_LENGTH;
		case SLH_DSA_SHAKE_256F_PARAMETER_SET:
			return SLH_DSA_SHAKE_256F_SIGNATURE_LENGTH;
		default:
			return 0UL;
	}
}


