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
#include <climits>

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
/** Return whether the supplied non-null type name identifies SLH-DSA parameters. */
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

/** Decode an eight-byte parameter identifier, rejecting overflow and unsupported sets. */
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

	if (parameter > ULONG_MAX ||
	    !isSupported(static_cast<unsigned long>(parameter)))
	{
		return false;
	}

	setParameterSet(parameter);

	return true;
}

// Check if the parameter set is supported
/** Return whether the identifier names one of the twelve PKCS#11 SLH-DSA parameter sets. */
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
/** Return the SLH-DSA signature length in bytes, or zero for an unsupported set. */
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


// Raw key lengths from FIPS 205: public keys contain 2n bytes, private keys 4n.
/** Return the raw public-key length (2n bytes), or zero for an unsupported set. */
unsigned long SLHDSAParameters::publicKeyLength(unsigned long parameterSet)
{
	switch (parameterSet)
	{
		case CKP_SLH_DSA_SHA2_128S:
		case CKP_SLH_DSA_SHAKE_128S:
		case CKP_SLH_DSA_SHA2_128F:
		case CKP_SLH_DSA_SHAKE_128F:
			return 32;
		case CKP_SLH_DSA_SHA2_192S:
		case CKP_SLH_DSA_SHAKE_192S:
		case CKP_SLH_DSA_SHA2_192F:
		case CKP_SLH_DSA_SHAKE_192F:
			return 48;
		case CKP_SLH_DSA_SHA2_256S:
		case CKP_SLH_DSA_SHAKE_256S:
		case CKP_SLH_DSA_SHA2_256F:
		case CKP_SLH_DSA_SHAKE_256F:
			return 64;
		default:
			return 0;
	}
}

/** Return the raw private-key length (4n bytes), or zero for an unsupported set. */
unsigned long SLHDSAParameters::privateKeyLength(unsigned long parameterSet)
{
	return 2 * publicKeyLength(parameterSet);
}
