/*****************************************************************************
 SLHDSAParameters.cpp

 SLH-DSA parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SLHDSAParameters.h"
#include <string.h>

// The type
/*static*/ const char* SLHDSAParameters::type = "SLH-DSA parameters";

// Set the parameter set
void SLHDSAParameters::setParameterSet(const unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the parameter set
unsigned long SLHDSAParameters::getParameterSet() const
{
	return parameterSet;
}

// Are the parameters of the given type?
bool SLHDSAParameters::areOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

// Serialisation
ByteString SLHDSAParameters::serialise() const
{
	return ByteString(getParameterSet());
}

bool SLHDSAParameters::deserialise(ByteString& serialised)
{
	if (serialised.size() != 8)
	{
		return false;
	}

	unsigned long parameter = serialised.long_val();
	if (parameter != SLH_DSA_SHA2_128S_PARAMETER_SET &&
	    parameter != SLH_DSA_SHAKE_128S_PARAMETER_SET &&
	    parameter != SLH_DSA_SHA2_128F_PARAMETER_SET &&
	    parameter != SLH_DSA_SHAKE_128F_PARAMETER_SET &&
	    parameter != SLH_DSA_SHA2_192S_PARAMETER_SET &&
	    parameter != SLH_DSA_SHAKE_192S_PARAMETER_SET &&
	    parameter != SLH_DSA_SHA2_192F_PARAMETER_SET &&
	    parameter != SLH_DSA_SHAKE_192F_PARAMETER_SET &&
	    parameter != SLH_DSA_SHA2_256S_PARAMETER_SET &&
	    parameter != SLH_DSA_SHAKE_256S_PARAMETER_SET &&
	    parameter != SLH_DSA_SHA2_256F_PARAMETER_SET &&
	    parameter != SLH_DSA_SHAKE_256F_PARAMETER_SET) 
	{
		return false;
	}

	setParameterSet(parameter);

	return true;
}

