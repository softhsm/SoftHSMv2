/*****************************************************************************
 MLDSAParameters.cpp

 ML-DSA parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLDSAParameters.h"
#include <string.h>

// The type
/*static*/ const char* MLDSAParameters::type = "ML-DSA parameters";

// Set the parameter set
void MLDSAParameters::setParameterSet(const unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the parameter set
unsigned long MLDSAParameters::getParameterSet() const
{
	return parameterSet;
}

// Are the parameters of the given type?
bool MLDSAParameters::areOfType(const char* inType)
{
	return (strcmp(type, inType) == 0);
}

// Serialisation
ByteString MLDSAParameters::serialise() const
{
	return ByteString(getParameterSet());
}

bool MLDSAParameters::deserialise(ByteString& serialised)
{

	if (serialised.size() == 0)
	{
		return false;
	}

	setParameterSet(serialised.long_val());

	return true;
}

