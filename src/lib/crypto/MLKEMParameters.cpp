/*****************************************************************************
 MLKEMParameters.cpp

 ML-KEM parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLKEMParameters.h"
#include <string.h>

// The type
/*static*/ const char* MLKEMParameters::type = "ML-KEM parameters";

// Set the parameter set
void MLKEMParameters::setParameterSet(const unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the parameter set
unsigned long MLKEMParameters::getParameterSet() const
{
	return parameterSet;
}

// Are the parameters of the given type?
bool MLKEMParameters::areOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return (strcmp(type, inType) == 0);
}

// Serialisation
ByteString MLKEMParameters::serialise() const
{
	return ByteString(getParameterSet());
}

bool MLKEMParameters::deserialise(ByteString& serialised)
{

	if (serialised.size() != 8)
	{
		return false;
	}

	unsigned long parameter = serialised.long_val();
	if (parameter != ML_KEM_512_PARAMETER_SET &&
		parameter != ML_KEM_768_PARAMETER_SET &&
		parameter != ML_KEM_1024_PARAMETER_SET)
	{
		return false;
	}

	setParameterSet(parameter);

	return true;
}

