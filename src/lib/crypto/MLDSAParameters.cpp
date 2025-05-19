/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 ECParameters.cpp

 Elliptic Curve parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLDSAParameters.h"
#include <string.h>

// The type
/*static*/ const char* MLDSAParameters::type = "ML-DSA parameters";

// Set the curve OID ec
void MLDSAParameters::setParameterSet(const unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the curve OID ec
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
	ByteString parameterSet = ByteString::chainDeserialise(serialised);

	if (parameterSet.size() == 0)
	{
		return false;
	}

	setParameterSet(parameterSet.long_val());

	return true;
}

