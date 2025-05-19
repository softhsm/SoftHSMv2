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
 MLDSAPrivateKey.cpp

 ML-DSA private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "MLDSAParameters.h"
#include "MLDSAPrivateKey.h"
#include <string.h>

// Set the type
/*static*/ const char* MLDSAPrivateKey::type = "Abstract ML-DSA private key";

// Check if the key is of the given type
bool MLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

unsigned long MLDSAPrivateKey::getBitLength() const
{
	return getValue().bits();
}

// Get the bit length
unsigned long MLDSAPrivateKey::getParameterSet() const
{
	switch(value.size()) {
		case MLDSAParameters::ML_DSA_44_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_44_PARAMETER_SET;
		case MLDSAParameters::ML_DSA_65_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_65_PARAMETER_SET;
		case MLDSAParameters::ML_DSA_87_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_87_PARAMETER_SET;
	}
	return 0UL;
}

// Get the signatureLength length
unsigned long MLDSAPrivateKey::getOutputLength() const
{
	switch(value.size()) {
		case MLDSAParameters::ML_DSA_44_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_44_SIGNATURE_LENGTH;
		case MLDSAParameters::ML_DSA_65_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_65_SIGNATURE_LENGTH;
		case MLDSAParameters::ML_DSA_87_PRIV_LENGTH:
			return MLDSAParameters::ML_DSA_87_SIGNATURE_LENGTH;
	}
	return 0UL;
}

void MLDSAPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

const ByteString& MLDSAPrivateKey::getValue() const
{
	return value;
}

void MLDSAPrivateKey::setSeed(const ByteString& inSeed)
{
	seed = inSeed;
}

const ByteString& MLDSAPrivateKey::getSeed() const
{
	return seed;
}

// Serialisation
ByteString MLDSAPrivateKey::serialise() const
{
	return seed.serialise() +
	       value.serialise();
}

bool MLDSAPrivateKey::deserialise(ByteString& serialised)
{
	ByteString seed = ByteString::chainDeserialise(serialised);
	ByteString value = ByteString::chainDeserialise(serialised);

	if ((seed.size() == 0) ||
	    (value.size() == 0))
	{
		return false;
	}

	setSeed(seed);
	setValue(value);
	
	return true;
}

