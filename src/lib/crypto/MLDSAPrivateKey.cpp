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

// Get the bit length
unsigned long MLDSAPrivateKey::getParameterSet() const
{
	return parameterSet;
}

void MLDSAPrivateKey::setParameterSet(unsigned long inParameterSet)
{
	parameterSet = inParameterSet;
}

// Get the signatureLength length
unsigned long MLDSAPrivateKey::getOutputLength() const
{
	switch(parameterSet) {
		case MLDSAParameters::ML_DSA_44_PARAMETER_SET:
			return MLDSAParameters::ML_DSA_44_SIGNATURE_LENGTH;
		case MLDSAParameters::ML_DSA_65_PARAMETER_SET:
			return MLDSAParameters::ML_DSA_65_SIGNATURE_LENGTH;
		case MLDSAParameters::ML_DSA_87_PARAMETER_SET:
			return MLDSAParameters::ML_DSA_87_SIGNATURE_LENGTH;
	}
	return 0UL;
}

// Setters for the EC private key components
void MLDSAPrivateKey::setRho(const ByteString& inRho)
{
	rho = inRho;
}

void MLDSAPrivateKey::setK(const ByteString& inK)
{
	k = inK;
}

void MLDSAPrivateKey::setTr(const ByteString& inTr)
{
	tr = inTr;
}

void MLDSAPrivateKey::setS1(const ByteString& inS1)
{
	s1 = inS1;
}

void MLDSAPrivateKey::setS2(const ByteString& inS2)
{
	s2 = inS2;
}

void MLDSAPrivateKey::setT0(const ByteString& inT0)
{
	t0 = inT0;
}

void MLDSAPrivateKey::setT1(const ByteString& inT1)
{
	t1 = inT1;
}

void MLDSAPrivateKey::setSeed(const ByteString& inSeed)
{
	seed = inSeed;
}

// Setters for the EC private key components
const ByteString& MLDSAPrivateKey::getRho() const
{
	return rho;
}

const ByteString& MLDSAPrivateKey::getK() const
{
	return k;
}

const ByteString& MLDSAPrivateKey::getTr() const
{
	return tr;
}

const ByteString& MLDSAPrivateKey::getS1() const
{
	return s1;
}

const ByteString& MLDSAPrivateKey::getS2() const
{
	return s2;
}

const ByteString& MLDSAPrivateKey::getT0() const
{
	return t0;
}

const ByteString& MLDSAPrivateKey::getT1() const
{
	return t1;
}

const ByteString& MLDSAPrivateKey::getSeed() const
{
	return seed;
}

// Serialisation
ByteString MLDSAPrivateKey::serialise() const
{
	return rho.serialise() +
	       k.serialise() +
	       tr.serialise() +
	       s1.serialise() +
	       s2.serialise() +
	       t0.serialise() +
	       t1.serialise() +
	       seed.serialise();
}

bool MLDSAPrivateKey::deserialise(ByteString& serialised)
{
	ByteString rho = ByteString::chainDeserialise(serialised);
	ByteString k = ByteString::chainDeserialise(serialised);
	ByteString tr = ByteString::chainDeserialise(serialised);
	ByteString s1 = ByteString::chainDeserialise(serialised);
	ByteString s2 = ByteString::chainDeserialise(serialised);
	ByteString t0 = ByteString::chainDeserialise(serialised);
	ByteString t1 = ByteString::chainDeserialise(serialised);
	ByteString seed = ByteString::chainDeserialise(serialised);

	if ((rho.size() == 0) ||
	    (k.size() == 0) ||
	    (tr.size() == 0) ||
	    (s1.size() == 0) ||
	    (s2.size() == 0) ||
	    (t0.size() == 0) ||
	    (t1.size() == 0) ||
	    (seed.size() == 0)
	)
	{
		return false;
	}

	setRho(rho);
	setK(k);
	setTr(tr);
	setS1(s1);
	setS2(s2);
	setT0(t0);
	setT1(t1);
	setSeed(seed);

	return true;
}

