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
 SLHPublicKey.cpp

 SLHDSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SLHPublicKey.h"
#include <string.h>

// Set the type
/*static*/ const char* SLHPublicKey::type = "Abstract SLHDSA public key";

// Check if the key is of the given type
bool SLHPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the bit length
unsigned long SLHPublicKey::getBitLength() const
{
	return getDerPublicKey().size() * 8;
}

// Get the output length
unsigned long SLHPublicKey::getOutputLength() const
{
	return getOrderLength();
}

// Setters for the SLH public key components
void SLHPublicKey::setDerPublicKey(const ByteString& inPk)
{
	derPublicKey = inPk;
}

// Getters for the SLH public key components
const ByteString& SLHPublicKey::getDerPublicKey() const
{
	return derPublicKey;
}

// Serialisation
ByteString SLHPublicKey::serialise() const
{
	return derPublicKey.serialise();
}

bool SLHPublicKey::deserialise(ByteString& serialised)
{
	ByteString dDerPublicKey = ByteString::chainDeserialise(serialised);

	if (dDerPublicKey.size() == 0)
	{
		return false;
	}

	setDerPublicKey(dDerPublicKey);

	return true;
}

