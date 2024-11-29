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
 DESKey.cpp

 DES key class
 *****************************************************************************/

#include "config.h"
#include "ByteString.h"
#include "Serialisable.h"
#include "DESKey.h"
#include "CryptoFactory.h"

// Set the key
bool DESKey::setKeyBits(const ByteString& keybits)
{
	if (bitLen > 0)
	{
		// Check if the correct input data is supplied
		size_t expectedLen = 0;

		switch(bitLen)
		{
			case 56:
				expectedLen = 8;
				break;
			case 112:
				expectedLen = 16;
				break;
			case 168:
				expectedLen = 24;
				break;
		};

		// Check the length
		if (keybits.size() != expectedLen)
		{
			return false;
		}
	}

	keyData = keybits;

	return true;
}

// Get key check value
ByteString DESKey::getKeyCheckValue() const
{
	SymAlgo::Type algo = SymAlgo::Unknown;
	ByteString iv;
	ByteString data;
	ByteString encryptedData;
	ByteString encryptedFinal;


	switch (this->getBitLen())
	{
		case 56:
			algo = SymAlgo::DES;
			break;
		case 112:
		case 168:
			algo = SymAlgo::DES3;
			break;
		default:
			return encryptedData;
	}

	SymmetricAlgorithm* cipher = CryptoFactory::i()->getSymmetricAlgorithm(algo);
	if (cipher == NULL) return encryptedData;

	// Single block of null (0x00) bytes
	data.resize(cipher->getBlockSize());
	memset(&data[0], 0, data.size());

	// Single block of null (0x00) bytes
	iv.resize(cipher->getBlockSize());
	memset(&iv[0], 0, iv.size());

	if (!cipher->encryptInit(this, SymMode::CBC, iv, false) ||
	    !cipher->encryptUpdate(data, encryptedData) ||
	    !cipher->encryptFinal(encryptedFinal))
	{
		CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);
		return encryptedData;
	}
	CryptoFactory::i()->recycleSymmetricAlgorithm(cipher);

	encryptedData += encryptedFinal;
	encryptedData.resize(3);

	return encryptedData;
}
