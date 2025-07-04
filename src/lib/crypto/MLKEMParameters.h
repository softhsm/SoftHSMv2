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
 MLKEMParameters.h

 ML-KEM parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMPARAMETERS_H
#define _SOFTHSM_V2_MLKEMPARAMETERS_H

#include <tuple>
#include <stdexcept>
#include "config.h"
#include "ByteString.h"
#include "AsymmetricParameters.h"


class MLKEMParameters : public AsymmetricParameters
{
public:
	// The type
	static const char* type;

	// Get the ML-KEM parameter set
	virtual unsigned long getParameterSet() const;

	// Setters for the ML-DSA parameter set
	virtual void setParameterSet(const unsigned long parameterSet);

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	static const unsigned long ML_KEM_512_PARAMETER_SET = CKP_ML_KEM_512;
	static const unsigned long ML_KEM_768_PARAMETER_SET = CKP_ML_KEM_768;
	static const unsigned long ML_KEM_1024_PARAMETER_SET = CKP_ML_KEM_1024;

	/*
	From https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
	Table 2. Sizes (in bytes) of keys and signatures of ML-DSA
						encapsulation key | decapsulation key | ciphertext | shared secret key
			ML-KEM-512       800          |       1632        |    768     |        32
			ML-KEM-768       1184         |       2400        |    1088    |        32
			ML-KEM-1024      1568         |       3168        |    1568    |        32
	*/
	
	static const unsigned long ML_KEM_512_PRIV_LENGTH = 1632;
	static const unsigned long ML_KEM_768_PRIV_LENGTH = 2400;
	static const unsigned long ML_KEM_1024_PRIV_LENGTH = 3168;

	static const unsigned long ML_KEM_512_PUB_LENGTH = 800;
	static const unsigned long ML_KEM_768_PUB_LENGTH = 1184;
	static const unsigned long ML_KEM_1024_PUB_LENGTH = 1568;

	static const unsigned long ML_KEM_512_CIPHERTEXT_LENGTH = 768;
	static const unsigned long ML_KEM_768_CIPHERTEXT_LENGTH = 1088;
	static const unsigned long ML_KEM_1024_CIPHERTEXT_LENGTH = 1568;

private:
	unsigned long parameterSet;

};

#endif // !_SOFTHSM_V2_MLKEMPARAMETERS_H

