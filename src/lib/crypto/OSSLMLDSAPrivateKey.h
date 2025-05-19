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
 OSSLMLDSAPrivateKey.h

 OpenSSL ML-DSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLDSAPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLMLDSAPRIVATEKEY_H

#include "config.h"
#include "MLDSAParameters.h"
#include "MLDSAPrivateKey.h"
#include <openssl/bn.h>
#include <openssl/evp.h>

class OSSLMLDSAPrivateKey : public MLDSAPrivateKey
{
public:
	// Constructors
	OSSLMLDSAPrivateKey();

	OSSLMLDSAPrivateKey(const EVP_PKEY* inMLDSAKEY);

	// Destructor
	virtual ~OSSLMLDSAPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Setters for the ML-DSA private key components
	virtual void setRho(const ByteString& rho);
	virtual void setK(const ByteString& k);
	virtual void setTr(const ByteString& tr);
	virtual void setS1(const ByteString& s1);
	virtual void setS2(const ByteString& s2);
	virtual void setT0(const ByteString& t0);
	virtual void setT1(const ByteString& t1);
	virtual void setSeed(const ByteString& seed);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

	// Set from OpenSSL representation
	virtual void setFromOSSL(const EVP_PKEY* inMLDSAKEY);

	// Retrieve the OpenSSL representation of the key
	EVP_PKEY* getOSSLKey();

private:
	// The internal OpenSSL representation
	unsigned char priv[MLDSAParameters::ML_DSA_87_PRIV_LENGTH];
	EVP_PKEY* mldsaKey;

};

#endif // !_SOFTHSM_V2_OSSLECPRIVATEKEY_H

