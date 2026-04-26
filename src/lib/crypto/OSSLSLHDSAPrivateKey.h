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
 OSSLSLHDSAPrivateKey.h

 OpenSSL SLH-DSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H

#include "config.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAParameters.h"
#include "SLHDSAPrivateKey.h"
#include <openssl/evp.h>

class OSSLSLHDSAPrivateKey : public SLHDSAPrivateKey
{
public:
 /** \brief Constructors */
	OSSLSLHDSAPrivateKey();

 /** \brief Constructor from OpenSSL representation */
	OSSLSLHDSAPrivateKey(const EVP_PKEY* inSLHDSAKEY);

 /** \brief Destructor */
	virtual ~OSSLSLHDSAPrivateKey();

 /** \brief Non-copyable (raw ownership of EVP_PKEY) */
	OSSLSLHDSAPrivateKey(const OSSLSLHDSAPrivateKey&) = delete;  
 /** \brief Non-copyable assignment */
    OSSLSLHDSAPrivateKey& operator=(const OSSLSLHDSAPrivateKey&) = delete;  
  
 /** \brief Movable */
	OSSLSLHDSAPrivateKey(OSSLSLHDSAPrivateKey&&) noexcept;  
 /** \brief Movable assignment */
	OSSLSLHDSAPrivateKey& operator=(OSSLSLHDSAPrivateKey&&) noexcept;  

 /** \brief The type */
	static const char* type;

 /** \brief Check if the key is of the given type */
	virtual bool isOfType(const char* inType);

 /** \brief Setters for the SLH-DSA private key components */
	virtual void setValue(const ByteString& value);
	
 /** \brief Encode into PKCS#8 DER */
	virtual ByteString PKCS8Encode();

 /** \brief Decode from PKCS#8 BER */
	virtual bool PKCS8Decode(const ByteString& ber);

 /** \brief Set from OpenSSL representation */
	virtual bool setFromOSSL(const EVP_PKEY* inSLHDSAKEY);

 /** \brief Retrieve the OpenSSL representation of the key */
	EVP_PKEY* getOSSLKey();

private:
 /** \brief The internal OpenSSL representation */
	EVP_PKEY* pkey;

 /** \brief Create the OpenSSL representation of the key */
	void createOSSLKey();

};

#endif // WITH_SLH_DSA
#endif // !_SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H

