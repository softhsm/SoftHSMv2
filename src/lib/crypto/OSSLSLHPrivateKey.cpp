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
 OSSLSLHPrivateKey.cpp

 OpenSSL SLHDSA private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLHDSA
#include "log.h"
#include "OSSLSLHPrivateKey.h"
#include "OSSLUtil.h"
#include <cstdlib>
#include <cstring>
#include <openssl/x509.h>
#include "OSSLSLHUtil.h"

// Constructors
OSSLSLHPrivateKey::OSSLSLHPrivateKey()
{
	pkey = NULL;
	name = NULL;
}

OSSLSLHPrivateKey::OSSLSLHPrivateKey(const EVP_PKEY* inPKEY)
{
	pkey = NULL;
	name = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLSLHPrivateKey::~OSSLSLHPrivateKey()
{
  if (pkey) {
      EVP_PKEY_free(pkey);
      pkey = NULL;
  }
  name = NULL;
}

// The type
/*static*/ const char* OSSLSLHPrivateKey::type = "OpenSSL SLHDSA Private Key";

unsigned long OSSLSLHPrivateKey::getOrderLength() const
{
	return OSSLSLH::getSignatureSizeFromName(name);
}

// Set from OpenSSL representation
void OSSLSLHPrivateKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
  if (EVP_PKEY_get0_type_name(inPKEY) == NULL)
  {
    ERROR_MSG("Could not determine algorithm name from EVP_PKEY");
    return;
  }
  name = EVP_PKEY_get0_type_name(inPKEY);

  // Serialize to DER (PKCS#8), like function PKCS8Encode
  ByteString der;
  PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(inPKEY);
  if (!p8inf)
  	{ ERROR_MSG("EVP_PKEY2PKCS8 info error"); return; }
  int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
  if (len <= 0)
  {
  	ERROR_MSG("i2d_PKCS8_PRIV_KEY_INFO info error, len is smaller or eq than zero");
  	return;
  }

  der.resize(len);
	unsigned char* p = &der[0];
  if (i2d_PKCS8_PRIV_KEY_INFO(p8inf, &p) != len)
  	{ ERROR_MSG("i2d_PKCS8_PRIV_KEY_INFO serialization error"); return; }

  PKCS8_PRIV_KEY_INFO_free(p8inf);

  setDerPrivateKey(der);
  return;
}

// Check if the key is of the given type
bool OSSLSLHPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLSLHPrivateKey::setDerPrivateKey(const ByteString& inSk)
{
	SLHPrivateKey::setDerPrivateKey(inSk);

	getOSSLKey();
  if (EVP_PKEY_get0_type_name(pkey) == NULL)
  	{ ERROR_MSG("Could not determine algorithm name from EVP_PKEY"); return; }

  name = EVP_PKEY_get0_type_name(pkey);

	if (pkey)
		{ EVP_PKEY_free(pkey); pkey = NULL; }
}

// Encode into PKCS#8 DER
ByteString OSSLSLHPrivateKey::PKCS8Encode()
{
	ByteString der;
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(key);
	if (p8 == NULL) return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8, NULL);
	if (len <= 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8);
		return der;
	}
	der.resize(len);
	unsigned char* p = &der[0];
	i2d_PKCS8_PRIV_KEY_INFO(p8, &p);
	PKCS8_PRIV_KEY_INFO_free(p8);
	return der;
}

// Decode from PKCS#8 BER
bool OSSLSLHPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* p = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
	if (p8 == NULL) return false;
	EVP_PKEY* key = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (key == NULL) return false;
	setFromOSSL(key);
	EVP_PKEY_free(key);
	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLSLHPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLSLHPrivateKey::createOSSLKey()
{
  // Deserialize from DER (PKCS#8), like function PKCS8Decode
	if (pkey != NULL) return;

	const unsigned char *p = &derPrivateKey[0];
  PKCS8_PRIV_KEY_INFO* p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, derPrivateKey.size());
  if (!p8inf)
  	ERROR_MSG("d2i_PKCS8_PRIV_KEY_INFO; error on decoding pkey");
  pkey = EVP_PKCS82PKEY(p8inf);
  PKCS8_PRIV_KEY_INFO_free(p8inf);

  if (!pkey)
  	ERROR_MSG("EVP_PKCS82PKEY; Error on deserialize derPrivateKey to pkey");

  if (EVP_PKEY_get0_type_name(pkey) == NULL)
  	{ ERROR_MSG("Could not determine algorithm name from EVP_PKEY"); return; }
  name = EVP_PKEY_get0_type_name(pkey);
}


#endif
