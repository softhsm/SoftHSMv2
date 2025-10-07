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
 OSSLSLHPublicKey.cpp

 OpenSSL SLHDSA public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLHDSA
#include "log.h"
#include "DerUtil.h"
#include "OSSLSLHPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/x509.h>
#include <string.h>

// Constructors
OSSLSLHPublicKey::OSSLSLHPublicKey()
{
	pkey = NULL;
	name = NULL;
}

OSSLSLHPublicKey::OSSLSLHPublicKey(const EVP_PKEY* inPKEY)
{
	name = NULL;
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLSLHPublicKey::~OSSLSLHPublicKey()
{
  if (pkey) {
      EVP_PKEY_free(pkey);
      pkey = NULL;
  }
  name = NULL;
}

// The type
/*static*/ const char* OSSLSLHPublicKey::type = "OpenSSL SLHDSA Public Key";

unsigned long OSSLSLHPublicKey::getOrderLength() const
{
  if (name == NULL){
    ERROR_MSG("Could not determine the signature size, name is NULL");
    return 0;
  }
  size_t name_len = strnlen(name, 100);
  size_t signature_size = 0;

  INFO_MSG("name %s", name);
  if (strncmp(&name[name_len - 4], "128s", 4) == 0) {
    signature_size = 7856;
  } else if (strncmp(&name[name_len - 4], "128f", 4) == 0) {
    signature_size = 17088;
  } else if (strncmp(&name[name_len - 4], "192s", 4) == 0) {
    signature_size = 16224;
  } else if (strncmp(&name[name_len - 4], "192f", 4) == 0) {
    signature_size = 35664;
  } else if (strncmp(&name[name_len - 4], "256s", 4) == 0) {
    signature_size = 29792;
  } else if (strncmp(&name[name_len - 4], "256f", 4) == 0) {
    signature_size = 49856;
  } else{
    ERROR_MSG("Could not determine the signature size");
  }
	return signature_size;
}

// Set from OpenSSL representation
void OSSLSLHPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
  if (EVP_PKEY_get0_type_name(inPKEY) == NULL)
  {
    ERROR_MSG("Could not determine algorithm name from EVP_PKEY");
    return;
  }
  name = EVP_PKEY_get0_type_name(inPKEY);

	ByteString der;
  int len = i2d_PUBKEY(inPKEY, NULL);
  if (len <= 0)
  {
  	ERROR_MSG("i2d_PUBKEY info error, len is smaller or eq than zero");
  	return;
  }
	der.resize(len);
  unsigned char* p = &der[0];
  if (i2d_PUBKEY(inPKEY, &p) != len)
  	{ ERROR_MSG("i2d_PUBKEY serialization error"); return; }

	setDerPublicKey(der);
}

// Check if the key is of the given type
bool OSSLSLHPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the SLHDSA public key components
void OSSLSLHPublicKey::setDerPublicKey(const ByteString& inPk)
{
	SLHPublicKey::setDerPublicKey(inPk);

	getOSSLKey();
  if (EVP_PKEY_get0_type_name(pkey) == NULL)
  	{ ERROR_MSG("Could not determine algorithm name from EVP_PKEY"); return; }

  name = EVP_PKEY_get0_type_name(pkey);

	if (pkey)
		{ EVP_PKEY_free(pkey); pkey = NULL; }
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLSLHPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLSLHPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;

	const unsigned char *p = &derPublicKey[0];
	pkey = d2i_PUBKEY(NULL, &p, (long)derPublicKey.size());

  if (!pkey)
  	ERROR_MSG("d2i_PUBKEY; Error on deserialize derPublicKey to pkey");

  if (EVP_PKEY_get0_type_name(pkey) == NULL)
  	{ ERROR_MSG("Could not determine algorithm name from EVP_PKEY"); return; }
  name = EVP_PKEY_get0_type_name(pkey);
}
#endif
