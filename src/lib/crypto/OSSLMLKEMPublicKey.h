/*****************************************************************************
 OSSLMLKEMPublicKey.h

 OpenSSL ML-KEM public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLKEMPUBLICKEY_H
#define _SOFTHSM_V2_OSSLMLKEMPUBLICKEY_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "MLKEMParameters.h"
#include "MLKEMPublicKey.h"
#include <openssl/evp.h>

class OSSLMLKEMPublicKey : public MLKEMPublicKey
{
public:
	// Constructors
	OSSLMLKEMPublicKey();

	OSSLMLKEMPublicKey(const EVP_PKEY* inMLKEMKEY);

	// Destructor
	virtual ~OSSLMLKEMPublicKey();

	// Non-copyable (raw ownership of EVP_PKEY)
    OSSLMLKEMPublicKey(const OSSLMLKEMPublicKey&) = delete;
    OSSLMLKEMPublicKey& operator=(const OSSLMLKEMPublicKey&) = delete;

	// Movable
	OSSLMLKEMPublicKey(OSSLMLKEMPublicKey&&) noexcept;
	OSSLMLKEMPublicKey& operator=(OSSLMLKEMPublicKey&&) noexcept;

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	virtual void setValue(const ByteString& value);

	// Set from OpenSSL representation
	virtual void setFromOSSL(const EVP_PKEY* inMLKEMKEY);

	// Retrieve the OpenSSL representation of the key
	EVP_PKEY* getOSSLKey();

private:
	// The internal OpenSSL representation
	EVP_PKEY* pkey;

	// Create the OpenSSL representation of the key
	void createOSSLKey();
};

#endif // !WITH_ML_KEM
#endif // !_SOFTHSM_V2_OSSLKEMPUBLICKEY_H

