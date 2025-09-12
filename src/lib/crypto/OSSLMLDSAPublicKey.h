/*****************************************************************************
 OSSLMLDSAPublicKey.h

 OpenSSL ML-DSA public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLDSAPUBLICKEY_H
#define _SOFTHSM_V2_OSSLMLDSAPUBLICKEY_H

#include "config.h"
#include "MLDSAParameters.h"
#include "MLDSAPublicKey.h"
#include <openssl/evp.h>

class OSSLMLDSAPublicKey : public MLDSAPublicKey
{
public:
	// Constructors
	OSSLMLDSAPublicKey();

	OSSLMLDSAPublicKey(const EVP_PKEY* inMLDSAKEY);

	// Destructor
	virtual ~OSSLMLDSAPublicKey();

	// Non-copyable (raw ownership of EVP_PKEY)
    OSSLMLDSAPublicKey(const OSSLMLDSAPublicKey&) = delete;
    OSSLMLDSAPublicKey& operator=(const OSSLMLDSAPublicKey&) = delete;

	// Movable
	OSSLMLDSAPublicKey(OSSLMLDSAPublicKey&&) noexcept;
	OSSLMLDSAPublicKey& operator=(OSSLMLDSAPublicKey&&) noexcept;

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	virtual void setValue(const ByteString& value);

	// Set from OpenSSL representation
	virtual void setFromOSSL(const EVP_PKEY* inMLDSAKEY);

	// Retrieve the OpenSSL representation of the key
	EVP_PKEY* getOSSLKey();

private:
	// The internal OpenSSL representation
	EVP_PKEY* pkey;

	// Create the OpenSSL representation of the key
	void createOSSLKey();
};

#endif // !_SOFTHSM_V2_OSSLDSAPUBLICKEY_H

