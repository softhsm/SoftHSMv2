/*****************************************************************************
 OSSLMLKEMPrivateKey.h

 OpenSSL ML-KEM private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLKEMPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLMLKEMPRIVATEKEY_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "MLKEMParameters.h"
#include "MLKEMPrivateKey.h"
#include <openssl/bn.h>
#include <openssl/evp.h>

class OSSLMLKEMPrivateKey : public MLKEMPrivateKey
{
public:
	// Constructors
	OSSLMLKEMPrivateKey();

	OSSLMLKEMPrivateKey(const EVP_PKEY* inMLKEMKEY);

	// Destructor
	virtual ~OSSLMLKEMPrivateKey();

	// Non-copyable (raw ownership of EVP_PKEY)
	OSSLMLKEMPrivateKey(const OSSLMLKEMPrivateKey&) = delete;
    OSSLMLKEMPrivateKey& operator=(const OSSLMLKEMPrivateKey&) = delete;

	// Movable
	OSSLMLKEMPrivateKey(OSSLMLKEMPrivateKey&&) noexcept;
	OSSLMLKEMPrivateKey& operator=(OSSLMLKEMPrivateKey&&) noexcept;

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Setters for the ML-KEM private key components
	virtual void setValue(const ByteString& value);
	virtual void setSeed(const ByteString& seed);
	
	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

	// Set from OpenSSL representation
	virtual bool setFromOSSL(const EVP_PKEY* inMLKEMKEY);

	// Retrieve the OpenSSL representation of the key
	EVP_PKEY* getOSSLKey();

private:
	// The internal OpenSSL representation
	EVP_PKEY* pkey;

	// Create the OpenSSL representation of the key
	void createOSSLKey();

};

#endif // !WITH_ML_KEM
#endif // !_SOFTHSM_V2_OSSLECPRIVATEKEY_H

