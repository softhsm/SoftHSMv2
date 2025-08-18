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
	virtual void setValue(const ByteString& value);
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
	EVP_PKEY* pkey;

	// Create the OpenSSL representation of the key
	void createOSSLKey();

};

#endif // !_SOFTHSM_V2_OSSLECPRIVATEKEY_H

