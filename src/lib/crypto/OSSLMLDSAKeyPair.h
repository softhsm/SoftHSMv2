/*****************************************************************************
 OSSLMLDSAKeyPair.h

 OpenSSL ML-DSA key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLDSAKEYPAIR_H
#define _SOFTHSM_V2_OSSLMLDSAKEYPAIR_H

#include "config.h"
#include "AsymmetricKeyPair.h"
#include "OSSLMLDSAPublicKey.h"
#include "OSSLMLDSAPrivateKey.h"

class OSSLMLDSAKeyPair : public AsymmetricKeyPair
{
public:
	// Set the public key
	void setPublicKey(OSSLMLDSAPublicKey& publicKey);

	// Set the private key
	void setPrivateKey(OSSLMLDSAPrivateKey& privateKey);

	// Return the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Return the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	// The public key
	OSSLMLDSAPublicKey pubKey;

	// The private key
	OSSLMLDSAPrivateKey privKey;
};

#endif // !_SOFTHSM_V2_OSSLMLDSAKEYPAIR_H

