/*****************************************************************************
 OSSLMLKEMKeyPair.h

 OpenSSL ML-KEM key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLKEMKEYPAIR_H
#define _SOFTHSM_V2_OSSLMLKEMKEYPAIR_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "AsymmetricKeyPair.h"
#include "OSSLMLKEMPublicKey.h"
#include "OSSLMLKEMPrivateKey.h"

class OSSLMLKEMKeyPair : public AsymmetricKeyPair
{
public:
	// Set the public key
	void setPublicKey(OSSLMLKEMPublicKey& publicKey);

	// Set the private key
	void setPrivateKey(OSSLMLKEMPrivateKey& privateKey);

	// Return the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Return the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	// The public key
	OSSLMLKEMPublicKey pubKey;

	// The private key
	OSSLMLKEMPrivateKey privKey;
};

#endif // !WITH_ML_KEM
#endif // !_SOFTHSM_V2_OSSLMLKEMKEYPAIR_H

