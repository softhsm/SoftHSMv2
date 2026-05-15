/*****************************************************************************
 OSSLMLKEMKeyPair.cpp

 OpenSSL ML-KEM key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "log.h"
#include "OSSLMLKEMKeyPair.h"

// Set the public key
void OSSLMLKEMKeyPair::setPublicKey(OSSLMLKEMPublicKey& publicKey)
{
	// Copy only the public material; avoid sharing OpenSSL handles
	pubKey.setValue(publicKey.getValue());
}

// Set the private key
void OSSLMLKEMKeyPair::setPrivateKey(OSSLMLKEMPrivateKey& privateKey)
{
	// Copy only the raw material; avoid sharing OpenSSL handles
	privKey.setSeed(privateKey.getSeed());
	privKey.setValue(privateKey.getValue());
}

// Return the public key
PublicKey* OSSLMLKEMKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OSSLMLKEMKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* OSSLMLKEMKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OSSLMLKEMKeyPair::getConstPrivateKey() const
{
	return &privKey;
}
#endif
