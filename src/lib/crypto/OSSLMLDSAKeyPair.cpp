/*****************************************************************************
 OSSLMLDSAKeyPair.cpp

 OpenSSL ML-DSA key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "log.h"
#include "OSSLMLDSAKeyPair.h"

// Set the public key
void OSSLMLDSAKeyPair::setPublicKey(OSSLMLDSAPublicKey& publicKey)
{
	// Copy only the public material; avoid sharing OpenSSL handles
	pubKey.setValue(publicKey.getValue());
}

// Set the private key
void OSSLMLDSAKeyPair::setPrivateKey(OSSLMLDSAPrivateKey& privateKey)
{
	// Copy only the raw material; avoid sharing OpenSSL handles
	privKey.setSeed(privateKey.getSeed());
	privKey.setValue(privateKey.getValue());
}

// Return the public key
PublicKey* OSSLMLDSAKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OSSLMLDSAKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* OSSLMLDSAKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OSSLMLDSAKeyPair::getConstPrivateKey() const
{
	return &privKey;
}
#endif
