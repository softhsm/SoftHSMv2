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
	pubKey = publicKey;
}

// Set the private key
void OSSLMLDSAKeyPair::setPrivateKey(OSSLMLDSAPrivateKey& privateKey)
{
	privKey = privateKey;
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
