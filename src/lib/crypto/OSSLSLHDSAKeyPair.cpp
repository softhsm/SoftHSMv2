/*****************************************************************************
 OSSLSLHDSAKeyPair.cpp

 OpenSSL SLH-DSA key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLH_DSA
#include "log.h"
#include "OSSLSLHDSAKeyPair.h"

// Set the public key
/** \brief setPublicKey */
void OSSLSLHDSAKeyPair::setPublicKey(const OSSLSLHDSAPublicKey& publicKey)
{
	// Copy only the public material; avoid sharing OpenSSL handles
	pubKey.setValue(publicKey.getValue());
	pubKey.setParameterSet(publicKey.getParameterSet());
}

// Set the private key
/** \brief setPrivateKey */
void OSSLSLHDSAKeyPair::setPrivateKey(const OSSLSLHDSAPrivateKey& privateKey)
{
	// Copy only the raw material; avoid sharing OpenSSL handles
	privKey.setValue(privateKey.getValue());
	privKey.setParameterSet(privateKey.getParameterSet());
}

// Return the public key
/** \brief getPublicKey */
PublicKey* OSSLSLHDSAKeyPair::getPublicKey()
{
	return &pubKey;
}

/** \brief getConstPublicKey */
const PublicKey* OSSLSLHDSAKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
/** \brief getPrivateKey */
PrivateKey* OSSLSLHDSAKeyPair::getPrivateKey()
{
	return &privKey;
}

/** \brief getConstPrivateKey */
const PrivateKey* OSSLSLHDSAKeyPair::getConstPrivateKey() const
{
	return &privKey;
}
#endif
