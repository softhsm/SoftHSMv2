/*****************************************************************************
 OSSLSLHDSAKeyPair.h

 OpenSSL SLH-DSA key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSLHDSAKEYPAIR_H
#define _SOFTHSM_V2_OSSLSLHDSAKEYPAIR_H

#include "config.h"
#ifdef WITH_SLH_DSA
#include "AsymmetricKeyPair.h"
#include "OSSLSLHDSAPublicKey.h"
#include "OSSLSLHDSAPrivateKey.h"

class OSSLSLHDSAKeyPair : public AsymmetricKeyPair
{
public:
 /** \brief Set the public key */
	void setPublicKey(OSSLSLHDSAPublicKey& publicKey);

 /** \brief Set the private key */
	void setPrivateKey(OSSLSLHDSAPrivateKey& privateKey);

 /** \brief Return the public key */
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

 /** \brief Return the private key */
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
 /** \brief The public key */
	OSSLSLHDSAPublicKey pubKey;

 /** \brief The private key */
	OSSLSLHDSAPrivateKey privKey;
};

#endif // !WITH_SLH_DSA
#endif // !_SOFTHSM_V2_OSSLSLHDSAKEYPAIR_H
