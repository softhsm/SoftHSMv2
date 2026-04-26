/*****************************************************************************
 OSSLSLHDSAPublicKey.h

 OpenSSL SLH-DSA public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSLHDSAPUBLICKEY_H
#define _SOFTHSM_V2_OSSLSLHDSAPUBLICKEY_H

#include "config.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAParameters.h"
#include "SLHDSAPublicKey.h"
#include <openssl/evp.h>

class OSSLSLHDSAPublicKey : public SLHDSAPublicKey
{
public:
 /** \brief Constructors */
	OSSLSLHDSAPublicKey();

	OSSLSLHDSAPublicKey(const EVP_PKEY* inSLHDSAKEY);

 /** \brief Destructor */
	virtual ~OSSLSLHDSAPublicKey();

 /** \brief Non-copyable (raw ownership of EVP_PKEY) */
    OSSLSLHDSAPublicKey(const OSSLSLHDSAPublicKey&) = delete;
    OSSLSLHDSAPublicKey& operator=(const OSSLSLHDSAPublicKey&) = delete;

 /** \brief Movable */
	OSSLSLHDSAPublicKey(OSSLSLHDSAPublicKey&&) noexcept;
	OSSLSLHDSAPublicKey& operator=(OSSLSLHDSAPublicKey&&) noexcept;

 /** \brief The type */
	static const char* type;

 /** \brief Check if the key is of the given type */
	virtual bool isOfType(const char* inType);

	virtual void setValue(const ByteString& value);

 /** \brief Set from OpenSSL representation */
	virtual void setFromOSSL(const EVP_PKEY* inSLHDSAKEY);

 /** \brief Retrieve the OpenSSL representation of the key */
	EVP_PKEY* getOSSLKey();

private:
 /** \brief The internal OpenSSL representation */
	EVP_PKEY* pkey;

 /** \brief Create the OpenSSL representation of the key */
	void createOSSLKey();
};

#endif // !WITH_SLH_DSA
#endif // !_SOFTHSM_V2_OSSLSLHDSAPUBLICKEY_H

