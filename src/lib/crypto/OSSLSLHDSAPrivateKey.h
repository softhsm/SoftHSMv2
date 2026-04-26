/*****************************************************************************
 OSSLSLHDSAPrivateKey.h

 OpenSSL SLH-DSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H
#define _SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H

#include "config.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAParameters.h"
#include "SLHDSAPrivateKey.h"
#include <openssl/bn.h>
#include <openssl/evp.h>

class OSSLSLHDSAPrivateKey : public SLHDSAPrivateKey
{
public:
 /** \brief Constructors */
	OSSLSLHDSAPrivateKey();

	OSSLSLHDSAPrivateKey(const EVP_PKEY* inSLHDSAKEY);

 /** \brief Destructor */
	virtual ~OSSLSLHDSAPrivateKey();

 /** \brief Non-copyable (raw ownership of EVP_PKEY) */
	OSSLSLHDSAPrivateKey(const OSSLSLHDSAPrivateKey&) = delete;  
    OSSLSLHDSAPrivateKey& operator=(const OSSLSLHDSAPrivateKey&) = delete;  
  
 /** \brief Movable */
	OSSLSLHDSAPrivateKey(OSSLSLHDSAPrivateKey&&) noexcept;  
	OSSLSLHDSAPrivateKey& operator=(OSSLSLHDSAPrivateKey&&) noexcept;  

 /** \brief The type */
	static const char* type;

 /** \brief Check if the key is of the given type */
	virtual bool isOfType(const char* inType);

 /** \brief Setters for the SLH-DSA private key components */
	virtual void setValue(const ByteString& value);
	
 /** \brief Encode into PKCS#8 DER */
	virtual ByteString PKCS8Encode();

 /** \brief Decode from PKCS#8 BER */
	virtual bool PKCS8Decode(const ByteString& ber);

 /** \brief Set from OpenSSL representation */
	virtual bool setFromOSSL(const EVP_PKEY* inSLHDSAKEY);

 /** \brief Retrieve the OpenSSL representation of the key */
	EVP_PKEY* getOSSLKey();

private:
 /** \brief The internal OpenSSL representation */
	EVP_PKEY* pkey;

 /** \brief Create the OpenSSL representation of the key */
	void createOSSLKey();

};

#endif // !WITH_SLH_DSA
#endif // !_SOFTHSM_V2_OSSLSLHDSAPRIVATEKEY_H

