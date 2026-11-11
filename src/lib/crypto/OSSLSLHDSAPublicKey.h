/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

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

	/** \brief Constructor from OpenSSL representation */
	OSSLSLHDSAPublicKey(const EVP_PKEY* inSLHDSAKEY);

	/** \brief Destructor */
	virtual ~OSSLSLHDSAPublicKey();

	/** \brief Non-copyable (raw ownership of EVP_PKEY) */
	OSSLSLHDSAPublicKey(const OSSLSLHDSAPublicKey&) = delete;
	/** \brief Non-copyable assignment */
	OSSLSLHDSAPublicKey& operator=(const OSSLSLHDSAPublicKey&) = delete;

	/** \brief Movable */
	OSSLSLHDSAPublicKey(OSSLSLHDSAPublicKey&&) noexcept;
	/** \brief Movable assignment */
	OSSLSLHDSAPublicKey& operator=(OSSLSLHDSAPublicKey&&) noexcept;

	/** \brief The type */
	static const char* type;

	/** \brief Check if the key is of the given type */
	virtual bool isOfType(const char* inType);

	/** \brief Setters for the SLH-DSA public key components */
	virtual void setValue(const ByteString& value);
	virtual void setParameterSet(unsigned long inParameterSet);

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

#endif // WITH_SLH_DSA
#endif // !_SOFTHSM_V2_OSSLSLHDSAPUBLICKEY_H

