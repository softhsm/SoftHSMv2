/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OSSLSLHDSA.h

 OpenSSL SLH-DSA asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSLHDSA_H
#define _SOFTHSM_V2_OSSLSLHDSA_H

#include "config.h"
#ifdef WITH_SLH_DSA
#include "AsymmetricAlgorithm.h"
#include <memory>

class OSSLSLHDSA : public AsymmetricAlgorithm
{
public:
	OSSLSLHDSA() : message(), parameters(NULL), paramLength(0), mechanismParameters(nullptr) { }

	/** \brief Destructor */
	virtual ~OSSLSLHDSA() { }

	// Disallow copying
	OSSLSLHDSA(const OSSLSLHDSA&) = delete;
	OSSLSLHDSA& operator=(const OSSLSLHDSA&) = delete;


	/** \brief Sign data */
	virtual bool sign(PrivateKey *privateKey, const ByteString &dataToSign, ByteString &signature, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	/** \brief Initialize signing */
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	/** \brief Update signing */
	virtual bool signUpdate(const ByteString& dataToSign);
	/** \brief Finalize signing */
	virtual bool signFinal(ByteString& signature);

	/** \brief Verify signature */
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	/** \brief Initialize verification */
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	/** \brief Update verification */
	virtual bool verifyUpdate(const ByteString& originalData);
	/** \brief Finalize verification */
	virtual bool verifyFinal(const ByteString& signature);

	/** \brief Encrypt data */
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding,
		 const MechanismParam* mechanismParam = NULL);


	/** \brief Check encrypted data size */
	virtual bool checkEncryptedDataSize(PrivateKey* privateKey, const ByteString& encryptedData, int* errorCode);
	/** \brief Decrypt data */
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding,
		 const MechanismParam* mechanismParam = NULL);


// Key factory
	/** \brief Generate key pair */
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);
	/** \brief Get minimum key size */
	virtual unsigned long getMinKeySize();
	/** \brief Get maximum key size */
	virtual unsigned long getMaxKeySize();
	/** \brief Reconstruct key pair */
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData);
	/** \brief Reconstruct public key */
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData);
	/** \brief Reconstruct private key */
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData);
	/** \brief Reconstruct parameters */
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);
	/** \brief Create new public key */
	virtual PublicKey* newPublicKey();
	/** \brief Create new private key */
	virtual PrivateKey* newPrivateKey();
	/** \brief Create new parameters */
	virtual AsymmetricParameters* newParameters();

private:
	ByteString message;
	void* parameters;
	size_t paramLength;
	std::unique_ptr<const MechanismParam> mechanismParameters;
};

#endif // WITH_SLH_DSA
#endif // !_SOFTHSM_V2_OSSLSLHDSA_H

