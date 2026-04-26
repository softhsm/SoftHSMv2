/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

class OSSLSLHDSA : public AsymmetricAlgorithm
{
public:
 /** \brief Destructor */
	virtual ~OSSLSLHDSA() { }

 /** \brief Sign data */
	virtual bool sign(PrivateKey *privateKey, const ByteString &dataToSign, ByteString &signature, const AsymMech::Type mechanism, const void *param = NULL, const size_t paramLen = 0, const MechanismParam* mechanismParam = NULL);
 /** \brief Initialize signing */
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
 /** \brief Update signing */
	virtual bool signUpdate(const ByteString& dataToSign);
 /** \brief Finalize signing */
	virtual bool signFinal(ByteString& signature);

 /** \brief Verify signature */
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0, const MechanismParam* mechanismParam = NULL);
 /** \brief Initialize verification */
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
 /** \brief Update verification */
	virtual bool verifyUpdate(const ByteString& originalData);
 /** \brief Finalize verification */
	virtual bool verifyFinal(const ByteString& signature);

 /** \brief Encrypt data */
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding);

 /** \brief Check encrypted data size */
	virtual bool checkEncryptedDataSize(PrivateKey* privateKey, const ByteString& encryptedData, int* errorCode);
 /** \brief Decrypt data */
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding);
 /** \brief Get minimum key size */
	virtual unsigned long getMinKeySize();
 /** \brief Get maximum key size */
	virtual unsigned long getMaxKeySize();

 /** \brief Generate key pair */
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);
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
 /** \brief Random flag */
	static int OSSL_RANDOM;
 /** \brief Deterministic flag */
	static int OSSL_DETERMINISTIC;
};

#endif // WITH_SLH_DSA
#endif // !_SOFTHSM_V2_OSSLSLHDSA_H

