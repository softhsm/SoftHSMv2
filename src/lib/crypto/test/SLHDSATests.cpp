/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SLHDSATests.cpp

 Contains test cases to test the SLH-DSA class
 *****************************************************************************/

#include <stdlib.h>
#include <utility>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "SLHDSATests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAMechanismParam.h"
#include "SLHDSAParameters.h"
#include "SLHDSAPublicKey.h"
#include "SLHDSAPrivateKey.h"
#include "SLHDSAUtil.h"
#include "SessionObject.h"
#include "OSSLSLHDSAPublicKey.h"
#include "OSSLSLHDSAPrivateKey.h"
#include "OSSLUtil.h"
#include "SLHDSAKAT.h"
#include <openssl/rand.h>
#include <openssl/randerr.h>
#include <openssl/err.h>
#include <openssl/evperr.h>
#include <cstdint>

CPPUNIT_TEST_SUITE_REGISTRATION(SLHDSATests);

static const std::vector<unsigned long> allParameterSets =
{
	CKP_SLH_DSA_SHA2_128S, CKP_SLH_DSA_SHAKE_128S, CKP_SLH_DSA_SHA2_128F, CKP_SLH_DSA_SHAKE_128F, CKP_SLH_DSA_SHA2_192S, CKP_SLH_DSA_SHAKE_192S, CKP_SLH_DSA_SHA2_192F, CKP_SLH_DSA_SHAKE_192F, CKP_SLH_DSA_SHA2_256S, CKP_SLH_DSA_SHAKE_256S, CKP_SLH_DSA_SHA2_256F, CKP_SLH_DSA_SHAKE_256F
};

SLHDSATests::SLHDSATests() : slhdsa(NULL)
{
}

/** Create the SLH-DSA algorithm instance used by each test. */
void SLHDSATests::setUp()
{
	slhdsa = NULL;

	slhdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);

	// Check the SLHDSA object
	CPPUNIT_ASSERT(slhdsa != NULL);
}

/** Recycle the SLH-DSA algorithm instance and flush test output. */
void SLHDSATests::tearDown()
{
	if (slhdsa != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
	}

	fflush(stdout);
}

/** Recheck provider properties on every availability query without leaving fetch errors behind. */
void SLHDSATests::testParameterSetAvailability()
{
	CPPUNIT_ASSERT(!SLHDSAUtil::isParameterSetAvailable(0));
	for (const unsigned long parameterSet : allParameterSets)
		CPPUNIT_ASSERT(SLHDSAUtil::isParameterSetAvailable(parameterSet));

	char* properties = EVP_get1_default_properties(NULL);
	CPPUNIT_ASSERT(properties != NULL);
	ERR_clear_error();
	int configured = EVP_set_default_properties(NULL, "provider=softhsm-test-missing-provider");
	bool unavailable = !SLHDSAUtil::isParameterSetAvailable(CKP_SLH_DSA_SHA2_128F);
	unsigned long error = ERR_peek_error();
	int restored = EVP_set_default_properties(NULL, properties);
	OPENSSL_free(properties);
	bool availableAgain = SLHDSAUtil::isParameterSetAvailable(CKP_SLH_DSA_SHA2_128F);
	CPPUNIT_ASSERT_EQUAL(1, configured);
	CPPUNIT_ASSERT_EQUAL(1, restored);
	CPPUNIT_ASSERT(unavailable);
	CPPUNIT_ASSERT_EQUAL(0UL, error);
	CPPUNIT_ASSERT(availableAgain);
}

/** Generate keys for every supported SLH-DSA parameter set. */
void SLHDSATests::testKeyGeneration()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Set domain parameters
		SLHDSAParameters *p = new SLHDSAParameters();
		p->setParameterSet(parameterSet);

		// Generate key-pair
		AsymmetricKeyPair *kp;
		CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

		SLHDSAPublicKey *pub = (SLHDSAPublicKey *)kp->getPublicKey();
		SLHDSAPrivateKey *priv = (SLHDSAPrivateKey *)kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getParameterSet() == parameterSet);
		CPPUNIT_ASSERT(priv->getParameterSet() == parameterSet);

		slhdsa->recycleParameters(p);
		slhdsa->recycleKeyPair(kp);
	}
}

/** Round-trip SLH-DSA parameters and key pairs through their serialized representation. */
void SLHDSATests::testSerialisation()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		SLHDSAParameters *p = new SLHDSAParameters();
		p->setParameterSet(parameterSet);

		// Serialise the parameters
		ByteString serialisedParams = p->serialise();

		// Deserialise the parameters
		AsymmetricParameters *dSLHDSA;

		CPPUNIT_ASSERT(slhdsa->reconstructParameters(&dSLHDSA, serialisedParams));

		CPPUNIT_ASSERT(dSLHDSA->areOfType(SLHDSAParameters::type));

		SLHDSAParameters *ddSLHDSA = (SLHDSAParameters *)dSLHDSA;

		CPPUNIT_ASSERT(p->getParameterSet() == ddSLHDSA->getParameterSet());

		// Generate a key-pair
		AsymmetricKeyPair *kp;

		CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, dSLHDSA));


		// Serialise the key-pair
		ByteString serialisedKP = kp->serialise();

		// Deserialise the key-pair

		AsymmetricKeyPair *dKP;

		CPPUNIT_ASSERT(slhdsa->reconstructKeyPair(&dKP, serialisedKP));

		// Check the deserialised key-pair
		SLHDSAPrivateKey *privKey = (SLHDSAPrivateKey *)kp->getPrivateKey();
		SLHDSAPublicKey *pubKey = (SLHDSAPublicKey *)kp->getPublicKey();

		SLHDSAPrivateKey *dPrivKey = (SLHDSAPrivateKey *)dKP->getPrivateKey();
		SLHDSAPublicKey *dPubKey = (SLHDSAPublicKey *)dKP->getPublicKey();

		CPPUNIT_ASSERT(privKey->getParameterSet() == dPrivKey->getParameterSet());
		CPPUNIT_ASSERT(privKey->getValue() == dPrivKey->getValue());

		CPPUNIT_ASSERT(pubKey->getParameterSet() == dPubKey->getParameterSet());
		CPPUNIT_ASSERT(pubKey->getValue() == dPubKey->getValue());

		slhdsa->recycleParameters(p);
		slhdsa->recycleParameters(dSLHDSA);
		slhdsa->recycleKeyPair(kp);
		slhdsa->recycleKeyPair(dKP);
	}
}

/** Round-trip SLH-DSA private keys through PKCS#8 encoding. */
void SLHDSATests::testPKCS8()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		SLHDSAParameters *p = new SLHDSAParameters();
		p->setParameterSet(parameterSet);

		// Generate a key-pair
		AsymmetricKeyPair *kp;

		CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		SLHDSAPrivateKey *priv = (SLHDSAPrivateKey *)kp->getPrivateKey();
		CPPUNIT_ASSERT(priv != NULL);

		SLHDSAPublicKey *pub = (SLHDSAPublicKey *)kp->getPublicKey();
		CPPUNIT_ASSERT(pub != NULL);

		// Encode and decode the private key
		ByteString pkcs8 = priv->PKCS8Encode();
		CPPUNIT_ASSERT(pkcs8.size() != 0);

		SLHDSAPrivateKey *dPriv = (SLHDSAPrivateKey *)slhdsa->newPrivateKey();
		CPPUNIT_ASSERT(dPriv != NULL);

		CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

		CPPUNIT_ASSERT(priv->getParameterSet() == dPriv->getParameterSet());
		CPPUNIT_ASSERT(priv->getValue() == dPriv->getValue());

		slhdsa->recycleParameters(p);
		slhdsa->recyclePrivateKey(dPriv);
		slhdsa->recycleKeyPair(kp);
	}
}

/** Match independent NIST signatures and verify them with their nonempty contexts. */
void SLHDSATests::testKnownAnswers()
{
	for (const SLHDSAKnownAnswer& vector : slhdsaKnownAnswers)
	{
		OSSLSLHDSAPrivateKey privateKey;
		OSSLSLHDSAPublicKey publicKey;
		privateKey.setParameterSet(vector.parameterSet);
		privateKey.setValue(ByteString(vector.privateKey));
		publicKey.setParameterSet(vector.parameterSet);
		publicKey.setValue(ByteString(vector.publicKey));
		SLHDSAMechanismParam parameters;
		parameters.hedgeType = Hedge::DETERMINISTIC_REQUIRED;
		parameters.additionalContext = ByteString(vector.context);
		ByteString message(vector.message), expected(vector.signature), actual;
		CPPUNIT_ASSERT(slhdsa->sign(&privateKey, message, actual, AsymMech::SLHDSA, &parameters));
		CPPUNIT_ASSERT(actual == expected);
		CPPUNIT_ASSERT(slhdsa->verify(&publicKey, message, expected, AsymMech::SLHDSA, &parameters));
		parameters.additionalContext[0] ^= 1;
		CPPUNIT_ASSERT(!slhdsa->verify(&publicKey, message, expected, AsymMech::SLHDSA, &parameters));
	}
}

/** Sign and verify random messages for every supported SLH-DSA parameter set. */
void SLHDSATests::testSigningVerifying()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		SLHDSAParameters *p = new SLHDSAParameters();
		CPPUNIT_ASSERT(p != NULL);
		p->setParameterSet(parameterSet);

		// Generate key-pair
		AsymmetricKeyPair *kp;
		CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

		// Generate some data to sign
		ByteString dataToSign;

		RNG *rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

		// Sign the data
		ByteString sig;
		CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA));

		// And verify it
		CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA));

		slhdsa->recycleKeyPair(kp);
		slhdsa->recycleParameters(p);
	}
}



/** Exercise signing and verification with preferred randomized hedging. */
void SLHDSATests::testSigningVerifyingHedgePreferred()
{

	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

/** Verify preferred-hedging signatures bound to a nonempty context. */
void SLHDSATests::testSigningVerifyingHedgePreferredWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("HEDGE_PREFERRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

/** Reject an overlong context when randomized hedging is preferred. */
void SLHDSATests::testSigningVerifyingHedgePreferredWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("HEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERREDHEDGE_PREFERRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT_EQUAL(false, slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

/** Exercise signatures that require randomized hedging. */
void SLHDSATests::testSigningVerifyingHedgeRequired()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

/** Verify required-hedging signatures bound to a nonempty context. */
void SLHDSATests::testSigningVerifyingHedgeRequiredWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("HEDGE_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

/** Reject an overlong context when randomized hedging is required. */
void SLHDSATests::testSigningVerifyingHedgeRequiredWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("HEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIREDHEDGE_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

/** Check repeatable signatures when deterministic signing is required. */
void SLHDSATests::testSigningVerifyingDeterministic()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED);

	// Sign the data
	ByteString sig1;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig1, AsymMech::SLHDSA, &context));

	// Sign again and assert identical signature
	ByteString sig2;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig2, AsymMech::SLHDSA, &context));
	CPPUNIT_ASSERT(sig1 == sig2);

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig1, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

/** Check deterministic signing and verification with a nonempty context. */
void SLHDSATests::testSigningVerifyingDeterministicWithContext()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("DETERMINISTIC_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, contextBS);

	// Sign the data
	ByteString sig1;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig1, AsymMech::SLHDSA, &context));

	// Sign again and assert identical signature
	ByteString sig2;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig2, AsymMech::SLHDSA, &context));
	CPPUNIT_ASSERT(sig1 == sig2);

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig1, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

/** Reject an overlong context in deterministic signing and verification. */
void SLHDSATests::testSigningVerifyingDeterministicWithContextTooLong()
{
	// Get domain parameters
	SLHDSAParameters *p = new SLHDSAParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(CKP_SLH_DSA_SHA2_128S);

	// Generate key-pair
	AsymmetricKeyPair *kp;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

	// Generate some data to sign
	ByteString dataToSign;

	RNG *rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

	std::string contextStr = std::string("DETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIREDDETERMINISTIC_REQUIRED");
	ByteString contextBS((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}


/** Reject oversized parameter identifiers and malformed serialized raw-key lengths. */
void SLHDSATests::testInvalidSerialisation()
{
	for (unsigned long parameterSet : allParameterSets)
	{
		SLHDSAParameters parameters;
		SLHDSAPublicKey publicKey;
		OSSLSLHDSAPrivateKey privateKey;
		for (uint64_t id : {uint64_t(parameterSet), (uint64_t(1) << 32) | parameterSet, UINT64_MAX})
		{
			unsigned char bigEndian[8];
			for (size_t i = 0; i < 8; ++i) bigEndian[7-i] = (id >> (8*i)) & 0xff;
			ByteString encodedId(bigEndian, sizeof(bigEndian));
			CPPUNIT_ASSERT_EQUAL(id == parameterSet, parameters.deserialise(encodedId));
			ByteString nativeId(reinterpret_cast<const unsigned char*>(&id), sizeof(id));
			for (int delta : {-1, 0, 1})
			{
				ByteString value;
				value.resize(SLHDSAParameters::publicKeyLength(parameterSet) + delta);
				ByteString serialised = value.serialise() + nativeId.serialise();
				CPPUNIT_ASSERT_EQUAL(id == parameterSet && delta == 0, publicKey.deserialise(serialised));
				value.resize(SLHDSAParameters::privateKeyLength(parameterSet) + delta);
				serialised = value.serialise() + nativeId.serialise();
				CPPUNIT_ASSERT_EQUAL(id == parameterSet && delta == 0, privateKey.deserialise(serialised));
			}
		}
	}
}

/** Check that both key readers enforce raw lengths for all SLH-DSA parameter sets. */
void SLHDSATests::testKeyReadersRejectLengths()
{
	Token token;
	SessionObject object(NULL, 0, 0);
	SLHDSAPublicKey publicKey;
	OSSLSLHDSAPrivateKey privateKey;
	CPPUNIT_ASSERT(object.setAttribute(CKA_PRIVATE, false));
	for (unsigned long parameterSet : allParameterSets)
	{
		CPPUNIT_ASSERT(object.setAttribute(CKA_PARAMETER_SET, parameterSet));
		for (int delta : {-1, 0, 1})
		{
			ByteString value;
			value.resize(SLHDSAParameters::publicKeyLength(parameterSet) + delta);
			CPPUNIT_ASSERT(object.setAttribute(CKA_VALUE, value));
			CPPUNIT_ASSERT_EQUAL(CK_RV(delta == 0 ? CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID),
				SLHDSAUtil::getSLHDSAPublicKey(&publicKey, &token, &object));
			value.resize(SLHDSAParameters::privateKeyLength(parameterSet) + delta);
			CPPUNIT_ASSERT(object.setAttribute(CKA_VALUE, value));
			CPPUNIT_ASSERT_EQUAL(CK_RV(delta == 0 ? CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID),
				SLHDSAUtil::getSLHDSAPrivateKey(&privateKey, &token, &object));
		}
	}
}

/** Accept provider OID aliases and reject available non-SLH-DSA key types. */
void SLHDSATests::testProviderAliases()
{
	OSSLSLHDSAPublicKey publicKey;
	OSSLSLHDSAPrivateKey privateKey;
	for (unsigned long parameterSet : allParameterSets)
	{
		// Use the provider's OID alias to create the key.
		const ASN1_OBJECT* oid = OBJ_nid2obj(OBJ_ln2nid(OSSL::slhdsaParameterSet2Name(parameterSet)));
		char alias[80];
		CPPUNIT_ASSERT(OBJ_obj2txt(alias, sizeof(alias), oid, 1) > 0);
		EVP_PKEY* key = EVP_PKEY_Q_keygen(NULL, NULL, alias);
		CPPUNIT_ASSERT(key != NULL);
		CPPUNIT_ASSERT(publicKey.setFromOSSL(key));
		CPPUNIT_ASSERT(privateKey.setFromOSSL(key));
		CPPUNIT_ASSERT_EQUAL(parameterSet, publicKey.getParameterSet());
		CPPUNIT_ASSERT_EQUAL(parameterSet, privateKey.getParameterSet());
		EVP_PKEY_free(key);
	}
	// RSA generation is optional in a provider configuration supporting SLH-DSA.
	EVP_PKEY_CTX* rsa = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (rsa != NULL && EVP_PKEY_keygen_init(rsa) > 0)
	{
		EVP_PKEY* key = NULL;
		CPPUNIT_ASSERT(EVP_PKEY_generate(rsa, &key) > 0);
		CPPUNIT_ASSERT(key != NULL);
		CPPUNIT_ASSERT(!publicKey.setFromOSSL(key));
		CPPUNIT_ASSERT(!privateKey.setFromOSSL(key));
		EVP_PKEY_free(key);
	}
	EVP_PKEY_CTX_free(rsa);
	ERR_clear_error();
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
namespace {
int rngFailureLibrary;
int rngFailureReason;
int rngFailureCalls;
int failSLHRandomBytes(unsigned char*, int)
{
	++rngFailureCalls;
	ERR_raise(rngFailureLibrary, rngFailureReason);
	return 0;
}
struct RestoreRandomMethod {
	const RAND_METHOD* method;
	RestoreRandomMethod() : method(RAND_get_rand_method()) {}
	~RestoreRandomMethod() { RAND_set_rand_method(method); ERR_clear_error(); }
};
}
#endif

/** Check deterministic fallback only for RNG failures under preferred hedging. */
void SLHDSATests::testHedgeRngFailure()
{
#ifndef OPENSSL_NO_DEPRECATED_3_0
	SLHDSAParameters parameters;
	parameters.setParameterSet(CKP_SLH_DSA_SHA2_128F);
	AsymmetricKeyPair* pair = NULL;
	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&pair, &parameters));
	ByteString message("0102030405");
	SLHDSAMechanismParam preferred;
	preferred.hedgeType = Hedge::HEDGE_PREFERRED;
	preferred.additionalContext = ByteString("aabbcc");
	SLHDSAMechanismParam deterministic = preferred;
	deterministic.hedgeType = Hedge::DETERMINISTIC_REQUIRED;
	SLHDSAMechanismParam required = preferred;
	required.hedgeType = Hedge::HEDGE_REQUIRED;
	ByteString expected, actual;
	CPPUNIT_ASSERT(slhdsa->sign(pair->getPrivateKey(), message, expected, AsymMech::SLHDSA, &deterministic));
	{
		RestoreRandomMethod restore;
		RAND_METHOD failing = *restore.method;
		failing.bytes = failSLHRandomBytes;
		CPPUNIT_ASSERT_EQUAL(1, RAND_set_rand_method(&failing));
		for (int library : {ERR_LIB_RAND, ERR_LIB_EVP})
		{
			rngFailureLibrary = library;
			rngFailureReason = library == ERR_LIB_RAND ? RAND_R_ERROR_INSTANTIATING_DRBG : EVP_R_GENERATE_ERROR;
			rngFailureCalls = 0;
			CPPUNIT_ASSERT(slhdsa->sign(pair->getPrivateKey(), message, actual, AsymMech::SLHDSA, &preferred));
			CPPUNIT_ASSERT(rngFailureCalls > 0);
			CPPUNIT_ASSERT(actual == expected);
			CPPUNIT_ASSERT(slhdsa->verify(pair->getPublicKey(), message, actual, AsymMech::SLHDSA, &preferred));
			CPPUNIT_ASSERT(!slhdsa->sign(pair->getPrivateKey(), message, actual, AsymMech::SLHDSA, &required));
			CPPUNIT_ASSERT(slhdsa->sign(pair->getPrivateKey(), message, actual, AsymMech::SLHDSA, NULL));
			CPPUNIT_ASSERT(slhdsa->verify(pair->getPublicKey(), message, actual, AsymMech::SLHDSA, NULL));
		}
		// Unrelated provider errors must keep following the signing error path.
		rngFailureLibrary = ERR_LIB_EVP;
		rngFailureReason = EVP_R_INVALID_OPERATION;
		CPPUNIT_ASSERT(!slhdsa->sign(pair->getPrivateKey(), message, actual, AsymMech::SLHDSA, &preferred));
	}
	slhdsa->recycleKeyPair(pair);
#endif
}
#endif
