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

CPPUNIT_TEST_SUITE_REGISTRATION(SLHDSATests);

static const std::vector<unsigned long> allParameterSets = {
	CKP_SLH_DSA_SHA2_128S, CKP_SLH_DSA_SHAKE_128S, CKP_SLH_DSA_SHA2_128F, CKP_SLH_DSA_SHAKE_128F, CKP_SLH_DSA_SHA2_192S, CKP_SLH_DSA_SHAKE_192S, CKP_SLH_DSA_SHA2_192F, CKP_SLH_DSA_SHAKE_192F, CKP_SLH_DSA_SHA2_256S, CKP_SLH_DSA_SHAKE_256S, CKP_SLH_DSA_SHA2_256F, CKP_SLH_DSA_SHAKE_256F};

void SLHDSATests::setUp()
{
	slhdsa = NULL;

	slhdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);

	// Check the SLHDSA object
	CPPUNIT_ASSERT(slhdsa != NULL);
}

void SLHDSATests::tearDown()
{
	if (slhdsa != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
	}

	fflush(stdout);
}

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

// test vectors from https://github.com/google/boringssl/blob/main/third_party/wycheproof_testvectors/slhdsa_65_sign_seed_test.json
void SLHDSATests::testSigningTestVector() {}

void SLHDSATests::testSigningTestVectorEmptyContext() {}

void SLHDSATests::testSigningTestVectorNonEmptyContext() {}

void SLHDSATests::testSigningTestVectorLongestContext() {}

void SLHDSATests::testSigningTestVectorContextTooLong() {}

// test vectors from https://github.com/google/boringssl/blob/main/third_party/wycheproof_testvectors/slhdsa_65_verify_test.json
void SLHDSATests::testVerifyingTestVector() {}

void SLHDSATests::testVerifyingTestVectorEmptyContext() {}

void SLHDSATests::testVerifyingTestVectorNonEmptyContext() {}

void SLHDSATests::testVerifyingTestVectorLongestContext() {}

void SLHDSATests::testVerifyingTestVectorContextTooLong() {}

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
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

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
	ByteString* contextBS = new ByteString((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, *contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

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
	ByteString* contextBS = new ByteString((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_PREFERRED, *contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT_EQUAL(false, slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

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
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

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
	ByteString* contextBS = new ByteString((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, *contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

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
	ByteString* contextBS = new ByteString((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::HEDGE_REQUIRED, *contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

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
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

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
	ByteString* contextBS = new ByteString((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, *contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	// And verify it
	CPPUNIT_ASSERT(slhdsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

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
	ByteString* contextBS = new ByteString((const unsigned char*)contextStr.c_str(), contextStr.size());

	SLHDSAMechanismParam context = SLHDSAMechanismParam(Hedge::Type::DETERMINISTIC_REQUIRED, *contextBS);

	// Sign the data
	ByteString sig;
	CPPUNIT_ASSERT(!slhdsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::SLHDSA, NULL, 0UL, &context));

	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleParameters(p);
}

#endif
