/*****************************************************************************
 EDDSATests.cpp

 Contains test cases to test the EDDSA class
 *****************************************************************************/

#include <stdlib.h>
#include <utility>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "MLDSATests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#ifdef WITH_ML_DSA
#include "MLDSAParameters.h"
#include "MLDSAPublicKey.h"
#include "MLDSAPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(MLDSATests);

static const std::vector<unsigned long> allParameterSets = {
	1UL, 2UL, 3UL
};

void MLDSATests::setUp()
{
	mldsa = NULL;

	mldsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLDSA);

	// Check the EDDSA object
	CPPUNIT_ASSERT(mldsa != NULL);
}

void MLDSATests::tearDown()
{
	if (mldsa != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mldsa);
	}

	fflush(stdout);
}

void MLDSATests::testKeyGeneration()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Set domain parameters
		MLDSAParameters* p = new MLDSAParameters();
		p->setParameterSet(parameterSet);

		// Generate key-pair
		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(mldsa->generateKeyPair(&kp, p));

		MLDSAPublicKey* pub = (MLDSAPublicKey*) kp->getPublicKey();
		MLDSAPrivateKey* priv = (MLDSAPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getParameterSet() == parameterSet);
		CPPUNIT_ASSERT(priv->getParameterSet() == parameterSet);

		mldsa->recycleParameters(p);
		mldsa->recycleKeyPair(kp);
	}
}

void MLDSATests::testSerialisation()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		MLDSAParameters* p = new MLDSAParameters();
		p->setParameterSet(parameterSet);

		// Serialise the parameters
		ByteString serialisedParams = p->serialise();

		// Deserialise the parameters
		AsymmetricParameters* dMLDSA;

		CPPUNIT_ASSERT(mldsa->reconstructParameters(&dMLDSA, serialisedParams));

		CPPUNIT_ASSERT(dMLDSA->areOfType(MLDSAParameters::type));

		MLDSAParameters* ddMLDSA = (MLDSAParameters*) dMLDSA;

		CPPUNIT_ASSERT(p->getParameterSet() == ddMLDSA->getParameterSet());

		// Generate a key-pair
		AsymmetricKeyPair* kp;

		CPPUNIT_ASSERT(mldsa->generateKeyPair(&kp, dMLDSA));

		// Serialise the key-pair
		ByteString serialisedKP = kp->serialise();

		// Deserialise the key-pair
		AsymmetricKeyPair* dKP;

		CPPUNIT_ASSERT(mldsa->reconstructKeyPair(&dKP, serialisedKP));

		// Check the deserialised key-pair
		MLDSAPrivateKey* privKey = (MLDSAPrivateKey*) kp->getPrivateKey();
		MLDSAPublicKey* pubKey = (MLDSAPublicKey*) kp->getPublicKey();

		MLDSAPrivateKey* dPrivKey = (MLDSAPrivateKey*) dKP->getPrivateKey();
		MLDSAPublicKey* dPubKey = (MLDSAPublicKey*) dKP->getPublicKey();

		CPPUNIT_ASSERT(privKey->getParameterSet() == dPrivKey->getParameterSet());
		CPPUNIT_ASSERT(privKey->getValue() == dPrivKey->getValue());
		CPPUNIT_ASSERT(privKey->getSeed() == dPrivKey->getSeed());

		CPPUNIT_ASSERT(pubKey->getParameterSet() == dPubKey->getParameterSet());
		CPPUNIT_ASSERT(pubKey->getValue() == dPubKey->getValue());

		mldsa->recycleParameters(p);
		mldsa->recycleParameters(dMLDSA);
		mldsa->recycleKeyPair(kp);
		mldsa->recycleKeyPair(dKP);
	}
}

void MLDSATests::testPKCS8()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		MLDSAParameters* p = new MLDSAParameters();
		p->setParameterSet(parameterSet);

		// Generate a key-pair
		AsymmetricKeyPair* kp;

		CPPUNIT_ASSERT(mldsa->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		MLDSAPrivateKey* priv = (MLDSAPrivateKey*) kp->getPrivateKey();
		CPPUNIT_ASSERT(priv != NULL);

		MLDSAPublicKey* pub = (MLDSAPublicKey*) kp->getPublicKey();
		CPPUNIT_ASSERT(pub != NULL);

		// Encode and decode the private key
		ByteString pkcs8 = priv->PKCS8Encode();
		CPPUNIT_ASSERT(pkcs8.size() != 0);

		MLDSAPrivateKey* dPriv = (MLDSAPrivateKey*) mldsa->newPrivateKey();
		CPPUNIT_ASSERT(dPriv != NULL);

		CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

		CPPUNIT_ASSERT(priv->getParameterSet() == dPriv->getParameterSet());
		CPPUNIT_ASSERT(priv->getValue() == dPriv->getValue());

		mldsa->recycleParameters(p);
		mldsa->recyclePrivateKey(dPriv);
		mldsa->recycleKeyPair(kp);
	}
}

void MLDSATests::testSigningVerifying()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		MLDSAParameters* p = new MLDSAParameters();
		CPPUNIT_ASSERT(p != NULL);
		p->setParameterSet(parameterSet);


		// Generate key-pair
		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(mldsa->generateKeyPair(&kp, p));

		// Generate some data to sign
		ByteString dataToSign;

		RNG* rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

		// Sign the data
		ByteString sig;
		CPPUNIT_ASSERT(mldsa->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::MLDSA));

		// And verify it
		CPPUNIT_ASSERT(mldsa->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::MLDSA));

		mldsa->recycleKeyPair(kp);
		mldsa->recycleParameters(p);
	}
}

#endif
