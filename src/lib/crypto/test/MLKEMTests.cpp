/*****************************************************************************
 MLKEMTests.cpp

 Contains test cases to test the MLKEM class
 *****************************************************************************/

#include <stdlib.h>
#include <utility>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "MLKEMTests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "SymmetricKey.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#ifdef WITH_ML_KEM
#include "MLKEMParameters.h"
#include "MLKEMPublicKey.h"
#include "MLKEMPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(MLKEMTests);

static const std::vector<unsigned long> allParameterSets = {
	1UL, 2UL, 3UL
};

void MLKEMTests::setUp()
{
	mlKEM = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::MLKEM);

	// Check the ML-KEM object
	CPPUNIT_ASSERT(mlKEM != NULL);
}

void MLKEMTests::tearDown()
{
	if (mlKEM != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(mlKEM);
	}

	fflush(stdout);
}

void MLKEMTests::testKeyGeneration()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Set domain parameters
		MLKEMParameters* p = new MLKEMParameters();
		p->setParameterSet(parameterSet);

		// Generate key-pair
		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(mlKEM->generateKeyPair(&kp, p));

		MLKEMPublicKey* pub = (MLKEMPublicKey*) kp->getPublicKey();
		MLKEMPrivateKey* priv = (MLKEMPrivateKey*) kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getParameterSet() == parameterSet);
		CPPUNIT_ASSERT(priv->getParameterSet() == parameterSet);

		mlKEM->recycleParameters(p);
		mlKEM->recycleKeyPair(kp);
	}
}

void MLKEMTests::testSerialisation()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		MLKEMParameters* p = new MLKEMParameters();
		p->setParameterSet(parameterSet);

		// Serialise the parameters
		ByteString serialisedParams = p->serialise();

		// Deserialise the parameters
		AsymmetricParameters* dMLKEM;

		CPPUNIT_ASSERT(mlKEM->reconstructParameters(&dMLKEM, serialisedParams));

		CPPUNIT_ASSERT(dMLKEM->areOfType(MLKEMParameters::type));

		MLKEMParameters* ddMLKEM = (MLKEMParameters*) dMLKEM;

		CPPUNIT_ASSERT(p->getParameterSet() == ddMLKEM->getParameterSet());

		// Generate a key-pair
		AsymmetricKeyPair* kp;

		CPPUNIT_ASSERT(mlKEM->generateKeyPair(&kp, dMLKEM));

		// Serialise the key-pair
		ByteString serialisedKP = kp->serialise();

		CPPUNIT_ASSERT_GREATER((size_t) 0, serialisedKP.size());

		// Deserialise the key-pair
		AsymmetricKeyPair* dKP;

		CPPUNIT_ASSERT(mlKEM->reconstructKeyPair(&dKP, serialisedKP));

		// Check the deserialised key-pair
		MLKEMPrivateKey* privKey = (MLKEMPrivateKey*) kp->getPrivateKey();
		MLKEMPublicKey* pubKey = (MLKEMPublicKey*) kp->getPublicKey();

		MLKEMPrivateKey* dPrivKey = (MLKEMPrivateKey*) dKP->getPrivateKey();
		MLKEMPublicKey* dPubKey = (MLKEMPublicKey*) dKP->getPublicKey();

		CPPUNIT_ASSERT(privKey->getParameterSet() == dPrivKey->getParameterSet());
		CPPUNIT_ASSERT(privKey->getValue() == dPrivKey->getValue());
		CPPUNIT_ASSERT(privKey->getSeed() == dPrivKey->getSeed());

		CPPUNIT_ASSERT(pubKey->getParameterSet() == dPubKey->getParameterSet());
		CPPUNIT_ASSERT(pubKey->getValue() == dPubKey->getValue());

		mlKEM->recycleParameters(p);
		mlKEM->recycleParameters(dMLKEM);
		mlKEM->recycleKeyPair(kp);
		mlKEM->recycleKeyPair(dKP);
	}
}

void MLKEMTests::testPKCS8()
{
	for (const unsigned long parameterSet : allParameterSets)
	{
		// Get domain parameters
		MLKEMParameters* p = new MLKEMParameters();
		p->setParameterSet(parameterSet);

		// Generate a key-pair
		AsymmetricKeyPair* kp;

		CPPUNIT_ASSERT(mlKEM->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		MLKEMPrivateKey* priv = (MLKEMPrivateKey*) kp->getPrivateKey();
		CPPUNIT_ASSERT(priv != NULL);

		MLKEMPublicKey* pub = (MLKEMPublicKey*) kp->getPublicKey();
		CPPUNIT_ASSERT(pub != NULL);

		// Encode and decode the private key
		ByteString pkcs8 = priv->PKCS8Encode();
		CPPUNIT_ASSERT(pkcs8.size() != 0);

		MLKEMPrivateKey* dPriv = (MLKEMPrivateKey*) mlKEM->newPrivateKey();
		CPPUNIT_ASSERT(dPriv != NULL);

		CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

		CPPUNIT_ASSERT(priv->getParameterSet() == dPriv->getParameterSet());
		CPPUNIT_ASSERT(priv->getValue() == dPriv->getValue());

		mlKEM->recycleParameters(p);
		mlKEM->recyclePrivateKey(dPriv);
		mlKEM->recycleKeyPair(kp);
	}
}

void MLKEMTests::testEncapsulation()
{
	CPPUNIT_ASSERT(true);
	// Get domain parameters
	MLKEMParameters* p = new MLKEMParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(1UL);


	// Generate key-pair
	AsymmetricKeyPair* kp;
	CPPUNIT_ASSERT(mlKEM->generateKeyPair(&kp, p));

	ByteString cipherText;

	SymmetricKey* secretKey;
	CPPUNIT_ASSERT(mlKEM->encapsulate(kp->getPublicKey(), cipherText, &secretKey, (CK_KEY_TYPE) CKK_AES, AsymMech::MLKEM));

	mlKEM->recycleKeyPair(kp);
	mlKEM->recycleParameters(p);
	mlKEM->recycleSymmetricKey(secretKey);
}

void MLKEMTests::testEncapsulationDecapsulation()
{
	CPPUNIT_ASSERT(true);
	// Get domain parameters
	MLKEMParameters* p = new MLKEMParameters();
	CPPUNIT_ASSERT(p != NULL);
	p->setParameterSet(1UL);


	// Generate key-pair
	AsymmetricKeyPair* kp;
	CPPUNIT_ASSERT(mlKEM->generateKeyPair(&kp, p));

	ByteString cipherText;

	SymmetricKey* secretKeyEncap;
	SymmetricKey* secretKeyDecap;
	CPPUNIT_ASSERT(mlKEM->encapsulate(kp->getPublicKey(), cipherText, &secretKeyEncap, (CK_KEY_TYPE) CKK_AES, AsymMech::MLKEM));
	CPPUNIT_ASSERT(secretKeyEncap->getBitLen() > 0);
	CPPUNIT_ASSERT(cipherText.size() > 0);
	CPPUNIT_ASSERT(mlKEM->decapsulate(kp->getPrivateKey(), cipherText, &secretKeyDecap, (CK_KEY_TYPE) CKK_AES, AsymMech::MLKEM));
	CPPUNIT_ASSERT(secretKeyDecap->getBitLen() > 0);
	CPPUNIT_ASSERT_EQUAL(secretKeyEncap->getKeyCheckValue().hex_str(), secretKeyDecap->getKeyCheckValue().hex_str());

	mlKEM->recycleKeyPair(kp);
	mlKEM->recycleParameters(p);
	mlKEM->recycleSymmetricKey(secretKeyEncap);
	mlKEM->recycleSymmetricKey(secretKeyDecap);
}

#endif
