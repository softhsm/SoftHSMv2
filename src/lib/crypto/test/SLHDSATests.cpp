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
 SLHDSATests.cpp

 Contains test cases to test the SLHDSA class
 *****************************************************************************/

#include "SLHDSATests.h"
#include "AsymmetricAlgorithm.h"
#include "AsymmetricKeyPair.h"
#include "CryptoFactory.h"
#include "RNG.h"
#ifdef WITH_SLHDSA
#include "SLHParameters.h"
#include "SLHPrivateKey.h"
#include "SLHPublicKey.h"
#include <cppunit/extensions/HelperMacros.h>
#include <stdlib.h>
#include <utility>
#include <vector>

CPPUNIT_TEST_SUITE_REGISTRATION(SLHDSATests);

void SLHDSATests::setUp() {
  slhdsa = NULL;

  slhdsa = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::SLHDSA);

  // Check the SLHDSA object
  CPPUNIT_ASSERT(slhdsa != NULL);
}

void SLHDSATests::tearDown() {
  if (slhdsa != NULL) {
    CryptoFactory::i()->recycleAsymmetricAlgorithm(slhdsa);
  }

  fflush(stdout);
}

void SLHDSATests::testKeyGeneration() {
  // slhdsa_names to test
  std::vector<ByteString> slhdsa_names;
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHA2-128s", 18));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHAKE-128s", 20));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHA2-128f", 18));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHAKE-128f", 20));

  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHA2-192s", 18));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHAKE-192s", 20));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHA2-192f", 18));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHAKE-192f", 20));

  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHA2-256s", 18));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHAKE-256s", 20));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHA2-256f", 18));
  slhdsa_names.push_back(
      ByteString((const unsigned char *)"SLH-DSA-SHAKE-256f", 20));

  for (auto c = slhdsa_names.begin(); c != slhdsa_names.end(); c++) {
    AsymmetricKeyPair *kp;
    SLHParameters *p = new SLHParameters();
    p->setName(*c);

    // Generate key-pair
    CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));

    SLHPublicKey *pub = (SLHPublicKey *)kp->getPublicKey();
    SLHPrivateKey *priv = (SLHPrivateKey *)kp->getPrivateKey();

    CPPUNIT_ASSERT(pub->getDerPublicKey() != ByteString(""));
    CPPUNIT_ASSERT(priv->getDerPrivateKey() != ByteString(""));

    slhdsa->recycleParameters(p);
    slhdsa->recycleKeyPair(kp);
  }
}

void SLHDSATests::testSerialisation()
{
	SLHParameters* p = new SLHParameters;
	p->setName(ByteString((const unsigned char *) "SLH-DSA-SHA2-192f", 18));

	// Serialise the parameters
	ByteString serialisedParams = p->serialise();

	// Deserialise the parameters
	AsymmetricParameters* dName;

	CPPUNIT_ASSERT(slhdsa->reconstructParameters(&dName, serialisedParams));

	CPPUNIT_ASSERT(dName->areOfType(SLHParameters::type));

	SLHParameters* ddName = (SLHParameters*) dName;

	CPPUNIT_ASSERT(p->getName() == ddName->getName());

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, dName));

	// Serialise the key-pair
	ByteString serialisedKP = kp->serialise();

	// Deserialise the key-pair
	AsymmetricKeyPair* dKP;

	CPPUNIT_ASSERT(slhdsa->reconstructKeyPair(&dKP, serialisedKP));

	// Check the deserialised key-pair
	SLHPrivateKey* privKey = (SLHPrivateKey*) kp->getPrivateKey();
	SLHPublicKey* pubKey = (SLHPublicKey*) kp->getPublicKey();

	SLHPrivateKey* dPrivKey = (SLHPrivateKey*) dKP->getPrivateKey();
	SLHPublicKey* dPubKey = (SLHPublicKey*) dKP->getPublicKey();

	CPPUNIT_ASSERT(privKey->getDerPrivateKey() == dPrivKey->getDerPrivateKey());

	CPPUNIT_ASSERT(pubKey->getDerPublicKey() == dPubKey->getDerPublicKey());

	slhdsa->recycleParameters(p);
	slhdsa->recycleParameters(dName);
	slhdsa->recycleKeyPair(kp);
	slhdsa->recycleKeyPair(dKP);
}

void SLHDSATests::testPKCS8()
{
	SLHParameters* p = new SLHParameters;
	p->setName(ByteString((const unsigned char *) "SLH-DSA-SHA2-192f", 18));

	// Generate a key-pair
	AsymmetricKeyPair* kp;

	CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));
	CPPUNIT_ASSERT(kp != NULL);

	SLHPrivateKey* priv = (SLHPrivateKey*) kp->getPrivateKey();
	CPPUNIT_ASSERT(priv != NULL);

	// Encode and decode the private key
	ByteString pkcs8 = priv->PKCS8Encode();
	CPPUNIT_ASSERT(pkcs8.size() != 0);

	SLHPrivateKey* dPriv = (SLHPrivateKey*) slhdsa->newPrivateKey();
	CPPUNIT_ASSERT(dPriv != NULL);

	CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

	CPPUNIT_ASSERT(priv->getDerPrivateKey() == dPriv->getDerPrivateKey());

	slhdsa->recycleParameters(p);
	slhdsa->recycleKeyPair(kp);
	slhdsa->recyclePrivateKey(dPriv);
}

void SLHDSATests::testSigningVerifying()
{
  // slhdsa_names to test
  std::vector<ByteString> slhdsa_names;
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHA2-128s", 18));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHAKE-128s", 20));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHA2-128f", 18));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHAKE-128f", 20));

  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHA2-192s", 18));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHAKE-192s", 20));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHA2-192f", 18));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHAKE-192f", 20));

  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHA2-256s", 18));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHAKE-256s", 20));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHA2-256f", 18));
  slhdsa_names.push_back(ByteString((const unsigned char *)"SLH-DSA-SHAKE-256f", 20));

  for (auto c = slhdsa_names.begin(); c != slhdsa_names.end(); c++) {
    AsymmetricKeyPair *kp;
    SLHParameters *p = new SLHParameters();
    p->setName(*c);

    // Generate key-pair
    CPPUNIT_ASSERT(slhdsa->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(p != NULL);

		// Generate some data to sign
		ByteString dataToSign;

		RNG* rng = CryptoFactory::i()->getRNG();
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
#endif
