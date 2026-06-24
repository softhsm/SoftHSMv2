/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 SLHDSATests.h

 Contains test cases to test the SLH-DSA class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSATESTS_H
#define _SOFTHSM_V2_SLHDSATESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "AsymmetricAlgorithm.h"

class SLHDSATests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(SLHDSATests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testPKCS8);
	CPPUNIT_TEST(testSigningVerifying);

	CPPUNIT_TEST(testSigningVerifyingHedgePreferred);
	CPPUNIT_TEST(testSigningVerifyingHedgePreferredWithContext);
	CPPUNIT_TEST(testSigningVerifyingHedgePreferredWithContextTooLong);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequired);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequiredWithContext);
	CPPUNIT_TEST(testSigningVerifyingHedgeRequiredWithContextTooLong);
	CPPUNIT_TEST(testSigningVerifyingDeterministic);
	CPPUNIT_TEST(testSigningVerifyingDeterministicWithContext);
	CPPUNIT_TEST(testSigningVerifyingDeterministicWithContextTooLong);
	CPPUNIT_TEST_SUITE_END();

public:
	SLHDSATests();

	void testKeyGeneration();
	void testSerialisation();
	void testPKCS8();
	void testSigningVerifying();

	void testSigningVerifyingHedgePreferred();
	void testSigningVerifyingHedgePreferredWithContext();
	void testSigningVerifyingHedgePreferredWithContextTooLong();
	void testSigningVerifyingHedgeRequired();
	void testSigningVerifyingHedgeRequiredWithContext();
	void testSigningVerifyingHedgeRequiredWithContextTooLong();
	void testSigningVerifyingDeterministic();
	void testSigningVerifyingDeterministicWithContext();
	void testSigningVerifyingDeterministicWithContextTooLong();

	void setUp();
	void tearDown();

private:
	// SLHDSA instance
	AsymmetricAlgorithm* slhdsa;
};

#endif // !_SOFTHSM_V2_SLHDSATESTS_H

