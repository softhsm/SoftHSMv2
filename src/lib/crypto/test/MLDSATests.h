/*****************************************************************************
 MLDSATests.h

 Contains test cases to test the MLDSA class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSATESTS_H
#define _SOFTHSM_V2_MLDSATESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "AsymmetricAlgorithm.h"

class MLDSATests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(MLDSATests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testPKCS8);
	CPPUNIT_TEST(testSigningVerifying);
	CPPUNIT_TEST(testSigningTestVector);
	CPPUNIT_TEST(testSigningTestVectorEmptyContext);
	CPPUNIT_TEST(testSigningTestVectorNonEmptyContext);
	CPPUNIT_TEST(testSigningTestVectorLongestContext);
	CPPUNIT_TEST(testSigningTestVectorContextTooLong);
	CPPUNIT_TEST(testVerifyingTestVector);
	CPPUNIT_TEST(testVerifyingTestVectorEmptyContext);
	CPPUNIT_TEST(testVerifyingTestVectorNonEmptyContext);
	CPPUNIT_TEST(testVerifyingTestVectorLongestContext);
	CPPUNIT_TEST(testVerifyingTestVectorContextTooLong);
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
	void testKeyGeneration();
	void testSerialisation();
	void testPKCS8();
	void testSigningVerifying();
	void testSigningTestVector();
	void testSigningTestVectorEmptyContext();
	void testSigningTestVectorNonEmptyContext();
	void testSigningTestVectorLongestContext();
	void testSigningTestVectorContextTooLong();
	void testVerifyingTestVector();
	void testVerifyingTestVectorEmptyContext();
	void testVerifyingTestVectorNonEmptyContext();
	void testVerifyingTestVectorLongestContext();
	void testVerifyingTestVectorContextTooLong();
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
	// MLDSA instance
	AsymmetricAlgorithm* mldsa;
};

#endif // !_SOFTHSM_V2_MLDSATESTS_H

