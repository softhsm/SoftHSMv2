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
	CPPUNIT_TEST_SUITE_END();

public:
	void testKeyGeneration();
	void testSerialisation();
	void testPKCS8();
	void testSigningVerifying();
	
	void setUp();
	void tearDown();

private:
	// MLDSA instance
	AsymmetricAlgorithm* mldsa;
};

#endif // !_SOFTHSM_V2_EDDSATESTS_H

