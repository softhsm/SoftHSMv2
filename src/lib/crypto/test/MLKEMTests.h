/*****************************************************************************
 MLKEMTests.h

 Contains test cases to test the MLKEM class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMTESTS_H
#define _SOFTHSM_V2_MLKEMTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "AsymmetricAlgorithm.h"

class MLKEMTests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(MLKEMTests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testPKCS8);
	CPPUNIT_TEST(testEncapsulation);
	CPPUNIT_TEST(testEncapsulationDecapsulation);
	CPPUNIT_TEST_SUITE_END();

public:
	MLKEMTests() : mlKEM(NULL) {}
	void testKeyGeneration();
	void testSerialisation();
	void testPKCS8();
	void testEncapsulation();
	void testEncapsulationDecapsulation();
	
	void setUp();
	void tearDown();

private:
	// MLKEM instance
	AsymmetricAlgorithm* mlKEM;
};

#endif // !_SOFTHSM_V2_MLKEMTESTS_H

