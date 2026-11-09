/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 EncapDecapTests.cpp

 Contains test cases for C_EncapsulateKey and C_DecapsulateKey
 *****************************************************************************/

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include "EncapDecapTests.h"

#ifdef WITH_ML_KEM
const CK_BBOOL IN_SESSION = CK_FALSE;

const CK_BBOOL IS_PRIVATE = CK_TRUE;
const CK_BBOOL IS_PUBLIC = CK_FALSE;
#endif

CPPUNIT_TEST_SUITE_REGISTRATION(EncapDecapTests);

#ifdef WITH_ML_KEM
CK_RV EncapDecapTests::generateMLKEM(CK_ULONG parameterSet, CK_SESSION_HANDLE hSession, CK_BBOOL bTokenPuk, CK_BBOOL bPrivatePuk, CK_BBOOL bTokenPrk, CK_BBOOL bPrivatePrk, CK_OBJECT_HANDLE &hPuk, CK_OBJECT_HANDLE &hPrk)
{
	CK_MECHANISM mechanism = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_KEY_TYPE keyType = CKK_ML_KEM;
	CK_BYTE label[] = { 0x12, 0x34 }; // dummy
	CK_BYTE id[] = { 123 } ; // dummy
	CK_BBOOL bFalse = CK_FALSE;
	CK_BBOOL bTrue = CK_TRUE;

	CK_ATTRIBUTE pukAttribs[] = {
		{ CKA_PARAMETER_SET, &parameterSet, sizeof(parameterSet) },
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_ENCAPSULATE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &bTokenPuk, sizeof(bTokenPuk) },
		{ CKA_PRIVATE, &bPrivatePuk, sizeof(bPrivatePuk) }
	};
	CK_ATTRIBUTE prkAttribs[] = {
		{ CKA_LABEL, &label[0], sizeof(label) },
		{ CKA_ID, &id[0], sizeof(id) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_DECAPSULATE, &bTrue, sizeof(bFalse) },
		{ CKA_SENSITIVE, &bTrue, sizeof(bTrue) },
		{ CKA_TOKEN, &bTokenPrk, sizeof(bTokenPrk) },
		{ CKA_PRIVATE, &bPrivatePrk, sizeof(bPrivatePrk) },
		{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }
	};

	hPuk = CK_INVALID_HANDLE;
	hPrk = CK_INVALID_HANDLE;
	return CRYPTOKI_F_PTR( C_GenerateKeyPair(hSession, &mechanism,
						 pukAttribs, sizeof(pukAttribs)/sizeof(CK_ATTRIBUTE),
						 prkAttribs, sizeof(prkAttribs)/sizeof(CK_ATTRIBUTE),
						 &hPuk, &hPrk) );
}

void EncapDecapTests::testMLKEMEncapsulationDecapsulation(CK_ULONG parameterSet)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation - create a new AES key through encapsulation
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    CK_BYTE encapKCV[64];
    CK_ULONG encapKCVLen = sizeof(encapKCV);
    CK_ATTRIBUTE getEncapKCVAttrib = { CKA_CHECK_VALUE, encapKCV, encapKCVLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hEncapKey, &getEncapKCVAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    encapKCVLen = getEncapKCVAttrib.ulValueLen;

    // Test decapsulation - recover the shared secret using the ciphertext
    CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;

    CK_ATTRIBUTE decapKeyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = CRYPTOKI_F_PTR(C_DecapsulateKey(
        hSessionRW,
        &mechanism,
        hPrk,
        decapKeyAttribs,
        sizeof(decapKeyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        ulCipherTextLen,
        &hDecapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hDecapKey != CK_INVALID_HANDLE);

    // Verify that the decapsulated key has the same value as the encapsulated key
    CK_BYTE decapKCV[64];
    CK_ULONG decapKCVLen = sizeof(decapKCV);
    CK_ATTRIBUTE getDecapKCVAttrib = { CKA_CHECK_VALUE, decapKCV, decapKCVLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hDecapKey, &getDecapKCVAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    decapKCVLen = getDecapKCVAttrib.ulValueLen;

    CPPUNIT_ASSERT(encapKCVLen == decapKCVLen);
    CPPUNIT_ASSERT(memcmp(encapKCV, decapKCV, encapKCVLen) == 0);

    // Clean up
    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hEncapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hDecapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMEncapsulationCiphertextIsNull()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation - create a new AES key through encapsulation
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_ULONG ulCipherTextLen = sizeof(CK_ULONG);

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        NULL_PTR,  // Passing NULL_PTR for ciphertext to test behavior
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMDecapsulationCiphertextLengthIsZero()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation - create a new AES key through encapsulation
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    // Test decapsulation - recover the shared secret using the ciphertext
    CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;

    CK_ATTRIBUTE decapKeyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = CRYPTOKI_F_PTR(C_DecapsulateKey(
        hSessionRW,
        &mechanism,
        hPrk,
        decapKeyAttribs,
        sizeof(decapKeyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        0,  // Passing 0 for ciphertext length to test behavior
        &hDecapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);

    // Clean up
    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hEncapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMDecapsulationCiphertextIsNull()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation - create a new AES key through encapsulation
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    // Test decapsulation - recover the shared secret using the ciphertext
    CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;

    CK_ATTRIBUTE decapKeyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = CRYPTOKI_F_PTR(C_DecapsulateKey(
        hSessionRW,
        &mechanism,
        hPrk,
        decapKeyAttribs,
        sizeof(decapKeyAttribs) / sizeof(CK_ATTRIBUTE),
        NULL_PTR,  // Passing NULL_PTR for ciphertext to test behavior
        ulCipherTextLen,
        &hDecapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);

    // Clean up
    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hEncapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMEncapsulationDecapsulationWithValueLen(CK_ULONG ulValueLen)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRO;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Open read-only session on when the token is not initialized should fail
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-only session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSessionRO) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRO,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation with specific key length
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &ulValueLen, sizeof(ulValueLen) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hEncapKey != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen > 0);

    // Verify the decapsulated key has the correct length
    CK_ULONG encapKeyLength = 0;
    CK_ULONG encapKeyLengthLen = sizeof(encapKeyLength);
    CK_ATTRIBUTE getEncapKeyValueAttrib = { CKA_VALUE_LEN, &encapKeyLength, encapKeyLengthLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hEncapKey, &getEncapKeyValueAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(encapKeyLength == ulValueLen);

    // Get key check value for encapsulated key
    CK_BYTE encapKCV[64];
    CK_ULONG encapKCVLen = sizeof(encapKCV);
    CK_ATTRIBUTE getEncapKCVAttrib = { CKA_CHECK_VALUE, encapKCV, encapKCVLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hEncapKey, &getEncapKCVAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    encapKCVLen = getEncapKCVAttrib.ulValueLen;

    // Test decapsulation with specific key length
    CK_OBJECT_HANDLE hDecapKey = CK_INVALID_HANDLE;

    CK_ATTRIBUTE decapKeyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &ulValueLen, sizeof(ulValueLen) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    rv = CRYPTOKI_F_PTR(C_DecapsulateKey(
        hSessionRW,
        &mechanism,
        hPrk,
        decapKeyAttribs,
        sizeof(decapKeyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        ulCipherTextLen,
        &hDecapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hDecapKey != CK_INVALID_HANDLE);

    // Verify the decapsulated key has the correct length
    CK_ULONG decapKeyLength = 0;
    CK_ULONG decapKeyLengthLen = sizeof(decapKeyLength);
    CK_ATTRIBUTE getDecapKeyValueAttrib = { CKA_VALUE_LEN, &decapKeyLength, decapKeyLengthLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hDecapKey, &getDecapKeyValueAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(decapKeyLength == ulValueLen);

    // Get key check value for decapsulated key
    CK_BYTE decapKCV[64];
    CK_ULONG decapKCVLen = sizeof(decapKCV);
    CK_ATTRIBUTE getDecapKCVAttrib = { CKA_CHECK_VALUE, decapKCV, decapKCVLen };

    rv = CRYPTOKI_F_PTR(C_GetAttributeValue(hSessionRW, hDecapKey, &getDecapKCVAttrib, 1));
    CPPUNIT_ASSERT(rv == CKR_OK);
    decapKCVLen = getDecapKCVAttrib.ulValueLen;

    // Verify both keys have the same check values
    CPPUNIT_ASSERT(encapKCVLen == decapKCVLen);
    CPPUNIT_ASSERT(memcmp(encapKCV, decapKCV, encapKCVLen) == 0);

    // Clean up
    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hEncapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hDecapKey));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void EncapDecapTests::testMLKEMEncapsulationDecapsulationWithValueLenWrong()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSessionRW;
    CK_MECHANISM mechanism = { CKM_ML_KEM, NULL_PTR, 0 };
	CK_BBOOL bTrue = CK_TRUE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_ULONG parameterSet = CKP_ML_KEM_512;
    CK_ULONG ulValueLen = 10; // Intentionally incorrect value length for testing

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	// Initialize the library and start the test.
	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Open read-write session
	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionRW) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Login USER into the sessions so we can create a private objects
	rv = CRYPTOKI_F_PTR( C_Login(hSessionRW,CKU_USER,m_userPin1,m_userPin1Length) );
	CPPUNIT_ASSERT(rv==CKR_OK);

	CK_OBJECT_HANDLE hPuk = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE hPrk = CK_INVALID_HANDLE;

    // Generate ML-KEM key pair
    rv = generateMLKEM(parameterSet, hSessionRW, IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, hPuk, hPrk);
    CPPUNIT_ASSERT(rv == CKR_OK);
    CPPUNIT_ASSERT(hPuk != CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(hPrk != CK_INVALID_HANDLE);

    // Test encapsulation with specific key length
    CK_ATTRIBUTE keyAttribs[] = {
        { CKA_CLASS, &keyClass, sizeof(keyClass) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_VALUE_LEN, &ulValueLen, sizeof(ulValueLen) },
        { CKA_ENCRYPT, &bTrue, sizeof(bTrue) },
        { CKA_DECRYPT, &bTrue, sizeof(bTrue) }
    };

    CK_OBJECT_HANDLE hEncapKey = CK_INVALID_HANDLE;
    CK_BYTE cipherText[2048];
    CK_ULONG ulCipherTextLen = sizeof(cipherText);
    memset(cipherText, 0, sizeof(cipherText));

    rv = CRYPTOKI_F_PTR(C_EncapsulateKey(
        hSessionRW,
        &mechanism,
        hPuk,
        keyAttribs,
        sizeof(keyAttribs) / sizeof(CK_ATTRIBUTE),
        cipherText,
        &ulCipherTextLen,
        &hEncapKey
    ));
    CPPUNIT_ASSERT(rv == CKR_ATTRIBUTE_VALUE_INVALID);
    CPPUNIT_ASSERT(hEncapKey == CK_INVALID_HANDLE);
    CPPUNIT_ASSERT(ulCipherTextLen == 0);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPuk));
    CPPUNIT_ASSERT(rv == CKR_OK);

    rv = CRYPTOKI_F_PTR(C_DestroyObject(hSessionRW, hPrk));
    CPPUNIT_ASSERT(rv == CKR_OK);

	// Close the session
	rv = CRYPTOKI_F_PTR(C_CloseSession(hSessionRW));
	CPPUNIT_ASSERT(rv == CKR_OK);
}

#endif

#ifdef WITH_ML_KEM
void EncapDecapTests::testMLKEMGenericSecretCheckValue()
{
	CRYPTOKI_F_PTR(C_Finalize(NULL));
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_Initialize(NULL)));
	CK_SESSION_HANDLE session;
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session)));
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_Login(session, CKU_USER, m_userPin1, m_userPin1Length)));
	CK_OBJECT_HANDLE publicKey, privateKey;
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), generateMLKEM(CKP_ML_KEM_512, session,
		IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, publicKey, privateKey));
	CK_MECHANISM mechanism = {CKM_ML_KEM, NULL, 0};
	CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
	CK_KEY_TYPE type = CKK_GENERIC_SECRET;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	for (CK_ULONG length : {16, 24, 32})
	{
		CK_ATTRIBUTE attributes[] = {
			{CKA_CLASS, &objectClass, sizeof(objectClass)},
			{CKA_KEY_TYPE, &type, sizeof(type)},
			{CKA_VALUE_LEN, &length, sizeof(length)},
			{CKA_SENSITIVE, &no, sizeof(no)},
			{CKA_EXTRACTABLE, &yes, sizeof(yes)}
		};
		CK_BYTE ciphertext[2048];
		CK_ULONG ciphertextLength = sizeof(ciphertext);
		CK_OBJECT_HANDLE encapsulated = CK_INVALID_HANDLE, decapsulated = CK_INVALID_HANDLE;
		CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_ARGUMENTS_BAD), CRYPTOKI_F_PTR(C_EncapsulateKey(session,
			&mechanism, publicKey, attributes, 5, ciphertext, NULL, &encapsulated)));
		CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_EncapsulateKey(session,
			&mechanism, publicKey, attributes, 5, ciphertext, &ciphertextLength, &encapsulated)));
		CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_DecapsulateKey(session,
			&mechanism, privateKey, attributes, 5, ciphertext, ciphertextLength, &decapsulated)));
		CK_BYTE previousValue[32] = {0};
		for (CK_OBJECT_HANDLE key : {encapsulated, decapsulated})
		{
			CK_BYTE value[32], kcv[3], digest[20];
			CK_ATTRIBUTE result[] = {{CKA_VALUE, value, sizeof(value)}, {CKA_CHECK_VALUE, kcv, sizeof(kcv)}};
			CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_GetAttributeValue(session, key, result, 2)));
			CPPUNIT_ASSERT_EQUAL(length, result[0].ulValueLen);
			CPPUNIT_ASSERT_EQUAL(CK_ULONG(3), result[1].ulValueLen);
			CK_MECHANISM sha1 = {CKM_SHA_1, NULL, 0};
			CK_ULONG digestLength = sizeof(digest);
			CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_DigestInit(session, &sha1)));
			CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_Digest(session, value, length, digest, &digestLength)));
			CPPUNIT_ASSERT(memcmp(kcv, digest, sizeof(kcv)) == 0);
			if (key == encapsulated) memcpy(previousValue, value, length);
			else CPPUNIT_ASSERT(memcmp(previousValue, value, length) == 0);
			CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_DestroyObject(session, key)));
		}
	}
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_CloseSession(session)));
}

void EncapDecapTests::testMLKEMInvalidCheckValue()
{
	CRYPTOKI_F_PTR(C_Finalize(NULL));
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_Initialize(NULL)));
	CK_SESSION_HANDLE session;
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session)));
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_Login(session, CKU_USER, m_userPin1, m_userPin1Length)));
	CK_OBJECT_HANDLE publicKey, privateKey;
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), generateMLKEM(CKP_ML_KEM_512, session,
		IN_SESSION, IS_PUBLIC, IN_SESSION, IS_PRIVATE, publicKey, privateKey));
	CK_MECHANISM mechanism = {CKM_ML_KEM, NULL, 0};
	CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
	CK_KEY_TYPE type = CKK_GENERIC_SECRET;
	CK_BBOOL yes = CK_TRUE;
	CK_BYTE checkValue[3] = {1, 2, 3};
	CK_ATTRIBUTE attributes[] = {
		{CKA_CLASS, &objectClass, sizeof(objectClass)},
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_TOKEN, &yes, sizeof(yes)},
		{CKA_CHECK_VALUE, checkValue, sizeof(checkValue)}
	};
	CK_BYTE ciphertext[2048];
	CK_ULONG ciphertextLength = sizeof(ciphertext);
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_ATTRIBUTE_VALUE_INVALID), CRYPTOKI_F_PTR(C_EncapsulateKey(session,
		&mechanism, publicKey, attributes, 4, ciphertext, &ciphertextLength, &key)));
	CPPUNIT_ASSERT_EQUAL(CK_OBJECT_HANDLE(CK_INVALID_HANDLE), key);
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_EncapsulateKey(session,
		&mechanism, publicKey, attributes, 3, ciphertext, &ciphertextLength, &key)));
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_DestroyObject(session, key)));
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_ATTRIBUTE_VALUE_INVALID), CRYPTOKI_F_PTR(C_DecapsulateKey(session,
		&mechanism, privateKey, attributes, 4, ciphertext, ciphertextLength, &key)));
	CPPUNIT_ASSERT_EQUAL(CK_OBJECT_HANDLE(CK_INVALID_HANDLE), key);
	// Creating another token object proves the failed transaction released its lock.
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_DecapsulateKey(session,
		&mechanism, privateKey, attributes, 3, ciphertext, ciphertextLength, &key)));
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_DestroyObject(session, key)));
	CPPUNIT_ASSERT_EQUAL(CK_RV(CKR_OK), CRYPTOKI_F_PTR(C_CloseSession(session)));
}
#endif
