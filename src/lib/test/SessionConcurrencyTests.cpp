/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 SessionConcurrencyTests.cpp

 Contains test cases for calls that overlap on one session
 *****************************************************************************/

#include <config.h>
#include <string.h>
#include <atomic>
#include <thread>
#include "SessionConcurrencyTests.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SessionConcurrencyTests);

// Two callers overlap their calls on one session, as an application does when it
// abandons a call that timed out and starts the next one. The calls may fail with
// CKR_OPERATION_ACTIVE or CKR_OPERATION_NOT_INITIALIZED, but they must not corrupt
// the operation state of the session: no crash, and a digest that is returned is
// the digest of the data.
//
// The library must be initialised with CKF_OS_LOCKING_OK: without locking the
// application promises not to call the library from several threads at once.
void SessionConcurrencyTests::testOverlappingDigestCalls()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	CK_C_INITIALIZE_ARGS initArgs;
	CK_MECHANISM mechanism = { CKM_SHA512, NULL_PTR, 0 };
	CK_BYTE data[] = {"Text to digest"};
	CK_BYTE expected[64];
	CK_ULONG expectedLen = sizeof(expected);

	memset(&initArgs, 0, sizeof(initArgs));
	initArgs.flags = CKF_OS_LOCKING_OK;

	// Just make sure that we finalize any previous tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(&initArgs) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// The digest without any overlap
	rv = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	rv = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, expected, &expectedLen) );
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(expectedLen == sizeof(expected));

	std::atomic<unsigned long> unexpected(0);
	std::atomic<unsigned long> completed(0);

	// CppUnit assertions are not thread safe, so the callers only count
	auto caller = [&]()
	{
		for (int i = 0; i < 5000; i++)
		{
			CK_BYTE digest[64];
			CK_ULONG digestLen = sizeof(digest);

			CK_RV r = CRYPTOKI_F_PTR( C_DigestInit(hSession, &mechanism) );
			if (r != CKR_OK && r != CKR_OPERATION_ACTIVE)
			{
				unexpected++;
				continue;
			}

			r = CRYPTOKI_F_PTR( C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen) );
			if (r == CKR_OK)
			{
				if (digestLen == expectedLen && memcmp(digest, expected, expectedLen) == 0)
					completed++;
				else
					unexpected++;
			}
			else if (r != CKR_OPERATION_NOT_INITIALIZED)
			{
				unexpected++;
			}
		}
	};

	std::thread first(caller);
	std::thread second(caller);
	first.join();
	second.join();

	CPPUNIT_ASSERT(unexpected == 0);
	CPPUNIT_ASSERT(completed > 0);

	rv = CRYPTOKI_F_PTR( C_CloseSession(hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}
