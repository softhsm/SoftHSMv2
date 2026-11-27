/*
 * Copyright (c) 2012 SURFnet bv
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
 HandleManagerTests.cpp

 Contains test cases to test the handle manager implementation
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "HandleManagerTests.h"
#include "OSObject.h"
#include "Session.h"

CPPUNIT_TEST_SUITE_REGISTRATION(HandleManagerTests);

namespace {

// Minimal OSObject for tests. We only need acquire()/release() to behave
// correctly and the pointer itself to serve as a unique identity.
class TestOSObject : public OSObject
{
public:
	TestOSObject(bool* inDeleted = NULL) : deleted(inDeleted) {}
	~TestOSObject() { if (deleted != NULL) *deleted = true; }

	bool attributeExists(CK_ATTRIBUTE_TYPE) { return false; }
	OSAttribute getAttribute(CK_ATTRIBUTE_TYPE) { abort(); }
	bool getBooleanValue(CK_ATTRIBUTE_TYPE, bool v) { return v; }
	unsigned long getUnsignedLongValue(CK_ATTRIBUTE_TYPE, unsigned long v) { return v; }
	ByteString getByteStringValue(CK_ATTRIBUTE_TYPE) { abort(); }
	CK_ATTRIBUTE_TYPE nextAttributeType(CK_ATTRIBUTE_TYPE) { return CKA_CLASS; }
	bool setAttribute(CK_ATTRIBUTE_TYPE, const OSAttribute&) { return true; }
	bool deleteAttribute(CK_ATTRIBUTE_TYPE) { return true; }
	bool isValid() { return true; }
	bool startTransaction(Access) { return true; }
	bool commitTransaction() { return true; }
	bool abortTransaction() { return true; }
	bool destroyObject() { return true; }

private:
	bool* deleted;
};

} // anonymous namespace

void HandleManagerTests::setUp()
{
	handleManager = new HandleManager();
}

void HandleManagerTests::tearDown()
{
	delete handleManager;
}

void HandleManagerTests::testHandleManager()
{
	CPPUNIT_ASSERT(handleManager != NULL);

	CK_SLOT_ID slotID = 1234;
	CK_SESSION_HANDLE hSession;
	CK_SESSION_HANDLE hSession2;
	CK_OBJECT_HANDLE hObject;
	CK_OBJECT_HANDLE hObject2;
	CK_OBJECT_HANDLE hObject3;
	CK_OBJECT_HANDLE hObject4;
	CK_OBJECT_HANDLE hObject5;

	// addSession() takes a reference to the session, so they must be real sessions
	Slot slot(NULL, slotID, NULL);
	Session* session  = new Session(&slot, false, NULL, NULL);
	Session* session2 = new Session(&slot, false, NULL, NULL);

	// Objects must be real OSObjects because addSessionObject acquires and
	// the cleanup paths release. Each starts at refcount=1.
	OSObject* object  = new TestOSObject();
	OSObject* object2 = new TestOSObject();
	OSObject* object3 = new TestOSObject();
	OSObject* object4 = new TestOSObject();
	OSObject* object5 = new TestOSObject();

	// Check session object management.
	hSession = handleManager->addSession(slotID, session);
	CPPUNIT_ASSERT(hSession != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session == handleManager->getSession(hSession).get());
	CPPUNIT_ASSERT_NO_THROW(handleManager->sessionClosed(123124));
	handleManager->sessionClosed(hSession);
	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession).get());

	// Add an object, hSession doesn't have to exist
	hObject = handleManager->addSessionObject(slotID, 4412412, true, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject).get());
	handleManager->sessionClosed(4412412);
	// Object still exists as the hSession was invalid
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject).get());
	handleManager->allSessionsClosed(slotID);
	// Object is now gone as all sessions for the given slotID have been removed.
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject).get());

	// Add an object and then destroy it.
	hObject = handleManager->addSessionObject(slotID, 4412412, true, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	handleManager->destroyObject(hObject);
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject).get());

	hObject = handleManager->addTokenObject(slotID, false, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	handleManager->destroyObject(hObject);
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject).get());

	// Create a valid session again
	hSession = handleManager->addSession(slotID, session);
	CPPUNIT_ASSERT(hSession != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session == handleManager->getSession(hSession).get());

	// Now some magic with a couple of objects
	hObject = handleManager->addTokenObject(slotID, false, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject).get());

	hObject2 = handleManager->addTokenObject(slotID, true, object2);
	CPPUNIT_ASSERT(hObject2 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object2 == handleManager->getObject(hObject2).get());

	hObject3 = handleManager->addTokenObject(slotID, true, object3);
	CPPUNIT_ASSERT(hObject3 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object3 == handleManager->getObject(hObject3).get());

	// Re-registering returns the same handle whether marked private or public.
	CPPUNIT_ASSERT(hObject2 == handleManager->addTokenObject(slotID, true, object2));
	CPPUNIT_ASSERT(hObject2 == handleManager->addTokenObject(slotID, false, object2));

	// Not allowed to migrate an object from one slot to another.
	CPPUNIT_ASSERT(CK_INVALID_HANDLE == handleManager->addTokenObject(124121, false, object2));

	hObject4 = handleManager->addSessionObject(slotID, hSession, true, object4);
	CPPUNIT_ASSERT(hObject4 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object4 == handleManager->getObject(hObject4).get());

	hObject5 = handleManager->addSessionObject(slotID, hSession, false, object5);
	CPPUNIT_ASSERT(hObject5 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(object5 == handleManager->getObject(hObject5).get());

	// Logout: private objects (both token and session) should be gone.
	handleManager->tokenLoggedOut(slotID);
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject).get()); // public token
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject2).get()); // private token
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject3).get()); // private token
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject4).get()); // private session
	CPPUNIT_ASSERT(object5 == handleManager->getObject(hObject5).get()); // public session

	hSession2 = handleManager->addSession(slotID, session2);
	CPPUNIT_ASSERT(hSession2 != CK_INVALID_HANDLE);
	CPPUNIT_ASSERT(session2 == handleManager->getSession(hSession2).get());

	handleManager->sessionClosed(hSession);
	CPPUNIT_ASSERT(object == handleManager->getObject(hObject).get()); // token object stays
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject5).get()); // session object gone

	// Closing the last session cascades into allSessionsClosed.
	handleManager->sessionClosed(hSession2);
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject).get());
	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession).get());
	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession2).get());

	// Bulk close
	hSession  = handleManager->addSession(slotID, session);
	hSession2 = handleManager->addSession(slotID, session2);
	handleManager->allSessionsClosed(slotID);
	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession).get());
	CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession2).get());

	// At this point HandleManager holds no references to any of our test
	// objects; refcount on each should be 1 (the "creating" ref we still own).
	// Release once to delete each.
	object->release();
	object2->release();
	object3->release();
	object4->release();
	object5->release();

	session->release();
	session2->release();
}

void HandleManagerTests::testObjectReference()
{
	CK_SLOT_ID slotID = 1234;
	CK_SESSION_HANDLE hSession;
	Slot slot(NULL, slotID, NULL);
	Session* session = new Session(&slot, false, NULL, NULL);

	// Session closed
	bool deleted = false;
	OSObject* object = new TestOSObject(&deleted);
	hSession = handleManager->addSession(slotID, session);
	CK_OBJECT_HANDLE hObject = handleManager->addSessionObject(slotID, hSession, false, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	{
		OSObjectRef ref = handleManager->getObject(hObject);
		CPPUNIT_ASSERT(ref == object);

		// Drop the handle manager and the owning reference
		handleManager->sessionClosed(hSession);
		CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject).get());
		object->release();

		CPPUNIT_ASSERT(!deleted);
		CPPUNIT_ASSERT(ref->isValid());
	}
	CPPUNIT_ASSERT(deleted);

	// Object destroyed
	deleted = false;
	object = new TestOSObject(&deleted);
	hSession = handleManager->addSession(slotID, session);
	hObject = handleManager->addSessionObject(slotID, hSession, false, object);
	CPPUNIT_ASSERT(hObject != CK_INVALID_HANDLE);
	{
		OSObjectRef ref = handleManager->getObject(hObject);
		OSObjectRef copy = ref;

		handleManager->destroyObject(hObject);
		object->release();
		CPPUNIT_ASSERT(!deleted);

		ref = OSObjectRef();
		CPPUNIT_ASSERT(NULL == ref.get());
		CPPUNIT_ASSERT(!deleted);
		CPPUNIT_ASSERT(copy == object);
	}
	CPPUNIT_ASSERT(deleted);

	// An unknown handle gives an empty reference
	CPPUNIT_ASSERT(NULL == handleManager->getObject(hObject).get());

	handleManager->sessionClosed(hSession);
}

// A reference returned by getSession() must keep the session alive when it is closed
// meanwhile and the session manager drops its reference.
void HandleManagerTests::testGetSessionKeepsSessionAlive()
{
	CK_SLOT_ID slotID = 1234;
	Slot slot(NULL, slotID, NULL);
	Session* session = new Session(&slot, true, NULL, NULL);

	CK_SESSION_HANDLE hSession = handleManager->addSession(slotID, session);
	CPPUNIT_ASSERT(hSession != CK_INVALID_HANDLE);

	{
		SessionRef ref = handleManager->getSession(hSession);
		CPPUNIT_ASSERT(session == ref);

		// What a concurrent C_CloseSession does: the handle manager and then the
		// session manager drop their references.
		handleManager->sessionClosed(hSession);
		session->release();
		CPPUNIT_ASSERT(NULL == handleManager->getSession(hSession).get());

		// Still usable, not freed yet
		CPPUNIT_ASSERT(ref->isRW());
	}
}
