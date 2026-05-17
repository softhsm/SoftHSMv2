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
 SessionObjectStore.cpp

 The token class; a token is stored in a directory containing several files.
 Each object is stored in a separate file and a token object is present that
 has the token specific attributes
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSAttributes.h"
#include "OSAttribute.h"
#include "SessionObject.h"
#include "cryptoki.h"
#include "SessionObjectStore.h"
#include <vector>
#include <string>
#include <set>
#include <map>
#include <list>

// Constructor
SessionObjectStore::SessionObjectStore()
{
	storeMutex = MutexFactory::i()->getMutex();
}

// Destructor
SessionObjectStore::~SessionObjectStore()
{
	// Clean up
	objects.clear();
	std::set<SessionObject*> cleanUp = allObjects;
	allObjects.clear();

	for (auto* obj : cleanUp)
	{
		if (obj == NULL) continue;
		obj->release();
	}

	MutexFactory::i()->recycleMutex(storeMutex);
}

int SessionObjectStore::getObjectCount()
{
    return objects.size();
}

void SessionObjectStore::getObjects(std::set<OSObject*> &inObjects)
{
    // Make sure that no other thread is in the process of changing
    // the object list when we return it
    MutexLocker lock(storeMutex);

    std::set<SessionObject*>::iterator it;
    for (it=objects.begin(); it!=objects.end(); ++it) {
        inObjects.insert(*it);
    }
}

void SessionObjectStore::getObjects(CK_SLOT_ID slotID, std::set<OSObject*> &inObjects)
{
	// Make sure that no other thread is in the process of changing
	// the object list when we return it
	MutexLocker lock(storeMutex);

	std::set<SessionObject*>::iterator it;
	for (it=objects.begin(); it!=objects.end(); ++it) {
		if ((*it)->hasSlotID(slotID))
			inObjects.insert(*it);
	}
}

// Create a new object
SessionObject* SessionObjectStore::createObject(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession, bool isPrivate)
{
	// Create the new object file
	SessionObject* newObject = new SessionObject(this, slotID, hSession, isPrivate);

	if (!newObject->isValid())
	{
		ERROR_MSG("Failed to create new object");

		delete newObject;

		return NULL;
	}

	// Now add it to the set of objects
	MutexLocker lock(storeMutex);

	objects.insert(newObject);
	allObjects.insert(newObject);

	DEBUG_MSG("(0x%08X) Created new object (0x%08X)", this, newObject);

	return newObject;
}

// Delete an object
bool SessionObjectStore::deleteObject(SessionObject* object)
{
	SessionObject* toRelease = NULL;
	{
		MutexLocker lock(storeMutex);
		if (objects.find(object) == objects.end())
		{
			ERROR_MSG("Cannot delete non-existent object 0x%08X", object);
			return false;
		}
		object->invalidate();
		objects.erase(object);
		allObjects.erase(object);
		toRelease = object;
	}
	if (toRelease)
	{
		toRelease->release();
	}
	return true;
}

// Indicate that a session has been closed - remove all its objects
void SessionObjectStore::sessionClosed(CK_SESSION_HANDLE hSession)
{
	std::set<SessionObject*> toRelease;
	{
		MutexLocker lock(storeMutex);
		for (auto it = objects.begin(); it != objects.end(); ) {
			if ((*it)->removeOnSessionClose(hSession))
			{
				toRelease.insert(*it);
				allObjects.erase(*it);
				it = objects.erase(it);
			}
			else
			{
				++it;
			}
		}
	}
	for (auto* obj : toRelease)
	{
		obj->release();
	}
}

void SessionObjectStore::allSessionsClosed(CK_SLOT_ID slotID)
{
		std::set<SessionObject*> toRelease;
		{
			MutexLocker lock(storeMutex);
			for (auto it = objects.begin(); it != objects.end(); ) {
				if ((*it)->removeOnAllSessionsClose(slotID))
				{
					toRelease.insert(*it);
					allObjects.erase(*it);
					it = objects.erase(it);
				}
				else
				{
					++it;
				}
			}
		}
	for (auto* obj : toRelease)
	{
		obj->release();
	}
}

void SessionObjectStore::tokenLoggedOut(CK_SLOT_ID slotID)
{
	std::set<SessionObject*> toRelease;
	{
		MutexLocker lock(storeMutex);
		for (auto it = objects.begin(); it != objects.end(); ) {
			if ((*it)->removeOnTokenLogout(slotID)) {
				toRelease.insert(*it);
				allObjects.erase(*it);
				it = objects.erase(it);
			}
			else
			{
				++it;
			}
		}
	}
	for (auto* obj : toRelease)
	{
		obj->release();
	}
}

// Clear the whole store
void SessionObjectStore::clearStore()
{
	std::set<SessionObject*> clearObjects;
	{
		MutexLocker lock(storeMutex);
		objects.clear();
		clearObjects.swap(allObjects);
	}
	for (auto* obj : clearObjects)
	{
		obj->release();
	}
}
