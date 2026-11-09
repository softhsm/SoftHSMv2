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
 HandleManager.cpp

 One of the most difficult problems to track down is when stale cryptoki handles
 for e.g. keys, objects and sessions get reused by a misbehaving application.
 Especialy when handles that became invalid have since been reused.
 A simple solution to this is to never reuse a handle once it has been issued
 and subsequently invalidated.

 The handle manager tracks issued handles along with what kind of object
 is presented by the handle and an actual pointer to the object in question.

 Issued handles are unique per application run. All session and object handles
 use the same handle manager and therefore there will never be e.g. a session
 with the same handle as an object.

 *****************************************************************************/

#include "HandleManager.h"
#include "log.h"

// Constructor
HandleManager::HandleManager()
{
	handlesMutex = MutexFactory::i()->getMutex();
	handleCounter = 0;
}

// Destructor
HandleManager::~HandleManager()
{
	// Safety net to release any session-object handles that weren't explicitly cleaned up.
	// In normal C_Finalize flow this should be empty.
	for (auto& kv : handles)
	{
		if (kv.second.kind == CKH_OBJECT && kv.second.hSession != CK_INVALID_HANDLE)
		{
			WARNING_MSG("Session object handle %lu (session %lu) was not released before "
				"HandleManager destruction; releasing now",
				kv.first, kv.second.hSession);
			kv.second.object->release();
		}
	}

	MutexFactory::i()->recycleMutex(handlesMutex);
}

CK_SESSION_HANDLE HandleManager::addSession(CK_SLOT_ID slotID, Session *session)
{
	MutexLocker lock(handlesMutex);

	Handle h( CKH_SESSION, slotID );
	h.session = session;
	handles[++handleCounter] = h;
	slotHandles[slotID].insert(handleCounter);
	slotSessionCount[slotID]++;
	return (CK_SESSION_HANDLE)handleCounter;
}

Session *HandleManager::getSession(const CK_SESSION_HANDLE hSession)
{
	MutexLocker lock(handlesMutex);

	std::map< CK_ULONG, Handle>::iterator it = handles.find(hSession);
	if (it == handles.end() || CKH_SESSION != it->second.kind)
		return nullptr;
	return it->second.session;
}

CK_OBJECT_HANDLE HandleManager::addSessionObject(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession, bool isPrivate, OSObject *object)
{
	MutexLocker lock(handlesMutex);

	// Return existing handle when the object has already been registered.
	auto oit = objects.find(object);
	if (oit != objects.end()) {
		auto hit = handles.find(oit->second);
		if (hit == handles.end() || CKH_OBJECT != hit->second.kind || slotID != hit->second.slotID) {
			objects.erase(oit);
			return CK_INVALID_HANDLE;
		} else
			return oit->second;
	}

	Handle h( CKH_OBJECT, slotID, hSession );
	h.isPrivate = isPrivate;
	h.object = object;
	handles[++handleCounter] = h;
	objects[object] = handleCounter;

	sessionObjectHandles[hSession].insert(handleCounter);
	slotHandles[slotID].insert(handleCounter);

	object->acquire();

	DEBUG_MSG("Added session object - handle: %lu, slot ID: %lu, session ID: %lu, private: %d, obj: %p",
		handleCounter, slotID, hSession, isPrivate, object);

	return (CK_OBJECT_HANDLE)handleCounter;
}

CK_OBJECT_HANDLE HandleManager::addTokenObject(CK_SLOT_ID slotID, bool isPrivate, OSObject *object)
{
	MutexLocker lock(handlesMutex);

	// Return existing handle when the object has already been registered.
	auto oit = objects.find(object);
	if (oit != objects.end()) {
		auto hit = handles.find(oit->second);
		if (hit == handles.end() || CKH_OBJECT != hit->second.kind || slotID != hit->second.slotID) {
			objects.erase(oit);
			return CK_INVALID_HANDLE;
		} else
			return oit->second;
	}

	// Token objects are not associated with a specific session.
	Handle h( CKH_OBJECT, slotID );
	h.isPrivate = isPrivate;
	h.object = object;
	handles[++handleCounter] = h;
	objects[object] = handleCounter;

	slotHandles[slotID].insert(handleCounter);

	DEBUG_MSG("Added token object - handle: %lu, slot ID: %lu, private: %d, obj: %p",
		handleCounter, slotID, isPrivate, object);

	return (CK_OBJECT_HANDLE)handleCounter;
}

OSObject *HandleManager::getObject(const CK_OBJECT_HANDLE hObject)
{
	MutexLocker lock(handlesMutex);

	auto it = handles.find(hObject);
	if (it == handles.end() || CKH_OBJECT != it->second.kind )
		return nullptr;
	return it->second.object;
}

CK_OBJECT_HANDLE HandleManager::getObjectHandle(OSObject *object)
{
	MutexLocker lock(handlesMutex);

	auto it = objects.find(object);
	if (it == objects.end())
		return CK_INVALID_HANDLE;
	return it->second;
}

void HandleManager::destroyObject(const CK_OBJECT_HANDLE hObject)
{
	OSObject* toRelease = NULL;
	{
		MutexLocker lock(handlesMutex);

		auto it = handles.find(hObject);
		if (it != handles.end() && CKH_OBJECT == it->second.kind) {
			// Remove from secondary indexes
			if (it->second.hSession != CK_INVALID_HANDLE) {
				sessionObjectHandles[it->second.hSession].erase(hObject);
				toRelease = it->second.object;
			}
			slotHandles[it->second.slotID].erase(hObject);

			objects.erase(it->second.object);
			handles.erase(it);
			DEBUG_MSG("Destroyed object handle: %lu", hObject);
		} else {
			DEBUG_MSG("Cannot destroy handle %lu that is not found or not an object handle", hObject);
		}
	}
	if (toRelease != NULL)
		toRelease->release();
}

void HandleManager::sessionClosed(const CK_SESSION_HANDLE hSession)
{
	std::set<OSObject*> toRelease;

	{
		MutexLocker lock(handlesMutex);

		std::map< CK_ULONG, Handle>::iterator it = handles.find(hSession);
		if (it == handles.end() || CKH_SESSION != it->second.kind)
		{
			DEBUG_MSG("Session %lu not found and cannot be closed", hSession);
			return; // Unable to find the specified session.
		}
		CK_SLOT_ID slotID = it->second.slotID;

		// session closed, so we can erase information about it.
		slotHandles[slotID].erase(hSession);
		handles.erase(it);

		DEBUG_MSG("Session %lu (slot %lu) closed", hSession, slotID);

		// Erase all session object handles associated with the given session handle
		// using the secondary index instead of scanning the entire handles map.
		auto soit = sessionObjectHandles.find(hSession);
		if (soit != sessionObjectHandles.end()) {
			std::set<CK_ULONG>& objHandles = soit->second;
			for (auto oit = objHandles.begin(); oit != objHandles.end(); ++oit) {
				auto hit = handles.find(*oit);
				if (hit != handles.end()) {
					toRelease.insert(hit->second.object);
					objects.erase(hit->second.object);
					DEBUG_MSG("Erasing object %lu for closed session %lu", hit->first, hSession);
					slotHandles[slotID].erase(*oit);
					handles.erase(hit);
				}
			}
			sessionObjectHandles.erase(soit);
		}

		// Use the session counter to check if there are remaining open sessions.
		CK_ULONG& count = slotSessionCount[slotID];
		if (count > 0)
			count--;

		if (count == 0)
			allSessionsClosed(slotID, true);
	}

	for (auto* obj : toRelease)
		obj->release();
}

void HandleManager::allSessionsClosed(const CK_SLOT_ID slotID, bool isLocked)
{
	std::set<OSObject*> toRelease;

	DEBUG_MSG("Closing all sessions for slot %lu", slotID);

	{
		MutexLocker lock(isLocked ? NULL : handlesMutex);

		// Erase all "session", "session object" and "token object" handles for a given slot id
		// using the per-slot index instead of scanning the entire handles map.
		auto sit = slotHandles.find(slotID);
		if (sit != slotHandles.end()) {
			auto& handleSet = sit->second;
			for (auto it = handleSet.begin(); it != handleSet.end(); ++it) {
				auto hit = handles.find(*it);
				if (hit != handles.end()) {
					if (CKH_OBJECT == hit->second.kind) {
						DEBUG_MSG("Erasing object %lu for empty slot %lu", hit->first, slotID);
						if (hit->second.hSession != CK_INVALID_HANDLE)
							toRelease.insert(hit->second.object);
						objects.erase(hit->second.object);
					}
					if (CKH_SESSION == hit->second.kind)
						sessionObjectHandles.erase(*it);
					handles.erase(hit);
				}
			}
			slotHandles.erase(sit);
		}

		slotSessionCount.erase(slotID);
	}

	for (auto* obj : toRelease)
		obj->release();
}

void HandleManager::tokenLoggedOut(const CK_SLOT_ID slotID)
{
	std::set<OSObject*> toRelease;
	{
		MutexLocker lock(handlesMutex);

		// Erase all private "token object" or "session object" handles for a given slot id
		// using the per-slot index instead of scanning the entire handles map.
		auto sit = slotHandles.find(slotID);
		if (sit == slotHandles.end())
			return;

		auto& handleSet = sit->second;
		for (auto it = handleSet.begin(); it != handleSet.end(); ) {
			auto hit = handles.find(*it);
			if (hit != handles.end() && CKH_OBJECT == hit->second.kind && hit->second.isPrivate) {
				// A private object is present for the given slotID so we need to remove it.
				DEBUG_MSG("Erasing private object %lu for logged out token slot %lu", hit->first, slotID);
				if (hit->second.hSession != CK_INVALID_HANDLE) {
					sessionObjectHandles[hit->second.hSession].erase(*it);
					toRelease.insert(hit->second.object);
				}
				objects.erase(hit->second.object);
				handles.erase(hit);
				handleSet.erase(it++);
				continue;
			}
			++it;
		}
	}


	for (auto* obj : toRelease)
		obj->release();
}
