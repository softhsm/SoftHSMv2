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

	MutexFactory::i()->recycleMutex(handlesMutex);
}

CK_SESSION_HANDLE HandleManager::addSession(CK_SLOT_ID slotID, CK_VOID_PTR session)
{
	MutexLocker lock(handlesMutex);

	Handle h( CKH_SESSION, slotID );
	h.object = session;
	handles[++handleCounter] = h;
	slotHandles[slotID].insert(handleCounter);
	slotSessionCount[slotID]++;
	return (CK_SESSION_HANDLE)handleCounter;
}

CK_VOID_PTR HandleManager::getSession(const CK_SESSION_HANDLE hSession)
{
	MutexLocker lock(handlesMutex);

	std::map< CK_ULONG, Handle>::iterator it = handles.find(hSession);
	if (it == handles.end() || CKH_SESSION != it->second.kind)
		return NULL_PTR;
	return it->second.object;
}

CK_OBJECT_HANDLE HandleManager::addSessionObject(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession, bool isPrivate, CK_VOID_PTR object)
{
	MutexLocker lock(handlesMutex);

	// Return existing handle when the object has already been registered.
	std::map< CK_VOID_PTR, CK_ULONG>::iterator oit = objects.find(object);
	if (oit != objects.end()) {
		std::map< CK_ULONG, Handle>::iterator hit = handles.find(oit->second);
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
	return (CK_OBJECT_HANDLE)handleCounter;
}

CK_OBJECT_HANDLE HandleManager::addTokenObject(CK_SLOT_ID slotID, bool isPrivate, CK_VOID_PTR object)
{
	MutexLocker lock(handlesMutex);

	// Return existing handle when the object has already been registered.
	std::map< CK_VOID_PTR, CK_ULONG>::iterator oit = objects.find(object);
	if (oit != objects.end()) {
		std::map< CK_ULONG, Handle>::iterator hit = handles.find(oit->second);
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
	return (CK_OBJECT_HANDLE)handleCounter;
}

CK_VOID_PTR HandleManager::getObject(const CK_OBJECT_HANDLE hObject)
{
	MutexLocker lock(handlesMutex);

	std::map< CK_ULONG, Handle>::iterator it = handles.find(hObject);
	if (it == handles.end() || CKH_OBJECT != it->second.kind )
		return NULL_PTR;
	return it->second.object;
}

CK_OBJECT_HANDLE HandleManager::getObjectHandle(CK_VOID_PTR object)
{
	MutexLocker lock(handlesMutex);

	std::map< CK_VOID_PTR, CK_ULONG>::iterator it = objects.find(object);
	if (it == objects.end())
		return CK_INVALID_HANDLE;
	return it->second;
}

void HandleManager::destroyObject(const CK_OBJECT_HANDLE hObject)
{
	MutexLocker lock(handlesMutex);

	std::map< CK_ULONG, Handle>::iterator it = handles.find(hObject);
	if (it != handles.end() && CKH_OBJECT == it->second.kind) {
		// Remove from secondary indexes
		if (it->second.hSession != CK_INVALID_HANDLE)
			sessionObjectHandles[it->second.hSession].erase(hObject);
		slotHandles[it->second.slotID].erase(hObject);

		objects.erase(it->second.object);
		handles.erase(it);
	}
}

void HandleManager::sessionClosed(const CK_SESSION_HANDLE hSession)
{
	MutexLocker lock(handlesMutex);

	std::map< CK_ULONG, Handle>::iterator it = handles.find(hSession);
	if (it == handles.end() || CKH_SESSION != it->second.kind)
		return; // Unable to find the specified session.

	CK_SLOT_ID slotID = it->second.slotID;

	// session closed, so we can erase information about it.
	slotHandles[slotID].erase(hSession);
	handles.erase(it);

	// Erase all session object handles associated with the given session handle
	// using the secondary index instead of scanning the entire handles map.
	std::map< CK_SESSION_HANDLE, std::set<CK_ULONG> >::iterator soit = sessionObjectHandles.find(hSession);
	if (soit != sessionObjectHandles.end()) {
		std::set<CK_ULONG>& objHandles = soit->second;
		for (std::set<CK_ULONG>::iterator oit = objHandles.begin(); oit != objHandles.end(); ++oit) {
			std::map< CK_ULONG, Handle>::iterator hit = handles.find(*oit);
			if (hit != handles.end()) {
				objects.erase(hit->second.object);
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

	if (count > 0)
		return;

	// No more sessions open for this token, so remove all remaining object handles (token objects)
	// for the given slotID.
	slotSessionCount.erase(slotID);
	allSessionsClosed(slotID, true);
}

void HandleManager::allSessionsClosed(const CK_SLOT_ID slotID, bool isLocked)
{
	MutexLocker lock(isLocked ? NULL : handlesMutex);

	// Erase all "session", "session object" and "token object" handles for a given slot id
	// using the per-slot index instead of scanning the entire handles map.
	std::map< CK_SLOT_ID, std::set<CK_ULONG> >::iterator sit = slotHandles.find(slotID);
	if (sit != slotHandles.end()) {
		std::set<CK_ULONG>& handleSet = sit->second;
		for (std::set<CK_ULONG>::iterator it = handleSet.begin(); it != handleSet.end(); ++it) {
			std::map< CK_ULONG, Handle>::iterator hit = handles.find(*it);
			if (hit != handles.end()) {
				if (CKH_OBJECT == hit->second.kind)
					objects.erase(hit->second.object);
				if (CKH_SESSION == hit->second.kind)
					sessionObjectHandles.erase(*it);
				handles.erase(hit);
			}
		}
		slotHandles.erase(sit);
	}

	slotSessionCount.erase(slotID);
}

void HandleManager::tokenLoggedOut(const CK_SLOT_ID slotID)
{
	MutexLocker lock(handlesMutex);

	// Erase all private "token object" or "session object" handles for a given slot id
	// using the per-slot index instead of scanning the entire handles map.
	std::map< CK_SLOT_ID, std::set<CK_ULONG> >::iterator sit = slotHandles.find(slotID);
	if (sit == slotHandles.end())
		return;

	std::set<CK_ULONG>& handleSet = sit->second;
	for (std::set<CK_ULONG>::iterator it = handleSet.begin(); it != handleSet.end(); ) {
		std::map< CK_ULONG, Handle>::iterator hit = handles.find(*it);
		if (hit != handles.end() && CKH_OBJECT == hit->second.kind && hit->second.isPrivate) {
			// A private object is present for the given slotID so we need to remove it.
			objects.erase(hit->second.object);
			if (hit->second.hSession != CK_INVALID_HANDLE)
				sessionObjectHandles[hit->second.hSession].erase(*it);
			handles.erase(hit);
			handleSet.erase(it++);
			continue;
		}
		++it;
	}
}
