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
 SessionManager.h

 Keeps track of the sessions within SoftHSM
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SESSIONMANAGER_H
#define _SOFTHSM_V2_SESSIONMANAGER_H

#include "Slot.h"
#include "Session.h"
#include "MutexFactory.h"
#include "config.h"
#include "cryptoki.h"
#include <memory>
#include <vector>

class SessionManager
{
public:
	SessionManager();

	virtual ~SessionManager();

	// When pSession is given it receives a reference to the new session. A caller must
	// use it instead of looking the session up by handle: the handle (an index) can be
	// reused by another session as soon as a concurrent close has freed it.
	CK_RV openSession(Slot* slot, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession, SessionRef* pSession = NULL);
	CK_RV closeSession(CK_SESSION_HANDLE hSession);
	// Close this very session. A caller that holds a session must close it with this
	// instead of by handle: the handle (an index) may meanwhile belong to a newer
	// session, which must not be closed (and its token logged out) by mistake.
	CK_RV closeSession(Session* session);
	CK_RV closeAllSessions(Slot* slot);
	CK_RV getSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
	// Returns a reference to the session; it is empty when there is no such session
	SessionRef getSession(CK_SESSION_HANDLE hSession);
	bool haveSession(CK_SLOT_ID slotID);
	bool haveROSession(CK_SLOT_ID slotID);

private:
	// The sessions
	std::vector<Session*> sessions;
	Mutex* sessionsMutex;

	// Close the session with the given handle; when expected is given only if it is
	// that very session
	CK_RV closeSessionChecked(CK_SESSION_HANDLE hSession, Session* expected);
};

#endif // !_SOFTHSM_V2_SESSIONMANAGER_H

