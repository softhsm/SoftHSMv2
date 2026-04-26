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
 SLHDSAUtil.h

 SLH-DSA convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSAUTIL_H
#define _SOFTHSM_V2_SLHDSAUTIL_H

#include "config.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAPrivateKey.h"
#include "SLHDSAPublicKey.h"
#include "SLHDSAParameters.h"
#include "SLHDSAMechanismParam.h"
#include "CryptoFactory.h"
#include "ByteString.h"
#include "Token.h"
#include "OSObject.h"

class SLHDSAUtil
{
public:
 /** \brief Delete constructor */
	SLHDSAUtil() = delete;
 /** \brief Get the private key */
	static CK_RV getSLHDSAPrivateKey(SLHDSAPrivateKey* privateKey, Token* token, OSObject* key);
 /** \brief Get the public key */
	static CK_RV getSLHDSAPublicKey(SLHDSAPublicKey* publicKey, Token* token, OSObject* key);

 /** \brief Set the private key */
	static CK_RV setSLHDSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate);

 /** \brief Set the hedge type */
	static CK_RV setHedge(CK_HEDGE_TYPE inHedgeType, Hedge::Type* outHedgeType);

};

#endif // WITH_SLH_DSA
#endif // !_SOFTHSM_V2_SLHDSAUTIL_H