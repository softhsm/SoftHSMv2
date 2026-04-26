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
 SLHDSAMechanismParam.h

 SLH-DSA mechanism parameters used for signing/verifying operations
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSAMECHANISMPARAM_H
#define _SOFTHSM_V2_SLHDSAMECHANISMPARAM_H

#include "config.h"
#ifdef WITH_SLH_DSA
#include "ByteString.h"
#include "MechanismParam.h"


class SLHDSAMechanismParam : public MechanismParam
{
public:

	Hedge::Type hedgeType;
	ByteString additionalContext;

 /** \brief The type */
	static const char* type;

	SLHDSAMechanismParam();

	SLHDSAMechanismParam(Hedge::Type hedgeType);

	SLHDSAMechanismParam(Hedge::Type hedgeType, ByteString additionalContext);
	
	SLHDSAMechanismParam* clone() const;

 /** \brief Check if the mechanism param is of the given type */
	virtual bool isOfType(const char* inType) const;
};

#endif // WITH_SLH_DSA
#endif // !_SOFTHSM_V2_SLHDSAMECHANISMPARAM_H

