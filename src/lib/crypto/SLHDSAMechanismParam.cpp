/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SLHDSAMechanismParam.cpp

 SLH-DSA mechanism parameters used for signing/verifying operations
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLH_DSA
#include "ByteString.h"
#include "MechanismParam.h"
#include "SLHDSAMechanismParam.h"
#include <cstring>

/** \brief SLHDSAMechanismParam */
SLHDSAMechanismParam::SLHDSAMechanismParam()
{
	this->hedgeType = Hedge::HEDGE_PREFERRED;
}

/** \brief SLHDSAMechanismParam */
SLHDSAMechanismParam::SLHDSAMechanismParam(Hedge::Type hedgeType)
{
	this->hedgeType = hedgeType;
}

/** \brief SLHDSAMechanismParam */
SLHDSAMechanismParam::SLHDSAMechanismParam(Hedge::Type hedgeType, const ByteString& additionalContext)
{
	this->hedgeType = hedgeType;
	this->additionalContext = additionalContext;
}

// Set the type
/*static*/ const char* SLHDSAMechanismParam::type = "SLH-DSA Signature param";

/** \brief clone */
SLHDSAMechanismParam* SLHDSAMechanismParam::clone() const
{
	return new SLHDSAMechanismParam(static_cast<const SLHDSAMechanismParam&>(*this)); // call the copy ctor.
}

// Check if the parameter is of the given type
/** \brief isOfType */
bool SLHDSAMechanismParam::isOfType(const char* inType) const
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}
#endif