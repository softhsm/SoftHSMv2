/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
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

	/** \brief The Hedge Type */
	Hedge::Type hedgeType;
	/** \brief Additional Context */
	ByteString additionalContext;

	/** \brief The type */
	static const char* type;

	/** \brief Default constructor */
	SLHDSAMechanismParam();

	/** \brief Constructor with Hedge Type */
	SLHDSAMechanismParam(Hedge::Type hedgeType);

	/** \brief Constructor with Hedge Type and Additional Context */
	SLHDSAMechanismParam(Hedge::Type hedgeType, const ByteString& additionalContext);

	/** \brief Clone */
	virtual SLHDSAMechanismParam* clone() const override;

	/** \brief Check if the mechanism param is of the given type */
	virtual bool isOfType(const char* inType) const;
};

#endif // WITH_SLH_DSA
#endif // !_SOFTHSM_V2_SLHDSAMECHANISMPARAM_H

