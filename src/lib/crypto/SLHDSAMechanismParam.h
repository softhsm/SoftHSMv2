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

#endif // !WITH_SLH_DSA
#endif // !_SOFTHSM_V2_SLHDSAMECHANISMPARAM_H

