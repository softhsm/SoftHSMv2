/*****************************************************************************
 MLDSAMechanismParam.h

 ML-DSA mechanism parameters used for signing/verifying operations
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSAMECHANISMPARAM_H
#define _SOFTHSM_V2_MLDSAMECHANISMPARAM_H

#include "config.h"
#ifdef WITH_ML_DSA
#include "ByteString.h"
#include "MechanismParam.h"

struct Hedge
{
	enum Type
	{
		HEDGE_PREFERRED,
		HEDGE_REQUIRED,
		DETERMINISTIC_REQUIRED
	};
};

class MLDSAMechanismParam : public MechanismParam
{
	public:
	
		Hedge::Type hedgeType;
		ByteString additionalContext;

		// The type
		static const char* type;

		MLDSAMechanismParam();

		MLDSAMechanismParam(Hedge::Type hedgeType);

		MLDSAMechanismParam(Hedge::Type hedgeType, ByteString additionalContext);
		
		MLDSAMechanismParam* clone() const;

		// Check if the mechanism param is of the given type
		virtual bool isOfType(const char* inType) const;
};

#endif // !WITH_ML_DSA
#endif // !_SOFTHSM_V2_MLDSAMECHANISMPARAM_H

