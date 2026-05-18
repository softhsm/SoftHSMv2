/*****************************************************************************
 MechanismParam.h

 Mechanism parameters
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MECHANISMPARAM_H
#define _SOFTHSM_V2_MECHANISMPARAM_H

#include "config.h"

struct Hedge
{
	enum Type
	{
		HEDGE_PREFERRED,
		HEDGE_REQUIRED,
		DETERMINISTIC_REQUIRED
	};
};

class MechanismParam
{
public:

    // Check if the key is of the given type
    virtual bool isOfType(const char* inType) const = 0;

    virtual MechanismParam* clone() const = 0;
    virtual ~MechanismParam() {}
};

#endif // !_SOFTHSM_V2_MECHANISMPARAM_H