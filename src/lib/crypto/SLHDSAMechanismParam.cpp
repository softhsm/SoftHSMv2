/*****************************************************************************
 SLHDSAMechanismParam.cpp

 SLH-DSA mechanism parameters used for signing/verifying operations
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLH_DSA
#include "ByteString.h"
#include "MechanismParam.h"
#include "SLHDSAMechanismParam.h"

SLHDSAMechanismParam::SLHDSAMechanismParam() {
    this->hedgeType = Hedge::HEDGE_PREFERRED;
}

SLHDSAMechanismParam::SLHDSAMechanismParam(Hedge::Type hedgeType) {
    this->hedgeType = hedgeType;
}

SLHDSAMechanismParam::SLHDSAMechanismParam(Hedge::Type hedgeType, ByteString additionalContext) {
    this->hedgeType = hedgeType;
    this->additionalContext = additionalContext;
}

// Set the type
/*static*/ const char* SLHDSAMechanismParam::type = "SLH-DSA Signature param";

SLHDSAMechanismParam* SLHDSAMechanismParam::clone() const
{
    return new SLHDSAMechanismParam(static_cast<const SLHDSAMechanismParam&>(*this)); // call the copy ctor.
}

// Check if the parameter is of the given type
bool SLHDSAMechanismParam::isOfType(const char* inType) const
{
    return !strcmp(type, inType);
}
#endif