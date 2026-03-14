/*****************************************************************************
 MLDSAMechanismParam.cpp

 ML-DSA mechanism parameters used for signing/verifying operations
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "ByteString.h"
#include "MechanismParam.h"
#include "MLDSAMechanismParam.h"

MLDSAMechanismParam::MLDSAMechanismParam() {
    this->hedgeType = Hedge::HEDGE_PREFERRED;
}

MLDSAMechanismParam::MLDSAMechanismParam(Hedge::Type hedgeType) {
    this->hedgeType = hedgeType;
}

MLDSAMechanismParam::MLDSAMechanismParam(Hedge::Type hedgeType, ByteString additionalContext) {
    this->hedgeType = hedgeType;
    this->additionalContext = additionalContext;
}

// Set the type
/*static*/ const char* MLDSAMechanismParam::type = "ML-DSA Signature param";

MLDSAMechanismParam* MLDSAMechanismParam::clone() const
{
    return new MLDSAMechanismParam(static_cast<const MLDSAMechanismParam&>(*this)); // call the copy ctor.
}

// Check if the parameter is of the given type
bool MLDSAMechanismParam::isOfType(const char* inType) const
{
    return !strcmp(type, inType);
}
#endif