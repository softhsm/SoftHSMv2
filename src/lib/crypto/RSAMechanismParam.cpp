/*****************************************************************************
 RSAMechanismParam.cpp

 RSA mechanism parameters used for signing/verifying and OAEP encryption/decryption operations
 *****************************************************************************/

#include "config.h"

#include "ByteString.h"
#include "MechanismParam.h"
#include "RSAMechanismParam.h"

RSAOaepMechanismParam::RSAOaepMechanismParam() {
    
}

RSAOaepMechanismParam::RSAOaepMechanismParam(HashAlgo::Type hashAlg,AsymRSAMGF::Type mgfAlg) {
    this->hashAlg = hashAlg;
    this->mgfAlg = mgfAlg;
}

RSAOaepMechanismParam::RSAOaepMechanismParam(HashAlgo::Type hashAlg,AsymRSAMGF::Type mgfAlg,ByteString label) {
    this->hashAlg = hashAlg;
    this->mgfAlg = mgfAlg;
    this->label = label;
}

// Set the type
/*static*/ const char* RSAOaepMechanismParam::type = "RSA OAEP encryption param";

RSAOaepMechanismParam* RSAOaepMechanismParam::RSAOaepMechanismParam::clone() const
{
    return new RSAOaepMechanismParam(static_cast<const RSAOaepMechanismParam&>(*this)); // call the copy ctor.
}

// Check if the parameter is of the given type
bool RSAOaepMechanismParam::isOfType(const char* inType) const
{
    return !strcmp(type, inType);
}
