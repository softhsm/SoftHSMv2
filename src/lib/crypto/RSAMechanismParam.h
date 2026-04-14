/*****************************************************************************
 RSAMechanismParam.h

 RSA mechanism parameters used for signing/verifying and encrypt/decrypt operations
 *****************************************************************************/

#ifndef _SOFTHSM_V2_RSAMECHANISMPARAM_H
#define _SOFTHSM_V2_RSAMECHANISMPARAM_H

#include "config.h"

#include "ByteString.h"
#include "HashAlgorithm.h"
#include "AsymmetricAlgorithm.h"
#include "MechanismParam.h"

// Limit OAEP label length to avoid overflow
#define MAX_RSA_OAEP_LABEL_LENGTH  0x0fffffff

// Mechanism parameter for RSA OAEP encryption
class RSAOaepMechanismParam : public MechanismParam
{
public:
    HashAlgo::Type hashAlg;
	AsymRSAMGF::Type mgfAlg;
	ByteString label;

	// The type
	static const char* type;

	RSAOaepMechanismParam();

	RSAOaepMechanismParam(HashAlgo::Type hashAlg,AsymRSAMGF::Type mgfAlg);

	RSAOaepMechanismParam(HashAlgo::Type hashAlg,AsymRSAMGF::Type mgfAlg,ByteString label);
	
	RSAOaepMechanismParam* clone() const;

	// Check if the mechanism param is of the given type
	virtual bool isOfType(const char* inType) const;
};

#endif // !_SOFTHSM_V2_RSAMECHANISMPARAM_H

