/*****************************************************************************
 SLHDSAParameters.h

 SLH-DSA parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSAPARAMETERS_H
#define _SOFTHSM_V2_SLHDSAPARAMETERS_H

#include "config.h"
#include "ByteString.h"
#include "AsymmetricParameters.h"


class SLHDSAParameters : public AsymmetricParameters
{
public:
	// The type
	static const char* type;

	// Get the SLH-DSA parameter set
	virtual unsigned long getParameterSet() const;

	// Setters for the SLH-DSA parameter set
	virtual void setParameterSet(const unsigned long parameterSet);

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	
	/* SLH-DSA values for CKA_PARAMETER_SETS */
	static const unsigned long SLH_DSA_SHA2_128S_PARAMETER_SET = CKP_SLH_DSA_SHA2_128S;
	static const unsigned long SLH_DSA_SHAKE_128S_PARAMETER_SET = CKP_SLH_DSA_SHAKE_128S;
	static const unsigned long SLH_DSA_SHA2_128F_PARAMETER_SET = CKP_SLH_DSA_SHA2_128F;
	static const unsigned long SLH_DSA_SHAKE_128F_PARAMETER_SET = CKP_SLH_DSA_SHAKE_128F;
	static const unsigned long SLH_DSA_SHA2_192S_PARAMETER_SET = CKP_SLH_DSA_SHA2_192S;
	static const unsigned long SLH_DSA_SHAKE_192S_PARAMETER_SET = CKP_SLH_DSA_SHAKE_192S;
	static const unsigned long SLH_DSA_SHA2_192F_PARAMETER_SET = CKP_SLH_DSA_SHA2_192F;
	static const unsigned long SLH_DSA_SHAKE_192F_PARAMETER_SET = CKP_SLH_DSA_SHAKE_192F;
	static const unsigned long SLH_DSA_SHA2_256S_PARAMETER_SET = CKP_SLH_DSA_SHA2_256S;
	static const unsigned long SLH_DSA_SHAKE_256S_PARAMETER_SET = CKP_SLH_DSA_SHAKE_256S;
	static const unsigned long SLH_DSA_SHA2_256F_PARAMETER_SET = CKP_SLH_DSA_SHA2_256F;
	static const unsigned long SLH_DSA_SHAKE_256F_PARAMETER_SET = CKP_SLH_DSA_SHAKE_256F;

	static const unsigned long SLH_DSA_SHA2_128S_PRIV_LENGTH = 64;
	static const unsigned long SLH_DSA_SHAKE_128S_PRIV_LENGTH = 64;
	static const unsigned long SLH_DSA_SHA2_128F_PRIV_LENGTH = 64;
	static const unsigned long SLH_DSA_SHAKE_128F_PRIV_LENGTH = 64;
	static const unsigned long SLH_DSA_SHA2_192S_PRIV_LENGTH = 96;
	static const unsigned long SLH_DSA_SHAKE_192S_PRIV_LENGTH = 96;
	static const unsigned long SLH_DSA_SHA2_192F_PRIV_LENGTH = 96;
	static const unsigned long SLH_DSA_SHAKE_192F_PRIV_LENGTH = 96;
	static const unsigned long SLH_DSA_SHA2_256S_PRIV_LENGTH = 128;
	static const unsigned long SLH_DSA_SHAKE_256S_PRIV_LENGTH = 128;
	static const unsigned long SLH_DSA_SHA2_256F_PRIV_LENGTH = 128;
	static const unsigned long SLH_DSA_SHAKE_256F_PRIV_LENGTH = 128;

	static const unsigned long SLH_DSA_SHA2_128S_PUB_LENGTH = 32;
	static const unsigned long SLH_DSA_SHAKE_128S_PUB_LENGTH = 32;
	static const unsigned long SLH_DSA_SHA2_128F_PUB_LENGTH = 32;
	static const unsigned long SLH_DSA_SHAKE_128F_PUB_LENGTH = 32;
	static const unsigned long SLH_DSA_SHA2_192S_PUB_LENGTH = 48;
	static const unsigned long SLH_DSA_SHAKE_192S_PUB_LENGTH = 48;
	static const unsigned long SLH_DSA_SHA2_192F_PUB_LENGTH = 48;
	static const unsigned long SLH_DSA_SHAKE_192F_PUB_LENGTH = 48;
	static const unsigned long SLH_DSA_SHA2_256S_PUB_LENGTH = 64;
	static const unsigned long SLH_DSA_SHAKE_256S_PUB_LENGTH = 64;
	static const unsigned long SLH_DSA_SHA2_256F_PUB_LENGTH = 64;
	static const unsigned long SLH_DSA_SHAKE_256F_PUB_LENGTH = 64;

	static const unsigned long SLH_DSA_SHA2_128S_SIGNATURE_LENGTH = 7856;
	static const unsigned long SLH_DSA_SHAKE_128S_SIGNATURE_LENGTH = 7856;
	static const unsigned long SLH_DSA_SHA2_128F_SIGNATURE_LENGTH = 17088;
	static const unsigned long SLH_DSA_SHAKE_128F_SIGNATURE_LENGTH = 17088;
	static const unsigned long SLH_DSA_SHA2_192S_SIGNATURE_LENGTH = 16224;
	static const unsigned long SLH_DSA_SHAKE_192S_SIGNATURE_LENGTH = 16224;
	static const unsigned long SLH_DSA_SHA2_192F_SIGNATURE_LENGTH = 35664;
	static const unsigned long SLH_DSA_SHAKE_192F_SIGNATURE_LENGTH = 35664;
	static const unsigned long SLH_DSA_SHA2_256S_SIGNATURE_LENGTH = 29792;
	static const unsigned long SLH_DSA_SHAKE_256S_SIGNATURE_LENGTH = 29792;
	static const unsigned long SLH_DSA_SHA2_256F_SIGNATURE_LENGTH = 49856;
	static const unsigned long SLH_DSA_SHAKE_256F_SIGNATURE_LENGTH = 49856;



private:
	unsigned long parameterSet = 0;

};

#endif // !_SOFTHSM_V2_SLHDSAPARAMETERS_H

