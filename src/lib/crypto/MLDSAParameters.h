/*****************************************************************************
 MLDSAParameters.h

 ML-DSA parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSAPARAMETERS_H
#define _SOFTHSM_V2_MLDSAPARAMETERS_H

#include <tuple>
#include <stdexcept>
#include "config.h"
#include "ByteString.h"
#include "AsymmetricParameters.h"


class MLDSAParameters : public AsymmetricParameters
{
public:
	// The type
	static const char* type;

	// Get the ML-DSA parameter set
	virtual unsigned long getParameterSet() const;

	// Setters for the ML-DSA parameter set
	virtual void setParameterSet(const unsigned long parameterSet);

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	/* ML-DSA values for CKA_PARAMETER_SETS
	typedef CK_ULONG CK_ML_DSA_PARAMETER_SET_TYPE;
	#define CKP_ML_DSA_44          0x00000001UL
	#define CKP_ML_DSA_65          0x00000002UL
	#define CKP_ML_DSA_87          0x00000003UL
	 */
	static const unsigned long ML_DSA_44_PARAMETER_SET = CKP_ML_DSA_44;
	static const unsigned long ML_DSA_65_PARAMETER_SET = CKP_ML_DSA_65;
	static const unsigned long ML_DSA_87_PARAMETER_SET = CKP_ML_DSA_87;

	/*
	From https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
	Table 2. Sizes (in bytes) of keys and signatures of ML-DSA
						Private Key | Public Key | Signature Size
			ML-DSA-44      2560     |    1312    |     2420
			ML-DSA-65      4032     |    1952    |     3309
			ML-DSA-87      4896     |    2592    |     4627
	*/
	
	static const unsigned long ML_DSA_44_PRIV_LENGTH = 2560;
	static const unsigned long ML_DSA_65_PRIV_LENGTH = 4032;
	static const unsigned long ML_DSA_87_PRIV_LENGTH = 4896;

	static const unsigned long ML_DSA_44_PUB_LENGTH = 1312;
	static const unsigned long ML_DSA_65_PUB_LENGTH = 1952;
	static const unsigned long ML_DSA_87_PUB_LENGTH = 2592;

	static const unsigned long ML_DSA_44_SIGNATURE_LENGTH = 2420;
	static const unsigned long ML_DSA_65_SIGNATURE_LENGTH = 3309;
	static const unsigned long ML_DSA_87_SIGNATURE_LENGTH = 4627;


private:
	unsigned long parameterSet;

};

#endif // !_SOFTHSM_V2_MLDSAPARAMETERS_H

