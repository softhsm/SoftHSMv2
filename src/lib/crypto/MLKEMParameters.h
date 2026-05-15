/*****************************************************************************
 MLKEMParameters.h

 ML-KEM parameters (only used for key generation)
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMPARAMETERS_H
#define _SOFTHSM_V2_MLKEMPARAMETERS_H

#include "config.h"
#include "ByteString.h"
#include "AsymmetricParameters.h"


class MLKEMParameters : public AsymmetricParameters
{
public:
	MLKEMParameters() : parameterSet(0) {}
	// The type
	static const char* type;

	// Get the ML-KEM parameter set
	virtual unsigned long getParameterSet() const;

	// Setters for the ML-KEM parameter set
	virtual void setParameterSet(const unsigned long parameterSet);

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

	/* ML-KEM values for CKA_PARAMETER_SETS
	typedef CK_ULONG CK_ML_KEM_PARAMETER_SET_TYPE;
	#define CKP_ML_KEM_512          0x00000001UL
	#define CKP_ML_KEM_768          0x00000002UL
	#define CKP_ML_KEM_1024          0x00000003UL
	 */
	static const unsigned long ML_KEM_512_PARAMETER_SET = CKP_ML_KEM_512;
	static const unsigned long ML_KEM_768_PARAMETER_SET = CKP_ML_KEM_768;
	static const unsigned long ML_KEM_1024_PARAMETER_SET = CKP_ML_KEM_1024;

	/*
	From https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
	Table 2. Sizes (in bytes) of keys and ciphertexts of ML-KEM
						encapsulation key | decapsulation key | ciphertext | shared secret key
			ML-KEM-512       800          |       1632        |    768     |        32
			ML-KEM-768       1184         |       2400        |    1088    |        32
			ML-KEM-1024      1568         |       3168        |    1568    |        32
	*/
	
	static const unsigned long ML_KEM_512_PRIV_LENGTH = 1632;
	static const unsigned long ML_KEM_768_PRIV_LENGTH = 2400;
	static const unsigned long ML_KEM_1024_PRIV_LENGTH = 3168;

	static const unsigned long ML_KEM_512_PUB_LENGTH = 800;
	static const unsigned long ML_KEM_768_PUB_LENGTH = 1184;
	static const unsigned long ML_KEM_1024_PUB_LENGTH = 1568;

	static const unsigned long ML_KEM_512_CIPHERTEXT_LENGTH = 768;
	static const unsigned long ML_KEM_768_CIPHERTEXT_LENGTH = 1088;
	static const unsigned long ML_KEM_1024_CIPHERTEXT_LENGTH = 1568;

private:
	unsigned long parameterSet;

};

#endif // !_SOFTHSM_V2_MLKEMPARAMETERS_H

