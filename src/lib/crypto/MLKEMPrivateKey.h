/*****************************************************************************
 MLKEMPrivateKey.h

 ML-KEM private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMPRIVATEKEY_H
#define _SOFTHSM_V2_MLKEMPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"

class MLKEMPrivateKey : public PrivateKey
{
	public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the ML-KEM parameter set
	virtual unsigned long getParameterSet() const;

	// Get the ciphertext length
	virtual unsigned long getOutputLength() const;

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Setters for the ML-KEM private key components
	virtual void setValue(const ByteString& value);
	virtual void setSeed(const ByteString& seed);

	// Getters for the ML-KEM private key components
	virtual const ByteString& getValue() const;
	virtual const ByteString& getSeed() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
    
	ByteString value;
	ByteString seed;
};

#endif // !_SOFTHSM_V2_MLKEMPRIVATEKEY_H

