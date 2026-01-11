/*****************************************************************************
 MLDSAPrivateKey.h

 ML-DSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSAPRIVATEKEY_H
#define _SOFTHSM_V2_MLDSAPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"

class MLDSAPrivateKey : public PrivateKey
{
	public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the ML-DSA parameter set
	virtual unsigned long getParameterSet() const;

	// Get the signature length
	virtual unsigned long getOutputLength() const;

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Setters for the ML-DSA private key components
	virtual void setValue(const ByteString& value);
	virtual void setSeed(const ByteString& seed);

	// Getters for the ML-DSA private key components
	virtual const ByteString& getValue() const;
	virtual const ByteString& getSeed() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
    
	ByteString value;
	ByteString seed;
};

#endif // !_SOFTHSM_V2_MLDSAPRIVATEKEY_H

