/*****************************************************************************
 MLDSAPublicKey.h

 ML-DSA public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSAPUBLICKEY_H
#define _SOFTHSM_V2_MLDSAPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"

class MLDSAPublicKey : public PublicKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the bit length
	virtual unsigned long getParameterSet() const;

	// Get the signature length
	virtual unsigned long getOutputLength() const;

	// Get the bit length
	virtual unsigned long getBitLength() const;

	virtual void setValue(const ByteString& value);

	// Getters for the ML-DSA public key components
	virtual const ByteString& getValue() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
    
	// Public components
	ByteString value;
};

#endif // !_SOFTHSM_V2_MLDSAPUBLICKEY_H

