/*****************************************************************************
 SLHDSAPublicKey.h

 SLH-DSA public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSAPUBLICKEY_H
#define _SOFTHSM_V2_SLHDSAPUBLICKEY_H

#include "config.h"
#include "PublicKey.h"
#include "ByteString.h"

class SLHDSAPublicKey : public PublicKey
{
public:
	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the parameter set
	virtual unsigned long getParameterSet() const;

	// Get the signature length
	virtual unsigned long getOutputLength() const;

	// Get the bit length
	virtual unsigned long getBitLength() const;

	virtual void setValue(const ByteString& value);
	virtual void setParameterSet(unsigned long inParameterSet);

	// Getters for the SLH-DSA public key components
	virtual const ByteString& getValue() const;

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
    
	// Public components
	ByteString value;
	unsigned long parameterSet = 0;

};

#endif // !_SOFTHSM_V2_SLHDSAPUBLICKEY_H

