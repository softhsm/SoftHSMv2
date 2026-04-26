/*****************************************************************************
 SLHDSAPrivateKey.h

 SLH-DSA private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSAPRIVATEKEY_H
#define _SOFTHSM_V2_SLHDSAPRIVATEKEY_H

#include "config.h"
#include "PrivateKey.h"

class SLHDSAPrivateKey : public PrivateKey
{
	public:
 /** \brief The type */
	static const char* type;

 /** \brief Check if the key is of the given type */
	virtual bool isOfType(const char* inType);

 /** \brief Get the SLH-DSA parameter set */
	virtual unsigned long getParameterSet() const;

 /** \brief Get the signature length */
	virtual unsigned long getOutputLength() const;

 /** \brief Get the bit length */
	virtual unsigned long getBitLength() const;

 /** \brief Setters for the SLH-DSA private key components */
	virtual void setValue(const ByteString& value);
	virtual void setParameterSet(unsigned long inParameterSet);

 /** \brief Getters for the SLH-DSA private key components */
	virtual const ByteString& getValue() const;

 /** \brief Serialisation */
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
    
	ByteString value;
	unsigned long parameterSet = 0;
};

#endif // !_SOFTHSM_V2_SLHDSAPRIVATEKEY_H

