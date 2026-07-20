/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

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
	/** \brief The type */
	static const char* type;

	/** \brief Constructor */
	SLHDSAPublicKey();

	/** \brief Check if the key is of the given type */
	virtual bool isOfType(const char* inType);

	/** \brief Get the parameter set */
	virtual unsigned long getParameterSet() const;

	/** \brief Get the signature length */
	virtual unsigned long getOutputLength() const;

	/** \brief Get the bit length */
	virtual unsigned long getBitLength() const;

	/** \brief Setters for the SLH-DSA public key components */
	virtual void setValue(const ByteString& value);
	virtual void setParameterSet(unsigned long inParameterSet);

	/** \brief Getters for the SLH-DSA public key components */
	virtual const ByteString& getValue() const;

	/** \brief Serialisation */
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:

	/** \brief Public components */
	ByteString value;
	/** \brief Parameter set */
	unsigned long parameterSet;

};

#endif // !_SOFTHSM_V2_SLHDSAPUBLICKEY_H

