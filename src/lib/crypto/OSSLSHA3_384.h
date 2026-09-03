/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OSSLSHA3_384.h

 OpenSSL SHA3-384 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSHA3_384_H
#define _SOFTHSM_V2_OSSLSHA3_384_H

#include "config.h"
#include "OSSLEVPHashAlgorithm.h"
#include <openssl/evp.h>

class OSSLSHA3_384 : public OSSLEVPHashAlgorithm
{
	virtual int getHashSize();
protected:
	virtual const EVP_MD* getEVPHash() const;
};

#endif // !_SOFTHSM_V2_OSSLSHA3_384_H
