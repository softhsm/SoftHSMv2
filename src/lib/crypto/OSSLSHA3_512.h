/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OSSLSHA3_512.h

 OpenSSL SHA3-512 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLSHA3_512_H
#define _SOFTHSM_V2_OSSLSHA3_512_H

#include "config.h"
#include "OSSLEVPHashAlgorithm.h"
#include <openssl/evp.h>

class OSSLSHA3_512 : public OSSLEVPHashAlgorithm
{
	virtual int getHashSize();
protected:
	virtual const EVP_MD* getEVPHash() const;
};

#endif // !_SOFTHSM_V2_OSSLSHA3_512_H
