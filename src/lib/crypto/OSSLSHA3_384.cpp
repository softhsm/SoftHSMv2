/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OSSLSHA3_384.cpp

 OpenSSL SHA3-384 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "OSSLSHA3_384.h"
#include <openssl/evp.h>

int OSSLSHA3_384::getHashSize()
{
	return 48;
}

const EVP_MD* OSSLSHA3_384::getEVPHash() const
{
	return EVP_sha3_384();
}
#endif
