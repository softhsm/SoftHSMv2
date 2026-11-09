/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OSSLSHA3_256.cpp

 OpenSSL SHA3-256 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "OSSLSHA3_256.h"
#include <openssl/evp.h>

int OSSLSHA3_256::getHashSize()
{
	return 32;
}

const EVP_MD* OSSLSHA3_256::getEVPHash() const
{
	return EVP_sha3_256();
}
#endif
