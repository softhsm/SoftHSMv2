/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OSSLSHA3_512.cpp

 OpenSSL SHA3-512 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "OSSLSHA3_512.h"
#include <openssl/evp.h>

int OSSLSHA3_512::getHashSize()
{
	return 64;
}

const EVP_MD* OSSLSHA3_512::getEVPHash() const
{
	return EVP_sha3_512();
}
#endif
