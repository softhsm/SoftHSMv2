/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 OSSLSHA3_224.cpp

 OpenSSL SHA3-224 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "OSSLSHA3_224.h"
#include <openssl/evp.h>

int OSSLSHA3_224::getHashSize()
{
	return 28;
}

const EVP_MD* OSSLSHA3_224::getEVPHash() const
{
	return EVP_sha3_224();
}
#endif
