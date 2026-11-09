/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 RSAUtil.h

 RSA convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_RSAUTIL_H
#define _SOFTHSM_V2_RSAUTIL_H

#include "config.h"
#include "AsymmetricAlgorithm.h"
#include "HashAlgorithm.h"
#include "MechanismParam.h"

class RSAUtil
{
public:
	RSAUtil() = delete;

	// Validate an RSA-PSS mechanism parameter against the expected hash/MGF algorithm and
	// check that the requested salt length fits the key size. Returns the salt length in sLen
	// on success; logs an ERROR_MSG and returns false otherwise.
	static bool checkPssParams(const MechanismParam* mechanismParam, HashAlgo::Type hashAlg, AsymRSAMGF::Type mgfAlg, size_t digestSize, size_t keyBitLength, size_t& sLen);
};

#endif // !_SOFTHSM_V2_RSAUTIL_H
