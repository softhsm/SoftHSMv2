/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BotanSHA3_256.h

 Botan SHA3-256 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANSHA3_256_H
#define _SOFTHSM_V2_BOTANSHA3_256_H

#include "config.h"
#include "BotanHashAlgorithm.h"
#include <botan/hash.h>

class BotanSHA3_256 : public BotanHashAlgorithm
{
	virtual int getHashSize();
protected:
	virtual const char* getHashName() const;
};

#endif // !_SOFTHSM_V2_BOTANSHA3_256_H
