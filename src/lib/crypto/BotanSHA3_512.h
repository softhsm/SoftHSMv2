/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BotanSHA3_512.h

 Botan SHA3-512 implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANSHA3_512_H
#define _SOFTHSM_V2_BOTANSHA3_512_H

#include "config.h"
#include "BotanHashAlgorithm.h"
#include <botan/hash.h>

class BotanSHA3_512 : public BotanHashAlgorithm
{
	virtual int getHashSize();
protected:
	virtual const char* getHashName() const;
};

#endif // !_SOFTHSM_V2_BOTANSHA3_512_H
