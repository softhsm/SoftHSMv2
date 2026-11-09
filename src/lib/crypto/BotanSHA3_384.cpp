/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BotanSHA3_384.cpp

 Botan SHA3-384 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "BotanSHA3_384.h"

int BotanSHA3_384::getHashSize()
{
	return 48;
}

const char* BotanSHA3_384::getHashName() const
{
	return "SHA-3(384)";
}
#endif
