/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BotanSHA3_256.cpp

 Botan SHA3-256 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "BotanSHA3_256.h"

int BotanSHA3_256::getHashSize()
{
	return 32;
}

const char* BotanSHA3_256::getHashName() const
{
	return "SHA-3(256)";
}
#endif
