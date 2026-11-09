/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BotanSHA3_512.cpp

 Botan SHA3-512 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "BotanSHA3_512.h"

int BotanSHA3_512::getHashSize()
{
	return 64;
}

const char* BotanSHA3_512::getHashName() const
{
	return "SHA-3(512)";
}
#endif
