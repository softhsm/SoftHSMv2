/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*****************************************************************************
 BotanSHA3_224.cpp

 Botan SHA3-224 implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SHA3
#include "BotanSHA3_224.h"

int BotanSHA3_224::getHashSize()
{
	return 28;
}

const char* BotanSHA3_224::getHashName() const
{
	return "SHA-3(224)";
}
#endif
