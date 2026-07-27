/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 RSAUtil.cpp

 RSA convenience functions
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "RSAUtil.h"
#include "RSAMechanismParam.h"

/*static*/ bool RSAUtil::checkPssParams(const MechanismParam* mechanismParam, HashAlgo::Type hashAlg,
					 AsymRSAMGF::Type mgfAlg, size_t digestSize, size_t keyBitLength,
					 size_t& sLen)
{
	if ((mechanismParam == NULL) || (!mechanismParam->isOfType(RSAPssMechanismParam::type)))
	{
		ERROR_MSG("Invalid RSA PSS mechanism parameter type supplied");
		return false;
	}
	const RSAPssMechanismParam* pssParam = dynamic_cast<const RSAPssMechanismParam*>(mechanismParam);
	if ((pssParam->hashAlg != hashAlg) || (pssParam->mgfAlg != mgfAlg))
	{
		ERROR_MSG("Invalid RSA PSS mechanism parameters supplied");
		return false;
	}
	sLen = pssParam->sLen;
	if (sLen > ((keyBitLength + 6) / 8 - 2 - digestSize))
	{
		ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
			  (unsigned long)sLen, keyBitLength);
		return false;
	}
	return true;
}
