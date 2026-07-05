/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 EDDSAUtil.cpp

 EdDSA convenience functions
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "EDDSAUtil.h"
#include "log.h"

// Maximum context data length allowed by CK_EDDSA_PARAMS
static const CK_ULONG maxEddsaContextDataLen = 255;

/*static*/ CK_RV EDDSAUtil::getEddsaParam(CK_MECHANISM_PTR pMechanism, EDDSAMechanismParam& eddsaParam, MechanismParam** mechanismParam)
{
	if (pMechanism->pParameter == NULL_PTR)
	{
		if (pMechanism->ulParameterLen != 0)
		{
			ERROR_MSG("EDDSA: No parameters supplied but ulParameterLen is %lu", (unsigned long) pMechanism->ulParameterLen);
			return CKR_ARGUMENTS_BAD;
		}

		// No parameters means the pure variant without context data
		return CKR_OK;
	}

	if (pMechanism->ulParameterLen != sizeof(CK_EDDSA_PARAMS))
	{
		ERROR_MSG("EDDSA: ulParameterLen is %lu, expected %lu", (unsigned long) pMechanism->ulParameterLen, (unsigned long) sizeof(CK_EDDSA_PARAMS));
		return CKR_ARGUMENTS_BAD;
	}

	CK_EDDSA_PARAMS* ckEddsaParams = (CK_EDDSA_PARAMS*) pMechanism->pParameter;

	if (ckEddsaParams->ulContextDataLen > maxEddsaContextDataLen)
	{
		ERROR_MSG("EDDSA: ulContextDataLen is %lu, maximum is %lu", (unsigned long) ckEddsaParams->ulContextDataLen, (unsigned long) maxEddsaContextDataLen);
		return CKR_ARGUMENTS_BAD;
	}

	if (ckEddsaParams->ulContextDataLen > 0 && ckEddsaParams->pContextData == NULL_PTR)
	{
		ERROR_MSG("EDDSA: ulContextDataLen is %lu but pContextData is NULL", (unsigned long) ckEddsaParams->ulContextDataLen);
		return CKR_ARGUMENTS_BAD;
	}

	eddsaParam.flag = (ckEddsaParams->phFlag != CK_FALSE);
	if (ckEddsaParams->ulContextDataLen > 0)
	{
		eddsaParam.contextData = ByteString(ckEddsaParams->pContextData, ckEddsaParams->ulContextDataLen);
	}

	DEBUG_MSG("EDDSA: preHash=%s, contextDataLen=%lu", eddsaParam.flag ? "true" : "false", (unsigned long) eddsaParam.contextData.size());

	*mechanismParam = &eddsaParam;

	return CKR_OK;
}
#endif
