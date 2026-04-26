/*****************************************************************************
 SLHDSAUtil.h

 SLH-DSA convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SLHDSAUTIL_H
#define _SOFTHSM_V2_SLHDSAUTIL_H

#include "config.h"
#ifdef WITH_SLH_DSA
#include "SLHDSAPrivateKey.h"
#include "SLHDSAPublicKey.h"
#include "SLHDSAParameters.h"
#include "SLHDSAMechanismParam.h"
#include "CryptoFactory.h"
#include "ByteString.h"
#include "Token.h"
#include "OSObject.h"

class SLHDSAUtil
{
public:
	SLHDSAUtil() = delete;
	static CK_RV getSLHDSAPrivateKey(SLHDSAPrivateKey* privateKey, Token* token, OSObject* key);
	static CK_RV getSLHDSAPublicKey(SLHDSAPublicKey* publicKey, Token* token, OSObject* key);

	static bool setSLHDSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate);

	static CK_RV setHedge(CK_HEDGE_TYPE inHedgeType, Hedge::Type* outHedgeType);

};

#endif // WITH_SLH_DSA
#endif // !_SOFTHSM_V2_SLHDSAUTIL_H