/*****************************************************************************
 MLDSAUtil.h

 ML-DSA convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLDSAUTIL_H
#define _SOFTHSM_V2_MLDSAUTIL_H

#include "config.h"
#ifdef WITH_ML_DSA
#include "MLDSAPrivateKey.h"
#include "MLDSAPublicKey.h"
#include "AsymmetricAlgorithm.h"
#include "CryptoFactory.h"
#include "ByteString.h"
#include "Token.h"
#include "OSObject.h"

class MLDSAUtil
{
public:
	static CK_RV getMLDSAPrivateKey(MLDSAPrivateKey* privateKey, Token* token, OSObject* key);
	static CK_RV getMLDSAPublicKey(MLDSAPublicKey* publicKey, Token* token, OSObject* key);

	static bool setMLDSAPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate);
};

#endif // WITH_ML_DSA
#endif // !_SOFTHSM_V2_MLDSAUTIL_H