/*****************************************************************************
 MLKEMUtil.h

 ML-KEM convenience functions
 *****************************************************************************/

#ifndef _SOFTHSM_V2_MLKEMUTIL_H
#define _SOFTHSM_V2_MLKEMUTIL_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "MLKEMPrivateKey.h"
#include "MLKEMPublicKey.h"
#include "AsymmetricAlgorithm.h"
#include "CryptoFactory.h"
#include "ByteString.h"
#include "Token.h"
#include "OSObject.h"

class MLKEMUtil
{
public:
	static CK_RV getMLKEMPrivateKey(MLKEMPrivateKey* privateKey, Token* token, OSObject* key);
	static CK_RV getMLKEMPublicKey(MLKEMPublicKey* publicKey, Token* token, OSObject* key);

	static bool setMLKEMPrivateKey(OSObject* key, const ByteString &ber, Token* token, bool isPrivate);
};

#endif // !_SOFTHSM_V2_MLKEMUTIL_H
#endif