/*****************************************************************************
 OSSLMLKEM.h

 OpenSSL ML-KEM asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSSLMLKEM_H
#define _SOFTHSM_V2_OSSLMLKEM_H

#include "config.h"
#include "AsymmetricAlgorithm.h"
#include "AESKey.h"
#include <openssl/evp.h>

class OSSLMLKEM : public AsymmetricAlgorithm
{
public:
	// Destructor
	virtual ~OSSLMLKEM() { }

	// Signing functions
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0, const MechanismParam* mechanismParam = NULL);
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0, const MechanismParam* mechanismParam = NULL);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0, const MechanismParam* mechanismParam = NULL);
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0, const MechanismParam* mechanismParam = NULL);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(const ByteString& signature);

	// Encryption functions
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding,
    		 const MechanismParam* mechanismParam = NULL);

	// Encapsulate/Decapsulate functions
	virtual bool encapsulate(PublicKey* publicKey, ByteString& cipherText, SymmetricKey** secretKey, CK_KEY_TYPE keyType, const AsymMech::Type mechanism);
	virtual bool decapsulate(PrivateKey* privateKey, const ByteString& cipherText, SymmetricKey** secretKey, CK_KEY_TYPE keyType, const AsymMech::Type mechanism);

	// Decryption functions
	virtual bool checkEncryptedDataSize(PrivateKey* privateKey, const ByteString& encryptedData, int* errorCode);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding,
    	     const MechanismParam* mechanismParam = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();

	// Key factory
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData);
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData);
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData);
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();
	virtual AsymmetricParameters* newParameters();

private:
};

#endif // !_SOFTHSM_V2_OSSLEDKEM_H

