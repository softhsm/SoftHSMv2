/*****************************************************************************
 OSSLMLKEMPrivateKey.cpp

 OpenSSL ML-KEM private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "log.h"
#include "OSSLMLKEMPrivateKey.h"
#include "MLKEMParameters.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

// Constructors
OSSLMLKEMPrivateKey::OSSLMLKEMPrivateKey()
{
	pkey = NULL;
}

OSSLMLKEMPrivateKey::OSSLMLKEMPrivateKey(const EVP_PKEY* inMLKEMKEY)
{
	pkey = NULL;

	setFromOSSL(inMLKEMKEY);
}

// Destructor
OSSLMLKEMPrivateKey::~OSSLMLKEMPrivateKey()
{
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

OSSLMLKEMPrivateKey::OSSLMLKEMPrivateKey(OSSLMLKEMPrivateKey&& other) noexcept
	: MLKEMPrivateKey(std::move(other)), pkey(other.pkey)
{
	other.pkey = NULL;
}

OSSLMLKEMPrivateKey& OSSLMLKEMPrivateKey::operator=(OSSLMLKEMPrivateKey&& other) noexcept
{
	if (this != &other)
	{
		MLKEMPrivateKey::operator=(std::move(other));
		if (pkey) EVP_PKEY_free(pkey);
		pkey = other.pkey;
		other.pkey = NULL;
	}
	return *this;
}

// The type
const char* OSSLMLKEMPrivateKey::type = "OpenSSL ML-KEM Private Key";

// Set from OpenSSL representation
bool OSSLMLKEMPrivateKey::setFromOSSL(const EVP_PKEY* inMLKEMKEY)
{
	if (inMLKEMKEY == NULL)
	{
		ERROR_MSG("NULL EVP_PKEY in setFromOSSL");
		return false;
	}
	ByteString localSeed;
	uint8_t osslSeed[64];
	size_t osslSeed_len;
	int rv = EVP_PKEY_get_octet_string_param(inMLKEMKEY, OSSL_PKEY_PARAM_ML_KEM_SEED,
								osslSeed, sizeof(osslSeed), &osslSeed_len);
	if(rv && osslSeed_len == 64) {
		localSeed = ByteString(osslSeed, osslSeed_len);
	} else {
		ERROR_MSG("Could not get seed, rv: %d", rv);
		OPENSSL_cleanse(osslSeed, sizeof(osslSeed));
		return false;
	}
	
	// let's use max priv length
	uint8_t priv[MLKEMParameters::ML_KEM_1024_PRIV_LENGTH];
	size_t priv_len;
	rv = EVP_PKEY_get_octet_string_param(inMLKEMKEY, OSSL_PKEY_PARAM_PRIV_KEY,
									priv, sizeof(priv), &priv_len);
	if(!rv) {
		ERROR_MSG("Could not get private key, rv: %d", rv);
		OPENSSL_cleanse(osslSeed, sizeof(osslSeed));
		OPENSSL_cleanse(priv, sizeof(priv));
		return false;
	}

	if (priv_len != MLKEMParameters::ML_KEM_512_PRIV_LENGTH &&
		priv_len != MLKEMParameters::ML_KEM_768_PRIV_LENGTH &&
		priv_len != MLKEMParameters::ML_KEM_1024_PRIV_LENGTH)
	{
		ERROR_MSG("Unsupported ML-KEM private key length: %zu", priv_len);
		OPENSSL_cleanse(osslSeed, sizeof(osslSeed));
		OPENSSL_cleanse(priv, sizeof(priv));
		return false;
	}

	// Commit state atomically after successful extraction
	setSeed(localSeed);
	setValue(ByteString(priv, priv_len));
	OPENSSL_cleanse(osslSeed, sizeof(osslSeed));
	OPENSSL_cleanse(priv, sizeof(priv));
	return true;
}

// Check if the key is of the given type
bool OSSLMLKEMPrivateKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType) || MLKEMPrivateKey::isOfType(inType);
}

void OSSLMLKEMPrivateKey::setValue(const ByteString& inValue)
{
	MLKEMPrivateKey::setValue(inValue);
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

void OSSLMLKEMPrivateKey::setSeed(const ByteString& inSeed)
{
	MLKEMPrivateKey::setSeed(inSeed);
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString OSSLMLKEMPrivateKey::PKCS8Encode()
{
	ByteString der;
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return der;
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(key);
	if (p8inf == NULL) return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char* priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len) der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLMLKEMPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* localPKey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (localPKey == NULL) return false;
	const bool ok = setFromOSSL(localPKey);
	EVP_PKEY_free(localPKey);
	return ok;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLMLKEMPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLMLKEMPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;

	ByteString localValue = getValue();
	ByteString localSeed = getSeed();

	const char* name = OSSL::mlkemParameterSet2Name(getParameterSet());
	if (name == NULL)
	{
		ERROR_MSG("Unknown ML-KEM parameter set (value length: %zu)", localValue.size());
		return;
	}
	if (localValue.size() == 0)
	{
		ERROR_MSG("Empty ML-KEM private key value; cannot create EVP_PKEY");
		return;
	}

	int selection = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[4], *p = params;

	*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
												localValue.byte_str(), localValue.size());
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
												localSeed.byte_str(), localSeed.size());
	selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

	*p = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL) {
		ERROR_MSG("Could not create context");
		return;
	}
	int rv = EVP_PKEY_fromdata_init(ctx);
	if (rv <= 0) {
		ERROR_MSG("Could not EVP_PKEY_fromdata_init:%d", rv);
		EVP_PKEY_CTX_free(ctx);
		return;
	}
	rv = EVP_PKEY_fromdata(ctx, &pkey, selection, params);
	if (rv <= 0) {
		ERROR_MSG("Could not EVP_PKEY_fromdata:%d", rv);
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	EVP_PKEY_CTX_free(ctx);

}

#endif
