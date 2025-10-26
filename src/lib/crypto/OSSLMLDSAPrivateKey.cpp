/*****************************************************************************
 OSSLMLDSAPrivateKey.cpp

 OpenSSL ML-DSA private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "log.h"
#include "OSSLMLDSAPrivateKey.h"
#include "MLDSAParameters.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

// Constructors
OSSLMLDSAPrivateKey::OSSLMLDSAPrivateKey()
{
	pkey = NULL;
}

OSSLMLDSAPrivateKey::OSSLMLDSAPrivateKey(const EVP_PKEY* inMLDSAKEY)
{
	pkey = NULL;

	setFromOSSL(inMLDSAKEY);
}

// Destructor
OSSLMLDSAPrivateKey::~OSSLMLDSAPrivateKey()
{
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

OSSLMLDSAPrivateKey::OSSLMLDSAPrivateKey(OSSLMLDSAPrivateKey&& other) noexcept  
	: MLDSAPrivateKey(std::move(other)), pkey(other.pkey)  
{  
	other.pkey = NULL;  
}  
  
OSSLMLDSAPrivateKey& OSSLMLDSAPrivateKey::operator=(OSSLMLDSAPrivateKey&& other) noexcept  
{  
	if (this != &other)  
	{  
		MLDSAPrivateKey::operator=(std::move(other));  
		if (pkey) EVP_PKEY_free(pkey);  
		pkey = other.pkey;  
		other.pkey = NULL;  
	}  
	return *this;  
}  

// The type
const char* OSSLMLDSAPrivateKey::type = "OpenSSL ML-DSA Private Key";

// Set from OpenSSL representation
void OSSLMLDSAPrivateKey::setFromOSSL(const EVP_PKEY* inMLDSAKEY)
{
	uint8_t seed[32];
	size_t seed_len;
	int rv = EVP_PKEY_get_octet_string_param(inMLDSAKEY, OSSL_PKEY_PARAM_ML_DSA_SEED,
								seed, sizeof(seed), &seed_len);
	if(rv && seed_len == 32) {
		// seed is not mandatory for OSSL key reconstruction
		ByteString seedBS = ByteString(seed, seed_len);
		setSeed(seedBS);
	}
	
	// let's use max priv length
	uint8_t priv[MLDSAParameters::ML_DSA_87_PRIV_LENGTH];
	size_t priv_len;
	rv = EVP_PKEY_get_octet_string_param(inMLDSAKEY, OSSL_PKEY_PARAM_PRIV_KEY,
									priv, sizeof(priv), &priv_len);
	if(!rv) {
		ERROR_MSG("Could not get private key private, rv: %d", rv);
		return;
	}

	ByteString valueBS = ByteString(priv, priv_len);

	setValue(valueBS);
}

// Check if the key is of the given type
bool OSSLMLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLMLDSAPrivateKey::setValue(const ByteString& inValue)
{
	MLDSAPrivateKey::setValue(inValue);
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

void OSSLMLDSAPrivateKey::setSeed(const ByteString& inSeed)
{
	MLDSAPrivateKey::setSeed(inSeed);
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Encode into PKCS#8 DER
ByteString OSSLMLDSAPrivateKey::PKCS8Encode()
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
bool OSSLMLDSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* localPKey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (localPKey == NULL) return false;
	setFromOSSL(localPKey);
	EVP_PKEY_free(localPKey);
	return true;
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLMLDSAPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLMLDSAPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;

	ByteString localValue = getValue();

	const char* name = OSSL::mldsaParameterSet2Name(getParameterSet());
	if (name == NULL) 
	{
		ERROR_MSG("Unknown ML-DSA parameter set (value length: %zu)", localValue.size());
		return;
	}
	if (localValue.size() == 0) 
	{
		ERROR_MSG("Empty ML-DSA private key value; cannot create EVP_PKEY");
		return;
	}

	int selection = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3], *p = params;

	*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
												localValue.byte_str(), localValue.size());
	selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

	*p = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
	if (ctx == NULL) {
		ERROR_MSG("Could not create context");
		return;
	}
	int rv = EVP_PKEY_fromdata_init(ctx);
	if (!rv) {
		ERROR_MSG("Could not EVP_PKEY_fromdata_init:%d", rv);
		EVP_PKEY_CTX_free(ctx);
		return;
	}
	rv = EVP_PKEY_fromdata(ctx, &pkey, selection, params);
	if (!rv) {
		ERROR_MSG("Could not EVP_PKEY_fromdata:%d", rv);
		EVP_PKEY_CTX_free(ctx);
		return;
	}

	EVP_PKEY_CTX_free(ctx);

}

#endif
