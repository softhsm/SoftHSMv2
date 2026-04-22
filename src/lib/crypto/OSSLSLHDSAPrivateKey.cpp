/*****************************************************************************
 OSSLSLHDSAPrivateKey.cpp

 OpenSSL SLH-DSA private key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLH_DSA
#include "log.h"
#include "OSSLSLHDSAPrivateKey.h"
#include "SLHDSAParameters.h"
#include "OSSLUtil.h"
#include <cstring>
#include <utility>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

// Constructors
OSSLSLHDSAPrivateKey::OSSLSLHDSAPrivateKey()
{
	pkey = NULL;
}

OSSLSLHDSAPrivateKey::OSSLSLHDSAPrivateKey(const EVP_PKEY* inSLHDSAKEY)
{
	pkey = NULL;

	setFromOSSL(inSLHDSAKEY);
}

// Destructor
OSSLSLHDSAPrivateKey::~OSSLSLHDSAPrivateKey()
{
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

OSSLSLHDSAPrivateKey::OSSLSLHDSAPrivateKey(OSSLSLHDSAPrivateKey&& other) noexcept  
	: SLHDSAPrivateKey(std::move(other)), pkey(other.pkey)  
{  
	other.pkey = NULL;  
}  
  
OSSLSLHDSAPrivateKey& OSSLSLHDSAPrivateKey::operator=(OSSLSLHDSAPrivateKey&& other) noexcept  
{  
	if (this != &other)  
	{  
		SLHDSAPrivateKey::operator=(std::move(other));  
		if (pkey) EVP_PKEY_free(pkey);  
		pkey = other.pkey;  
		other.pkey = NULL;  
	}  
	return *this;  
}  

// The type
const char* OSSLSLHDSAPrivateKey::type = "OpenSSL SLH-DSA Private Key";

// Set from OpenSSL representation
bool OSSLSLHDSAPrivateKey::setFromOSSL(const EVP_PKEY* inSLHDSAKEY)
{
	// let's use max priv length
	uint8_t priv[SLHDSAParameters::SLH_DSA_SHA2_256F_PRIV_LENGTH];
	size_t priv_len;
	int rv = EVP_PKEY_get_octet_string_param(inSLHDSAKEY, OSSL_PKEY_PARAM_PRIV_KEY,
									priv, sizeof(priv), &priv_len);
	if(!rv) {
		ERROR_MSG("Could not get private key, rv: %d", rv);
		memset(priv, 0, sizeof(priv));
		return false;
	}

	
	const char* type_name = EVP_PKEY_get0_type_name(inSLHDSAKEY);
	unsigned long paramSet = OSSL::name2slhdsaParameterSet(type_name);
	if (paramSet == 0) {
		ERROR_MSG("Unsupported SLH-DSA private key type: %s", type_name ? type_name : "unknown");
		memset(priv, 0, sizeof(priv));
		return false;
	}

	// Commit state atomically after successful extraction
	setValue(ByteString(priv, priv_len));
	setParameterSet(paramSet);
	memset(priv, 0, sizeof(priv));
	return true;
}

// Check if the key is of the given type
bool OSSLSLHDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

void OSSLSLHDSAPrivateKey::setValue(const ByteString& inValue)
{
	SLHDSAPrivateKey::setValue(inValue);
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}
// Encode into PKCS#8 DER
ByteString OSSLSLHDSAPrivateKey::PKCS8Encode()
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
bool OSSLSLHDSAPrivateKey::PKCS8Decode(const ByteString& ber)
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
EVP_PKEY* OSSLSLHDSAPrivateKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLSLHDSAPrivateKey::createOSSLKey()
{
	if (pkey != NULL) return;

	ByteString localValue = getValue();

	const char* name = OSSL::slhdsaParameterSet2Name(getParameterSet());
	if (name == NULL) 
	{
		ERROR_MSG("Unknown SLH-DSA parameter set (value length: %zu)", localValue.size());
		return;
	}
	if (localValue.size() == 0) 
	{
		ERROR_MSG("Empty SLH-DSA private key value; cannot create EVP_PKEY");
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
