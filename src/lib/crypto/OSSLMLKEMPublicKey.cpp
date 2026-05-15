/*****************************************************************************
 OSSLMLKEMPublicKey.cpp

 OpenSSL ML-KEM public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "log.h"
#include "OSSLMLKEMPublicKey.h"
#include "MLKEMParameters.h"
#include "OSSLUtil.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string.h>

// Constructors
OSSLMLKEMPublicKey::OSSLMLKEMPublicKey()
{
	pkey = NULL;
}

OSSLMLKEMPublicKey::OSSLMLKEMPublicKey(const EVP_PKEY* inEVPPKEY)
{
	pkey = NULL;

	setFromOSSL(inEVPPKEY);
}

// Destructor
OSSLMLKEMPublicKey::~OSSLMLKEMPublicKey()
{
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

OSSLMLKEMPublicKey::OSSLMLKEMPublicKey(OSSLMLKEMPublicKey&& other) noexcept
    : MLKEMPublicKey(std::move(other)), pkey(other.pkey)
{
    other.pkey = NULL;
}

OSSLMLKEMPublicKey& OSSLMLKEMPublicKey::operator=(OSSLMLKEMPublicKey&& other) noexcept
{
    if (this != &other)
    {
        // move base
        MLKEMPublicKey::operator=(std::move(other));
        // release current
        if (pkey) { EVP_PKEY_free(pkey); }
        // steal
        pkey = other.pkey;
        other.pkey = NULL;
    }
    return *this;
}

// The type
/*static*/ const char* OSSLMLKEMPublicKey::type = "OpenSSL ML-KEM Public Key";

// Set from OpenSSL representation
void OSSLMLKEMPublicKey::setFromOSSL(const EVP_PKEY* inEVPPKEY)
{
	if (inEVPPKEY == NULL)
	{
		ERROR_MSG("Could not get ML-KEM public key: input EVP_PKEY is NULL");
		return;
	}
	// let's use max pub length
	uint8_t localPub[MLKEMParameters::ML_KEM_1024_PUB_LENGTH];
    size_t pub_len;
    int rv = EVP_PKEY_get_octet_string_param(inEVPPKEY, OSSL_PKEY_PARAM_PUB_KEY,
                                    localPub, sizeof(localPub), &pub_len);

	if(!rv) {
		ERROR_MSG("Could not get ML-KEM public key, rv: %d", rv);
		return;
	}

	ByteString pubBS = ByteString(localPub, pub_len);
	setValue(pubBS);

}

// Check if the key is of the given type
bool OSSLMLKEMPublicKey::isOfType(const char* inType)
{
	if (inType == NULL) {
		return false;
	}
	 return !strcmp(OSSLMLKEMPublicKey::type, inType) || MLKEMPublicKey::isOfType(inType);
}

void OSSLMLKEMPublicKey::setValue(const ByteString& inValue)
{
	MLKEMPublicKey::setValue(inValue);
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLMLKEMPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
void OSSLMLKEMPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;

	ByteString localValue = getValue();

	const char* name = OSSL::mlkemParameterSet2Name(getParameterSet());
	if (name == NULL)
	{
		ERROR_MSG("Unknown ML-KEM parameter set (value length: %zu)", localValue.size());
		return;
	}

	int selection = 0;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[3], *p = params;

	*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
												localValue.byte_str(), localValue.size());
	selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

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
