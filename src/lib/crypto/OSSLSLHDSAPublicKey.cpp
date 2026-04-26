/*****************************************************************************
 OSSLSLHDSAPublicKey.cpp

 OpenSSL SLH-DSA public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_SLH_DSA
#include "log.h"
#include "OSSLSLHDSAPublicKey.h"
#include "SLHDSAParameters.h"
#include "OSSLUtil.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <string.h>

// Constructors
/** \brief OSSLSLHDSAPublicKey */
OSSLSLHDSAPublicKey::OSSLSLHDSAPublicKey()
{
	pkey = NULL;
}

/** \brief OSSLSLHDSAPublicKey */
OSSLSLHDSAPublicKey::OSSLSLHDSAPublicKey(const EVP_PKEY* inEVPPKEY)
{
	pkey = NULL;

	setFromOSSL(inEVPPKEY);
}

// Destructor
/** \brief ~OSSLSLHDSAPublicKey */
OSSLSLHDSAPublicKey::~OSSLSLHDSAPublicKey()
{
	if (pkey != NULL)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

/** \brief OSSLSLHDSAPublicKey */
OSSLSLHDSAPublicKey::OSSLSLHDSAPublicKey(OSSLSLHDSAPublicKey&& other) noexcept
    : SLHDSAPublicKey(std::move(other)), pkey(other.pkey)
{
    other.pkey = NULL;
}

OSSLSLHDSAPublicKey& OSSLSLHDSAPublicKey::operator=(OSSLSLHDSAPublicKey&& other) noexcept
{
    if (this != &other)
    {
        // move base
        SLHDSAPublicKey::operator=(std::move(other));
        // release current
        if (pkey) { EVP_PKEY_free(pkey); }
        // steal
        pkey = other.pkey;
        other.pkey = NULL;
    }
    return *this;
}

// The type
/*static*/ const char* OSSLSLHDSAPublicKey::type = "OpenSSL SLH-DSA Public Key";

// Set from OpenSSL representation
/** \brief setFromOSSL */
void OSSLSLHDSAPublicKey::setFromOSSL(const EVP_PKEY* inEVPPKEY)
{
	// let's use max pub length
	uint8_t localPub[SLHDSAParameters::SLH_DSA_SHA2_256F_PUB_LENGTH];
    size_t pub_len;
    int rv = EVP_PKEY_get_octet_string_param(inEVPPKEY, OSSL_PKEY_PARAM_PUB_KEY,
                                    localPub, sizeof(localPub), &pub_len);

	if(!rv) {
		ERROR_MSG("Could not get SLH-DSA public key, rv: %d", rv);
		return;
	}


	const char* type_name = EVP_PKEY_get0_type_name(inEVPPKEY);
	unsigned long paramSet = OSSL::name2slhdsaParameterSet(type_name);
	if (paramSet == 0) {
		ERROR_MSG("Unsupported SLH-DSA public key type: %s", type_name ? type_name : "unknown");
		return;
	}

	ByteString pubBS = ByteString(localPub, pub_len);
	setValue(pubBS);
	setParameterSet(paramSet);

	
}

// Check if the key is of the given type
/** \brief isOfType */
bool OSSLSLHDSAPublicKey::isOfType(const char* inType)
{
	 return !strcmp(OSSLSLHDSAPublicKey::type, inType) || SLHDSAPublicKey::isOfType(inType);
}

/** \brief setValue */
void OSSLSLHDSAPublicKey::setValue(const ByteString& inValue)
{
	SLHDSAPublicKey::setValue(inValue);
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
/** \brief getOSSLKey */
EVP_PKEY* OSSLSLHDSAPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// Create the OpenSSL representation of the key
/** \brief createOSSLKey */
void OSSLSLHDSAPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;

	ByteString localValue = getValue();

	const char* name = OSSL::slhdsaParameterSet2Name(getParameterSet());

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
