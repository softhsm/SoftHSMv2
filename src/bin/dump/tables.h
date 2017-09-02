/*
 * Copyright (c) 2013 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 tables.h

 Tables from PKCS#11 specs.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_TABLES_H
#define _SOFTHSM_V2_TABLES_H

#include "OSAttributes.h"

// Attribute types
void fill_CKA_table(std::map<unsigned long, std::string> &t)
{
	t[CKA_CLASS] = "CKA_CLASS";
	t[CKA_TOKEN] = "CKA_TOKEN";
	t[CKA_PRIVATE] = "CKA_PRIVATE";
	t[CKA_LABEL] = "CKA_LABEL";
	t[CKA_APPLICATION] = "CKA_APPLICATION";
	t[CKA_VALUE] = "CKA_VALUE";
	t[CKA_OBJECT_ID] = "CKA_OBJECT_ID";
	t[CKA_CERTIFICATE_TYPE] = "CKA_CERTIFICATE_TYPE";
	t[CKA_ISSUER] = "CKA_ISSUER";
	t[CKA_SERIAL_NUMBER] = "CKA_SERIAL_NUMBER";
	t[CKA_AC_ISSUER] = "CKA_AC_ISSUER";
	t[CKA_OWNER] = "CKA_OWNER";
	t[CKA_ATTR_TYPES] = "CKA_ATTR_TYPES";
	t[CKA_TRUSTED] = "CKA_TRUSTED";
	t[CKA_CERTIFICATE_CATEGORY] = "CKA_CERTIFICATE_CATEGORY";
	t[CKA_JAVA_MIDP_SECURITY_DOMAIN] = "CKA_JAVA_MIDP_SECURITY_DOMAIN";
	t[CKA_URL] = "CKA_URL";
	t[CKA_HASH_OF_SUBJECT_PUBLIC_KEY] = "CKA_HASH_OF_SUBJECT_PUBLIC_KEY";
	t[CKA_HASH_OF_ISSUER_PUBLIC_KEY] = "CKA_HASH_OF_ISSUER_PUBLIC_KEY";
	t[CKA_NAME_HASH_ALGORITHM] = "CKA_NAME_HASH_ALGORITHM";
	t[CKA_CHECK_VALUE] = "CKA_CHECK_VALUE";
	t[CKA_KEY_TYPE] = "CKA_KEY_TYPE";
	t[CKA_SUBJECT] = "CKA_SUBJECT";
	t[CKA_ID] = "CKA_ID";
	t[CKA_SENSITIVE] = "CKA_SENSITIVE";
	t[CKA_ENCRYPT] = "CKA_ENCRYPT";
	t[CKA_DECRYPT] = "CKA_DECRYPT";
	t[CKA_WRAP] = "CKA_WRAP";
	t[CKA_UNWRAP] = "CKA_UNWRAP";
	t[CKA_SIGN] = "CKA_SIGN";
	t[CKA_SIGN_RECOVER] = "CKA_SIGN_RECOVER";
	t[CKA_VERIFY] = "CKA_VERIFY";
	t[CKA_VERIFY_RECOVER] = "CKA_VERIFY_RECOVER";
	t[CKA_DERIVE] = "CKA_DERIVE";
	t[CKA_START_DATE] = "CKA_START_DATE";
	t[CKA_END_DATE] = "CKA_END_DATE";
	t[CKA_MODULUS] = "CKA_MODULUS";
	t[CKA_MODULUS_BITS] = "CKA_MODULUS_BITS";
	t[CKA_PUBLIC_EXPONENT] = "CKA_PUBLIC_EXPONENT";
	t[CKA_PRIVATE_EXPONENT] = "CKA_PRIVATE_EXPONENT";
	t[CKA_PRIME_1] = "CKA_PRIME_1";
	t[CKA_PRIME_2] = "CKA_PRIME_2";
	t[CKA_EXPONENT_1] = "CKA_EXPONENT_1";
	t[CKA_EXPONENT_2] = "CKA_EXPONENT_2";
	t[CKA_COEFFICIENT] = "CKA_COEFFICIENT";
	t[CKA_PUBLIC_KEY_INFO] = "CKA_PUBLIC_KEY_INFO";
	t[CKA_PRIME] = "CKA_PRIME";
	t[CKA_SUBPRIME] = "CKA_SUBPRIME";
	t[CKA_BASE] = "CKA_BASE";
	t[CKA_PRIME_BITS] = "CKA_PRIME_BITS";
	t[CKA_SUBPRIME_BITS] = "CKA_SUBPRIME_BITS";
	t[CKA_VALUE_BITS] = "CKA_VALUE_BITS";
	t[CKA_VALUE_LEN] = "CKA_VALUE_LEN";
	t[CKA_EXTRACTABLE] = "CKA_EXTRACTABLE";
	t[CKA_LOCAL] = "CKA_LOCAL";
	t[CKA_NEVER_EXTRACTABLE] = "CKA_NEVER_EXTRACTABLE";
	t[CKA_ALWAYS_SENSITIVE] = "CKA_ALWAYS_SENSITIVE";
	t[CKA_KEY_GEN_MECHANISM] = "CKA_KEY_GEN_MECHANISM";
	t[CKA_MODIFIABLE] = "CKA_MODIFIABLE";
	t[CKA_COPYABLE] = "CKA_COPYABLE";
	t[CKA_DESTROYABLE] = "CKA_DESTROYABLE";
	t[CKA_EC_PARAMS] = "CKA_EC_PARAMS";
	t[CKA_EC_POINT] = "CKA_EC_POINT";
	t[CKA_SECONDARY_AUTH] = "CKA_SECONDARY_AUTH";
	t[CKA_AUTH_PIN_FLAGS] = "CKA_AUTH_PIN_FLAGS";
	t[CKA_ALWAYS_AUTHENTICATE] = "CKA_ALWAYS_AUTHENTICATE";
	t[CKA_WRAP_WITH_TRUSTED] = "CKA_WRAP_WITH_TRUSTED";
	t[CKA_WRAP_TEMPLATE] = "CKA_WRAP_TEMPLATE";
	t[CKA_UNWRAP_TEMPLATE] = "CKA_UNWRAP_TEMPLATE";
	t[CKA_DERIVE_TEMPLATE] = "CKA_DERIVE_TEMPLATE";
	t[CKA_OTP_FORMAT] = "CKA_OTP_FORMAT";
	t[CKA_OTP_LENGTH] = "CKA_OTP_LENGTH";
	t[CKA_OTP_TIME_INTERVAL] = "CKA_OTP_TIME_INTERVAL";
	t[CKA_OTP_USER_FRIENDLY_MODE] = "CKA_OTP_USER_FRIENDLY_MODE";
	t[CKA_OTP_CHALLENGE_REQUIREMENT] = "CKA_OTP_CHALLENGE_REQUIREMENT";
	t[CKA_OTP_TIME_REQUIREMENT] = "CKA_OTP_TIME_REQUIREMENT";
	t[CKA_OTP_COUNTER_REQUIREMENT] = "CKA_OTP_COUNTER_REQUIREMENT";
	t[CKA_OTP_PIN_REQUIREMENT] = "CKA_OTP_PIN_REQUIREMENT";
	t[CKA_OTP_COUNTER] = "CKA_OTP_COUNTER";
	t[CKA_OTP_TIME] = "CKA_OTP_TIME";
	t[CKA_OTP_USER_IDENTIFIER] = "CKA_OTP_USER_IDENTIFIER";
	t[CKA_OTP_SERVICE_IDENTIFIER] = "CKA_OTP_SERVICE_IDENTIFIER";
	t[CKA_OTP_SERVICE_LOGO] = "CKA_OTP_SERVICE_LOGO";
	t[CKA_OTP_SERVICE_LOGO_TYPE] = "CKA_OTP_SERVICE_LOGO_TYPE";
	t[CKA_GOSTR3410_PARAMS] = "CKA_GOSTR3410_PARAMS";
	t[CKA_GOSTR3411_PARAMS] = "CKA_GOSTR3411_PARAMS";
	t[CKA_GOST28147_PARAMS] = "CKA_GOST28147_PARAMS";
	t[CKA_HW_FEATURE_TYPE] = "CKA_HW_FEATURE_TYPE";
	t[CKA_RESET_ON_INIT] = "CKA_RESET_ON_INIT";
	t[CKA_HAS_RESET] = "CKA_HAS_RESET";
	t[CKA_PIXEL_X] = "CKA_PIXEL_X";
	t[CKA_PIXEL_Y] = "CKA_PIXEL_Y";
	t[CKA_RESOLUTION] = "CKA_RESOLUTION";
	t[CKA_CHAR_ROWS] = "CKA_CHAR_ROWS";
	t[CKA_CHAR_COLUMNS] = "CKA_CHAR_COLUMNS";
	t[CKA_COLOR] = "CKA_COLOR";
	t[CKA_BITS_PER_PIXEL] = "CKA_BITS_PER_PIXEL";
	t[CKA_CHAR_SETS] = "CKA_CHAR_SETS";
	t[CKA_ENCODING_METHODS] = "CKA_ENCODING_METHODS";
	t[CKA_MIME_TYPES] = "CKA_MIME_TYPES";
	t[CKA_MECHANISM_TYPE] = "CKA_MECHANISM_TYPE";
	t[CKA_REQUIRED_CMS_ATTRIBUTES] = "CKA_REQUIRED_CMS_ATTRIBUTES";
	t[CKA_DEFAULT_CMS_ATTRIBUTES] = "CKA_DEFAULT_CMS_ATTRIBUTES";
	t[CKA_SUPPORTED_CMS_ATTRIBUTES] = "CKA_SUPPORTED_CMS_ATTRIBUTES";
	t[CKA_ALLOWED_MECHANISMS] = "CKA_ALLOWED_MECHANISMS";
	// local extensions
	t[CKA_VENDOR_SOFTHSM] = "CKA_VENDOR_SOFTHSM";
	t[CKA_OS_TOKENLABEL] = "CKA_OS_TOKENLABEL";
	t[CKA_OS_TOKENSERIAL] = "CKA_OS_TOKENSERIAL";
	t[CKA_OS_TOKENFLAGS] = "CKA_OS_TOKENFLAGS";
	t[CKA_OS_SOPIN] = "CKA_OS_SOPIN";
	t[CKA_OS_USERPIN] = "CKA_OS_USERPIN";
}

void fill_CKM_table(std::map<unsigned long, std::string> &t)
{
	t[CKM_RSA_PKCS_KEY_PAIR_GEN] = "CKM_RSA_PKCS_KEY_PAIR_GEN";
	t[CKM_RSA_PKCS] = "CKM_RSA_PKCS";
	t[CKM_RSA_9796] = "CKM_RSA_9796";
	t[CKM_RSA_X_509] = "CKM_RSA_X_509";
	t[CKM_MD2_RSA_PKCS] = "CKM_MD2_RSA_PKCS";
	t[CKM_MD5_RSA_PKCS] = "CKM_MD5_RSA_PKCS";
	t[CKM_SHA1_RSA_PKCS] = "CKM_SHA1_RSA_PKCS";
	t[CKM_RIPEMD128_RSA_PKCS] = "CKM_RIPEMD128_RSA_PKCS";
	t[CKM_RIPEMD160_RSA_PKCS] = "CKM_RIPEMD160_RSA_PKCS";
	t[CKM_RSA_PKCS_OAEP] = "CKM_RSA_PKCS_OAEP";
	t[CKM_RSA_X9_31_KEY_PAIR_GEN] = "CKM_RSA_X9_31_KEY_PAIR_GEN";
	t[CKM_RSA_X9_31] = "CKM_RSA_X9_31";
	t[CKM_SHA1_RSA_X9_31] = "CKM_SHA1_RSA_X9_31";
	t[CKM_RSA_PKCS_PSS] = "CKM_RSA_PKCS_PSS";
	t[CKM_SHA1_RSA_PKCS_PSS] = "CKM_SHA1_RSA_PKCS_PSS";
	t[CKM_DSA_KEY_PAIR_GEN] = "CKM_DSA_KEY_PAIR_GEN";
	t[CKM_DSA] = "CKM_DSA";
	t[CKM_DSA_SHA1] = "CKM_DSA_SHA1";
	t[CKM_DSA_SHA224] = "CKM_DSA_SHA224";
	t[CKM_DSA_SHA256] = "CKM_DSA_SHA256";
	t[CKM_DSA_SHA384] = "CKM_DSA_SHA384";
	t[CKM_DSA_SHA512] = "CKM_DSA_SHA512";
	t[CKM_DSA_SHA3_224] = "CKM_DSA_SHA3_224";
	t[CKM_DSA_SHA3_256] = "CKM_DSA_SHA3_256";
	t[CKM_DSA_SHA3_384] = "CKM_DSA_SHA3_384";
	t[CKM_DSA_SHA3_512] = "CKM_DSA_SHA3_512";
	t[CKM_DH_PKCS_KEY_PAIR_GEN] = "CKM_DH_PKCS_KEY_PAIR_GEN";
	t[CKM_DH_PKCS_DERIVE] = "CKM_DH_PKCS_DERIVE";
	t[CKM_X9_42_DH_KEY_PAIR_GEN] = "CKM_X9_42_DH_KEY_PAIR_GEN";
	t[CKM_X9_42_DH_DERIVE] = "CKM_X9_42_DH_DERIVE";
	t[CKM_X9_42_DH_HYBRID_DERIVE] = "CKM_X9_42_DH_HYBRID_DERIVE";
	t[CKM_X9_42_MQV_DERIVE] = "CKM_X9_42_MQV_DERIVE";
	t[CKM_SHA256_RSA_PKCS] = "CKM_SHA256_RSA_PKCS";
	t[CKM_SHA384_RSA_PKCS] = "CKM_SHA384_RSA_PKCS";
	t[CKM_SHA512_RSA_PKCS] = "CKM_SHA512_RSA_PKCS";
	t[CKM_SHA256_RSA_PKCS_PSS] = "CKM_SHA256_RSA_PKCS_PSS";
	t[CKM_SHA384_RSA_PKCS_PSS] = "CKM_SHA384_RSA_PKCS_PSS";
	t[CKM_SHA512_RSA_PKCS_PSS] = "CKM_SHA512_RSA_PKCS_PSS";
	t[CKM_SHA224_RSA_PKCS] = "CKM_SHA224_RSA_PKCS";
	t[CKM_SHA224_RSA_PKCS_PSS] = "CKM_SHA224_RSA_PKCS_PSS";
	t[CKM_SHA512_224] = "CKM_SHA512_224";
	t[CKM_SHA512_224_HMAC] = "CKM_SHA512_224_HMAC";
	t[CKM_SHA512_224_HMAC_GENERAL] = "CKM_SHA512_224_HMAC_GENERAL";
	t[CKM_SHA512_224_KEY_DERIVATION] = "CKM_SHA512_224_KEY_DERIVATION";
	t[CKM_SHA512_256] = "CKM_SHA512_256";
	t[CKM_SHA512_256_HMAC] = "CKM_SHA512_256_HMAC";
	t[CKM_SHA512_256_HMAC_GENERAL] = "CKM_SHA512_256_HMAC_GENERAL";
	t[CKM_SHA512_256_KEY_DERIVATION] = "CKM_SHA512_256_KEY_DERIVATION";
	t[CKM_SHA512_T] = "CKM_SHA512_T";
	t[CKM_SHA512_T_HMAC] = "CKM_SHA512_T_HMAC";
	t[CKM_SHA512_T_HMAC_GENERAL] = "CKM_SHA512_T_HMAC_GENERAL";
	t[CKM_SHA512_T_KEY_DERIVATION] = "CKM_SHA512_T_KEY_DERIVATION";
	t[CKM_SHA3_256_RSA_PKCS] = "CKM_SHA3_256_RSA_PKCS";
	t[CKM_SHA3_384_RSA_PKCS] = "CKM_SHA3_384_RSA_PKCS";
	t[CKM_SHA3_512_RSA_PKCS] = "CKM_SHA3_512_RSA_PKCS";
	t[CKM_SHA3_256_RSA_PKCS_PSS] = "CKM_SHA3_256_RSA_PKCS_PSS";
	t[CKM_SHA3_384_RSA_PKCS_PSS] = "CKM_SHA3_384_RSA_PKCS_PSS";
	t[CKM_SHA3_512_RSA_PKCS_PSS] = "CKM_SHA3_512_RSA_PKCS_PSS";
	t[CKM_SHA3_224_RSA_PKCS] = "CKM_SHA3_224_RSA_PKCS";
	t[CKM_SHA3_224_RSA_PKCS_PSS] = "CKM_SHA3_224_RSA_PKCS_PSS";
	t[CKM_RC2_KEY_GEN] = "CKM_RC2_KEY_GEN";
	t[CKM_RC2_ECB] = "CKM_RC2_ECB";
	t[CKM_RC2_CBC] = "CKM_RC2_CBC";
	t[CKM_RC2_MAC] = "CKM_RC2_MAC";
	t[CKM_RC2_MAC_GENERAL] = "CKM_RC2_MAC_GENERAL";
	t[CKM_RC2_CBC_PAD] = "CKM_RC2_CBC_PAD";
	t[CKM_RC4_KEY_GEN] = "CKM_RC4_KEY_GEN";
	t[CKM_RC4] = "CKM_RC4";
	t[CKM_DES_KEY_GEN] = "CKM_DES_KEY_GEN";
	t[CKM_DES_ECB] = "CKM_DES_ECB";
	t[CKM_DES_CBC] = "CKM_DES_CBC";
	t[CKM_DES_MAC] = "CKM_DES_MAC";
	t[CKM_DES_MAC_GENERAL] = "CKM_DES_MAC_GENERAL";
	t[CKM_DES_CBC_PAD] = "CKM_DES_CBC_PAD";
	t[CKM_DES2_KEY_GEN] = "CKM_DES2_KEY_GEN";
	t[CKM_DES3_KEY_GEN] = "CKM_DES3_KEY_GEN";
	t[CKM_DES3_ECB] = "CKM_DES3_ECB";
	t[CKM_DES3_CBC] = "CKM_DES3_CBC";
	t[CKM_DES3_MAC] = "CKM_DES3_MAC";
	t[CKM_DES3_MAC_GENERAL] = "CKM_DES3_MAC_GENERAL";
	t[CKM_DES3_CBC_PAD] = "CKM_DES3_CBC_PAD";
	t[CKM_DES3_CMAC_GENERAL] = "CKM_DES3_CMAC_GENERAL";
	t[CKM_DES3_CMAC] = "CKM_DES3_CMAC";
	t[CKM_CDMF_KEY_GEN] = "CKM_CDMF_KEY_GEN";
	t[CKM_CDMF_ECB] = "CKM_CDMF_ECB";
	t[CKM_CDMF_CBC] = "CKM_CDMF_CBC";
	t[CKM_CDMF_MAC] = "CKM_CDMF_MAC";
	t[CKM_CDMF_MAC_GENERAL] = "CKM_CDMF_MAC_GENERAL";
	t[CKM_CDMF_CBC_PAD] = "CKM_CDMF_CBC_PAD";
	t[CKM_DES_OFB64] = "CKM_DES_OFB64";
	t[CKM_DES_OFB8] = "CKM_DES_OFB8";
	t[CKM_DES_CFB64] = "CKM_DES_CFB64";
	t[CKM_DES_CFB8] = "CKM_DES_CFB8";
	t[CKM_MD2] = "CKM_MD2";
	t[CKM_MD2_HMAC] = "CKM_MD2_HMAC";
	t[CKM_MD2_HMAC_GENERAL] = "CKM_MD2_HMAC_GENERAL";
	t[CKM_MD5] = "CKM_MD5";
	t[CKM_MD5_HMAC] = "CKM_MD5_HMAC";
	t[CKM_MD5_HMAC_GENERAL] = "CKM_MD5_HMAC_GENERAL";
	t[CKM_SHA_1] = "CKM_SHA_1";
	t[CKM_SHA_1_HMAC] = "CKM_SHA_1_HMAC";
	t[CKM_SHA_1_HMAC_GENERAL] = "CKM_SHA_1_HMAC_GENERAL";
	t[CKM_RIPEMD128] = "CKM_RIPEMD128";
	t[CKM_RIPEMD128_HMAC] = "CKM_RIPEMD128_HMAC";
	t[CKM_RIPEMD128_HMAC_GENERAL] = "CKM_RIPEMD128_HMAC_GENERAL";
	t[CKM_RIPEMD160] = "CKM_RIPEMD160";
	t[CKM_RIPEMD160_HMAC] = "CKM_RIPEMD160_HMAC";
	t[CKM_RIPEMD160_HMAC_GENERAL] = "CKM_RIPEMD160_HMAC_GENERAL";
	t[CKM_SHA256] = "CKM_SHA256";
	t[CKM_SHA256_HMAC] = "CKM_SHA256_HMAC";
	t[CKM_SHA256_HMAC_GENERAL] = "CKM_SHA256_HMAC_GENERAL";
	t[CKM_SHA224] = "CKM_SHA224";
	t[CKM_SHA224_HMAC] = "CKM_SHA224_HMAC";
	t[CKM_SHA224_HMAC_GENERAL] = "CKM_SHA224_HMAC_GENERAL";
	t[CKM_SHA384] = "CKM_SHA384";
	t[CKM_SHA384_HMAC] = "CKM_SHA384_HMAC";
	t[CKM_SHA384_HMAC_GENERAL] = "CKM_SHA384_HMAC_GENERAL";
	t[CKM_SHA512] = "CKM_SHA512";
	t[CKM_SHA512_HMAC] = "CKM_SHA512_HMAC";
	t[CKM_SHA512_HMAC_GENERAL] = "CKM_SHA512_HMAC_GENERAL";
	t[CKM_SECURID_KEY_GEN] = "CKM_SECURID_KEY_GEN";
	t[CKM_SECURID] = "CKM_SECURID";
	t[CKM_HOTP_KEY_GEN] = "CKM_HOTP_KEY_GEN";
	t[CKM_HOTP] = "CKM_HOTP";
	t[CKM_ACTI] = "CKM_ACTI";
	t[CKM_ACTI_KEY_GEN] = "CKM_ACTI_KEY_GEN";
	t[CKM_SHA3_256] = "CKM_SHA3_256";
	t[CKM_SHA3_256_HMAC] = "CKM_SHA3_256_HMAC";
	t[CKM_SHA3_256_HMAC_GENERAL] = "CKM_SHA3_256_HMAC_GENERAL";
	t[CKM_SHA3_256_KEY_GEN] = "CKM_SHA3_256_KEY_GEN";
	t[CKM_SHA3_224] = "CKM_SHA3_224";
	t[CKM_SHA3_224_HMAC] = "CKM_SHA3_224_HMAC";
	t[CKM_SHA3_224_HMAC_GENERAL] = "CKM_SHA3_224_HMAC_GENERAL";
	t[CKM_SHA3_224_KEY_GEN] = "CKM_SHA3_224_KEY_GEN";
	t[CKM_SHA3_384] = "CKM_SHA3_384";
	t[CKM_SHA3_384_HMAC] = "CKM_SHA3_384_HMAC";
	t[CKM_SHA3_384_HMAC_GENERAL] = "CKM_SHA3_384_HMAC_GENERAL";
	t[CKM_SHA3_384_KEY_GEN] = "CKM_SHA3_384_KEY_GEN";
	t[CKM_SHA3_512] = "CKM_SHA3_512";
	t[CKM_SHA3_512_HMAC] = "CKM_SHA3_512_HMAC";
	t[CKM_SHA3_512_HMAC_GENERAL] = "CKM_SHA3_512_HMAC_GENERAL";
	t[CKM_SHA3_512_KEY_GEN] = "CKM_SHA3_512_KEY_GEN";
	t[CKM_CAST_KEY_GEN] = "CKM_CAST_KEY_GEN";
	t[CKM_CAST_ECB] = "CKM_CAST_ECB";
	t[CKM_CAST_CBC] = "CKM_CAST_CBC";
	t[CKM_CAST_MAC] = "CKM_CAST_MAC";
	t[CKM_CAST_MAC_GENERAL] = "CKM_CAST_MAC_GENERAL";
	t[CKM_CAST_CBC_PAD] = "CKM_CAST_CBC_PAD";
	t[CKM_CAST3_KEY_GEN] = "CKM_CAST3_KEY_GEN";
	t[CKM_CAST3_ECB] = "CKM_CAST3_ECB";
	t[CKM_CAST3_CBC] = "CKM_CAST3_CBC";
	t[CKM_CAST3_MAC] = "CKM_CAST3_MAC";
	t[CKM_CAST3_MAC_GENERAL] = "CKM_CAST3_MAC_GENERAL";
	t[CKM_CAST3_CBC_PAD] = "CKM_CAST3_CBC_PAD";
	t[CKM_CAST128_KEY_GEN] = "CKM_CAST128_KEY_GEN";
	t[CKM_CAST128_ECB] = "CKM_CAST128_ECB";
	t[CKM_CAST128_CBC] = "CKM_CAST128_CBC";
	t[CKM_CAST128_MAC] = "CKM_CAST128_MAC";
	t[CKM_CAST128_MAC_GENERAL] = "CKM_CAST128_MAC_GENERAL";
	t[CKM_CAST128_CBC_PAD] = "CKM_CAST128_CBC_PAD";
	t[CKM_RC5_KEY_GEN] = "CKM_RC5_KEY_GEN";
	t[CKM_RC5_ECB] = "CKM_RC5_ECB";
	t[CKM_RC5_CBC] = "CKM_RC5_CBC";
	t[CKM_RC5_MAC] = "CKM_RC5_MAC";
	t[CKM_RC5_MAC_GENERAL] = "CKM_RC5_MAC_GENERAL";
	t[CKM_RC5_CBC_PAD] = "CKM_RC5_CBC_PAD";
	t[CKM_IDEA_KEY_GEN] = "CKM_IDEA_KEY_GEN";
	t[CKM_IDEA_ECB] = "CKM_IDEA_ECB";
	t[CKM_IDEA_CBC] = "CKM_IDEA_CBC";
	t[CKM_IDEA_MAC] = "CKM_IDEA_MAC";
	t[CKM_IDEA_MAC_GENERAL] = "CKM_IDEA_MAC_GENERAL";
	t[CKM_IDEA_CBC_PAD] = "CKM_IDEA_CBC_PAD";
	t[CKM_GENERIC_SECRET_KEY_GEN] = "CKM_GENERIC_SECRET_KEY_GEN";
	t[CKM_CONCATENATE_BASE_AND_KEY] = "CKM_CONCATENATE_BASE_AND_KEY";
	t[CKM_CONCATENATE_BASE_AND_DATA] = "CKM_CONCATENATE_BASE_AND_DATA";
	t[CKM_CONCATENATE_DATA_AND_BASE] = "CKM_CONCATENATE_DATA_AND_BASE";
	t[CKM_XOR_BASE_AND_DATA] = "CKM_XOR_BASE_AND_DATA";
	t[CKM_EXTRACT_KEY_FROM_KEY] = "CKM_EXTRACT_KEY_FROM_KEY";
	t[CKM_SSL3_PRE_MASTER_KEY_GEN] = "CKM_SSL3_PRE_MASTER_KEY_GEN";
	t[CKM_SSL3_MASTER_KEY_DERIVE] = "CKM_SSL3_MASTER_KEY_DERIVE";
	t[CKM_SSL3_KEY_AND_MAC_DERIVE] = "CKM_SSL3_KEY_AND_MAC_DERIVE";
	t[CKM_SSL3_MASTER_KEY_DERIVE_DH] = "CKM_SSL3_MASTER_KEY_DERIVE_DH";
	t[CKM_TLS_PRE_MASTER_KEY_GEN] = "CKM_TLS_PRE_MASTER_KEY_GEN";
	t[CKM_TLS_MASTER_KEY_DERIVE] = "CKM_TLS_MASTER_KEY_DERIVE";
	t[CKM_TLS_KEY_AND_MAC_DERIVE] = "CKM_TLS_KEY_AND_MAC_DERIVE";
	t[CKM_TLS_MASTER_KEY_DERIVE_DH] = "CKM_TLS_MASTER_KEY_DERIVE_DH";
	t[CKM_TLS_PRF] = "CKM_TLS_PRF";
	t[CKM_SSL3_MD5_MAC] = "CKM_SSL3_MD5_MAC";
	t[CKM_SSL3_SHA1_MAC] = "CKM_SSL3_SHA1_MAC";
	t[CKM_MD5_KEY_DERIVATION] = "CKM_MD5_KEY_DERIVATION";
	t[CKM_MD2_KEY_DERIVATION] = "CKM_MD2_KEY_DERIVATION";
	t[CKM_SHA1_KEY_DERIVATION] = "CKM_SHA1_KEY_DERIVATION";
	t[CKM_SHA256_KEY_DERIVATION] = "CKM_SHA256_KEY_DERIVATION";
	t[CKM_SHA384_KEY_DERIVATION] = "CKM_SHA384_KEY_DERIVATION";
	t[CKM_SHA512_KEY_DERIVATION] = "CKM_SHA512_KEY_DERIVATION";
	t[CKM_SHA224_KEY_DERIVATION] = "CKM_SHA224_KEY_DERIVATION";
	t[CKM_SHA3_256_KEY_DERIVE] = "CKM_SHA3_256_KEY_DERIVE";
	t[CKM_SHA3_224_KEY_DERIVE] = "CKM_SHA3_224_KEY_DERIVE";
	t[CKM_SHA3_384_KEY_DERIVE] = "CKM_SHA3_384_KEY_DERIVE";
	t[CKM_SHA3_512_KEY_DERIVE] = "CKM_SHA3_512_KEY_DERIVE";
	t[CKM_SHAKE_128_KEY_DERIVE] = "CKM_SHAKE_128_KEY_DERIVE";
	t[CKM_SHAKE_256_KEY_DERIVE] = "CKM_SHAKE_256_KEY_DERIVE";
	t[CKM_PBE_MD2_DES_CBC] = "CKM_PBE_MD2_DES_CBC";
	t[CKM_PBE_MD5_DES_CBC] = "CKM_PBE_MD5_DES_CBC";
	t[CKM_PBE_MD5_CAST_CBC] = "CKM_PBE_MD5_CAST_CBC";
	t[CKM_PBE_MD5_CAST3_CBC] = "CKM_PBE_MD5_CAST3_CBC";
	t[CKM_PBE_MD5_CAST128_CBC] = "CKM_PBE_MD5_CAST128_CBC";
	t[CKM_PBE_SHA1_CAST128_CBC] = "CKM_PBE_SHA1_CAST128_CBC";
	t[CKM_PBE_SHA1_RC4_128] = "CKM_PBE_SHA1_RC4_128";
	t[CKM_PBE_SHA1_RC4_40] = "CKM_PBE_SHA1_RC4_40";
	t[CKM_PBE_SHA1_DES3_EDE_CBC] = "CKM_PBE_SHA1_DES3_EDE_CBC";
	t[CKM_PBE_SHA1_DES2_EDE_CBC] = "CKM_PBE_SHA1_DES2_EDE_CBC";
	t[CKM_PBE_SHA1_RC2_128_CBC] = "CKM_PBE_SHA1_RC2_128_CBC";
	t[CKM_PBE_SHA1_RC2_40_CBC] = "CKM_PBE_SHA1_RC2_40_CBC";
	t[CKM_PKCS5_PBKD2] = "CKM_PKCS5_PBKD2";
	t[CKM_PBA_SHA1_WITH_SHA1_HMAC] = "CKM_PBA_SHA1_WITH_SHA1_HMAC";
	t[CKM_WTLS_PRE_MASTER_KEY_GEN] = "CKM_WTLS_PRE_MASTER_KEY_GEN";
	t[CKM_WTLS_MASTER_KEY_DERIVE] = "CKM_WTLS_MASTER_KEY_DERIVE";
	t[CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC] = "CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC";
	t[CKM_WTLS_PRF] = "CKM_WTLS_PRF";
	t[CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE] = "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE";
	t[CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE] = "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE";
	t[CKM_TLS10_MAC_SERVER] = "CKM_TLS10_MAC_SERVER";
	t[CKM_TLS10_MAC_CLIENT] = "CKM_TLS10_MAC_CLIENT";
	t[CKM_TLS12_MAC] = "CKM_TLS12_MAC";
	t[CKM_TLS12_KDF] = "CKM_TLS12_KDF";
	t[CKM_TLS12_MASTER_KEY_DERIVE] = "CKM_TLS12_MASTER_KEY_DERIVE";
	t[CKM_TLS12_KEY_AND_MAC_DERIVE] = "CKM_TLS12_KEY_AND_MAC_DERIVE";
	t[CKM_TLS12_MASTER_KEY_DERIVE_DH] = "CKM_TLS12_MASTER_KEY_DERIVE_DH";
	t[CKM_TLS12_KEY_SAFE_DERIVE] = "CKM_TLS12_KEY_SAFE_DERIVE";
	t[CKM_TLS_MAC] = "CKM_TLS_MAC";
	t[CKM_TLS_KDF] = "CKM_TLS_KDF";
	t[CKM_KEY_WRAP_LYNKS] = "CKM_KEY_WRAP_LYNKS";
	t[CKM_KEY_WRAP_SET_OAEP] = "CKM_KEY_WRAP_SET_OAEP";
	t[CKM_CMS_SIG] = "CKM_CMS_SIG";
	t[CKM_KIP_DERIVE] = "CKM_KIP_DERIVE";
	t[CKM_KIP_WRAP] = "CKM_KIP_WRAP";
	t[CKM_KIP_MAC] = "CKM_KIP_MAC";
	t[CKM_CAMELLIA_KEY_GEN] = "CKM_CAMELLIA_KEY_GEN";
	t[CKM_CAMELLIA_ECB] = "CKM_CAMELLIA_ECB";
	t[CKM_CAMELLIA_CBC] = "CKM_CAMELLIA_CBC";
	t[CKM_CAMELLIA_MAC] = "CKM_CAMELLIA_MAC";
	t[CKM_CAMELLIA_MAC_GENERAL] = "CKM_CAMELLIA_MAC_GENERAL";
	t[CKM_CAMELLIA_CBC_PAD] = "CKM_CAMELLIA_CBC_PAD";
	t[CKM_CAMELLIA_ECB_ENCRYPT_DATA] = "CKM_CAMELLIA_ECB_ENCRYPT_DATA";
	t[CKM_CAMELLIA_CBC_ENCRYPT_DATA] = "CKM_CAMELLIA_CBC_ENCRYPT_DATA";
	t[CKM_CAMELLIA_CTR] = "CKM_CAMELLIA_CTR";
	t[CKM_ARIA_KEY_GEN] = "CKM_ARIA_KEY_GEN";
	t[CKM_ARIA_ECB] = "CKM_ARIA_ECB";
	t[CKM_ARIA_CBC] = "CKM_ARIA_CBC";
	t[CKM_ARIA_MAC] = "CKM_ARIA_MAC";
	t[CKM_ARIA_MAC_GENERAL] = "CKM_ARIA_MAC_GENERAL";
	t[CKM_ARIA_CBC_PAD] = "CKM_ARIA_CBC_PAD";
	t[CKM_ARIA_ECB_ENCRYPT_DATA] = "CKM_ARIA_ECB_ENCRYPT_DATA";
	t[CKM_ARIA_CBC_ENCRYPT_DATA] = "CKM_ARIA_CBC_ENCRYPT_DATA";
	t[CKM_SEED_KEY_GEN] = "CKM_SEED_KEY_GEN";
	t[CKM_SEED_ECB] = "CKM_SEED_ECB";
	t[CKM_SEED_CBC] = "CKM_SEED_CBC";
	t[CKM_SEED_MAC] = "CKM_SEED_MAC";
	t[CKM_SEED_MAC_GENERAL] = "CKM_SEED_MAC_GENERAL";
	t[CKM_SEED_CBC_PAD] = "CKM_SEED_CBC_PAD";
	t[CKM_SEED_ECB_ENCRYPT_DATA] = "CKM_SEED_ECB_ENCRYPT_DATA";
	t[CKM_SEED_CBC_ENCRYPT_DATA] = "CKM_SEED_CBC_ENCRYPT_DATA";
	t[CKM_SKIPJACK_KEY_GEN] = "CKM_SKIPJACK_KEY_GEN";
	t[CKM_SKIPJACK_ECB64] = "CKM_SKIPJACK_ECB64";
	t[CKM_SKIPJACK_CBC64] = "CKM_SKIPJACK_CBC64";
	t[CKM_SKIPJACK_OFB64] = "CKM_SKIPJACK_OFB64";
	t[CKM_SKIPJACK_CFB64] = "CKM_SKIPJACK_CFB64";
	t[CKM_SKIPJACK_CFB32] = "CKM_SKIPJACK_CFB32";
	t[CKM_SKIPJACK_CFB16] = "CKM_SKIPJACK_CFB16";
	t[CKM_SKIPJACK_CFB8] = "CKM_SKIPJACK_CFB8";
	t[CKM_SKIPJACK_WRAP] = "CKM_SKIPJACK_WRAP";
	t[CKM_SKIPJACK_PRIVATE_WRAP] = "CKM_SKIPJACK_PRIVATE_WRAP";
	t[CKM_SKIPJACK_RELAYX] = "CKM_SKIPJACK_RELAYX";
	t[CKM_KEA_KEY_PAIR_GEN] = "CKM_KEA_KEY_PAIR_GEN";
	t[CKM_KEA_KEY_DERIVE] = "CKM_KEA_KEY_DERIVE";
	t[CKM_FORTEZZA_TIMESTAMP] = "CKM_FORTEZZA_TIMESTAMP";
	t[CKM_BATON_KEY_GEN] = "CKM_BATON_KEY_GEN";
	t[CKM_BATON_ECB128] = "CKM_BATON_ECB128";
	t[CKM_BATON_ECB96] = "CKM_BATON_ECB96";
	t[CKM_BATON_CBC128] = "CKM_BATON_CBC128";
	t[CKM_BATON_COUNTER] = "CKM_BATON_COUNTER";
	t[CKM_BATON_SHUFFLE] = "CKM_BATON_SHUFFLE";
	t[CKM_BATON_WRAP] = "CKM_BATON_WRAP";
	t[CKM_EC_KEY_PAIR_GEN] = "CKM_EC_KEY_PAIR_GEN";
	t[CKM_ECDSA] = "CKM_ECDSA";
	t[CKM_ECDSA_SHA1] = "CKM_ECDSA_SHA1";
	t[CKM_ECDSA_SHA224] = "CKM_ECDSA_SHA224";
	t[CKM_ECDSA_SHA256] = "CKM_ECDSA_SHA256";
	t[CKM_ECDSA_SHA384] = "CKM_ECDSA_SHA384";
	t[CKM_ECDSA_SHA512] = "CKM_ECDSA_SHA512";
	t[CKM_ECDH1_DERIVE] = "CKM_ECDH1_DERIVE";
	t[CKM_ECDH1_COFACTOR_DERIVE] = "CKM_ECDH1_COFACTOR_DERIVE";
	t[CKM_ECMQV_DERIVE] = "CKM_ECMQV_DERIVE";
	t[CKM_ECDH_AES_KEY_WRAP] = "CKM_ECDH_AES_KEY_WRAP";
	t[CKM_RSA_AES_KEY_WRAP] = "CKM_RSA_AES_KEY_WRAP";
	t[CKM_JUNIPER_KEY_GEN] = "CKM_JUNIPER_KEY_GEN";
	t[CKM_JUNIPER_ECB128] = "CKM_JUNIPER_ECB128";
	t[CKM_JUNIPER_CBC128] = "CKM_JUNIPER_CBC128";
	t[CKM_JUNIPER_COUNTER] = "CKM_JUNIPER_COUNTER";
	t[CKM_JUNIPER_SHUFFLE] = "CKM_JUNIPER_SHUFFLE";
	t[CKM_JUNIPER_WRAP] = "CKM_JUNIPER_WRAP";
	t[CKM_FASTHASH] = "CKM_FASTHASH";
	t[CKM_AES_KEY_GEN] = "CKM_AES_KEY_GEN";
	t[CKM_AES_ECB] = "CKM_AES_ECB";
	t[CKM_AES_CBC] = "CKM_AES_CBC";
	t[CKM_AES_MAC] = "CKM_AES_MAC";
	t[CKM_AES_MAC_GENERAL] = "CKM_AES_MAC_GENERAL";
	t[CKM_AES_CBC_PAD] = "CKM_AES_CBC_PAD";
	t[CKM_AES_CTR] = "CKM_AES_CTR";
	t[CKM_AES_GCM] = "CKM_AES_GCM";
	t[CKM_AES_CCM] = "CKM_AES_CCM";
	t[CKM_AES_CTS] = "CKM_AES_CTS";
	t[CKM_AES_CMAC] = "CKM_AES_CMAC";
	t[CKM_AES_CMAC_GENERAL] = "CKM_AES_CMAC_GENERAL";
	t[CKM_AES_XCBC_MAC] = "CKM_AES_XCBC_MAC";
	t[CKM_AES_XCBC_MAC_96] = "CKM_AES_XCBC_MAC_96";
	t[CKM_AES_GMAC] = "CKM_AES_GMAC";
	t[CKM_BLOWFISH_KEY_GEN] = "CKM_BLOWFISH_KEY_GEN";
	t[CKM_BLOWFISH_CBC] = "CKM_BLOWFISH_CBC";
	t[CKM_TWOFISH_KEY_GEN] = "CKM_TWOFISH_KEY_GEN";
	t[CKM_TWOFISH_CBC] = "CKM_TWOFISH_CBC";
	t[CKM_BLOWFISH_CBC_PAD] = "CKM_BLOWFISH_CBC_PAD";
	t[CKM_TWOFISH_CBC_PAD] = "CKM_TWOFISH_CBC_PAD";
	t[CKM_DES_ECB_ENCRYPT_DATA] = "CKM_DES_ECB_ENCRYPT_DATA";
	t[CKM_DES_CBC_ENCRYPT_DATA] = "CKM_DES_CBC_ENCRYPT_DATA";
	t[CKM_DES3_ECB_ENCRYPT_DATA] = "CKM_DES3_ECB_ENCRYPT_DATA";
	t[CKM_DES3_CBC_ENCRYPT_DATA] = "CKM_DES3_CBC_ENCRYPT_DATA";
	t[CKM_AES_ECB_ENCRYPT_DATA] = "CKM_AES_ECB_ENCRYPT_DATA";
	t[CKM_AES_CBC_ENCRYPT_DATA] = "CKM_AES_CBC_ENCRYPT_DATA";
	t[CKM_GOSTR3410_KEY_PAIR_GEN] = "CKM_GOSTR3410_KEY_PAIR_GEN";
	t[CKM_GOSTR3410] = "CKM_GOSTR3410";
	t[CKM_GOSTR3410_WITH_GOSTR3411] = "CKM_GOSTR3410_WITH_GOSTR3411";
	t[CKM_GOSTR3410_KEY_WRAP] = "CKM_GOSTR3410_KEY_WRAP";
	t[CKM_GOSTR3410_DERIVE] = "CKM_GOSTR3410_DERIVE";
	t[CKM_GOSTR3411] = "CKM_GOSTR3411";
	t[CKM_GOSTR3411_HMAC] = "CKM_GOSTR3411_HMAC";
	t[CKM_GOST28147_KEY_GEN] = "CKM_GOST28147_KEY_GEN";
	t[CKM_GOST28147_ECB] = "CKM_GOST28147_ECB";
	t[CKM_GOST28147] = "CKM_GOST28147";
	t[CKM_GOST28147_MAC] = "CKM_GOST28147_MAC";
	t[CKM_GOST28147_KEY_WRAP] = "CKM_GOST28147_KEY_WRAP";
	t[CKM_DSA_PARAMETER_GEN] = "CKM_DSA_PARAMETER_GEN";
	t[CKM_DH_PKCS_PARAMETER_GEN] = "CKM_DH_PKCS_PARAMETER_GEN";
	t[CKM_X9_42_DH_PARAMETER_GEN] = "CKM_X9_42_DH_PARAMETER_GEN";
	t[CKM_DSA_PROBABLISTIC_PARAMETER_GEN] = "CKM_DSA_PROBABLISTIC_PARAMETER_GEN";
	t[CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN] = "CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN";
	t[CKM_AES_OFB] = "CKM_AES_OFB";
	t[CKM_AES_CFB64] = "CKM_AES_CFB64";
	t[CKM_AES_CFB8] = "CKM_AES_CFB8";
	t[CKM_AES_CFB128] = "CKM_AES_CFB128";
	t[CKM_AES_CFB1] = "CKM_AES_CFB1";
	t[CKM_AES_KEY_WRAP] = "CKM_AES_KEY_WRAP";
	t[CKM_AES_KEY_WRAP_PAD] = "CKM_AES_KEY_WRAP_PAD";
	t[CKM_RSA_PKCS_TPM_1_1] = "CKM_RSA_PKCS_TPM_1_1";
	t[CKM_RSA_PKCS_OAEP_TPM_1_1] = "CKM_RSA_PKCS_OAEP_TPM_1_1";
}

void fill_CKO_table(std::map<unsigned long, std::string> &t)
{
	t[CKO_DATA] = "CKO_DATA";
	t[CKO_CERTIFICATE] = "CKO_CERTIFICATE";
	t[CKO_PUBLIC_KEY] = "CKO_PUBLIC_KEY";
	t[CKO_PRIVATE_KEY] = "CKO_PRIVATE_KEY";
	t[CKO_SECRET_KEY] = "CKO_SECRET_KEY";
	t[CKO_HW_FEATURE] = "CKO_HW_FEATURE";
	t[CKO_DOMAIN_PARAMETERS] = "CKO_DOMAIN_PARAMETERS";
	t[CKO_MECHANISM] = "CKO_MECHANISM";
	t[CKO_OTP_KEY] = "CKO_OTP_KEY";
}

void fill_CKH_table(std::map<unsigned long, std::string> &t)
{
	t[CKH_MONOTONIC_COUNTER] = "CKH_MONOTONIC_COUNTER";
	t[CKH_CLOCK] = "CKH_CLOCK";
	t[CKH_USER_INTERFACE] = "CKH_USER_INTERFACE";
}

void fill_CKK_table(std::map<unsigned long, std::string> &t)
{
	t[CKK_RSA] = "CKK_RSA";
	t[CKK_DSA] = "CKK_DSA";
	t[CKK_DH] = "CKK_DH";
	t[CKK_EC] = "CKK_EC";
	t[CKK_X9_42_DH] = "CKK_X9_42_DH";
	t[CKK_KEA] = "CKK_KEA";
	t[CKK_GENERIC_SECRET] = "CKK_GENERIC_SECRET";
	t[CKK_RC2] = "CKK_RC2";
	t[CKK_RC4] = "CKK_RC4";
	t[CKK_DES] = "CKK_DES";
	t[CKK_DES2] = "CKK_DES2";
	t[CKK_DES3] = "CKK_DES3";
	t[CKK_CAST] = "CKK_CAST";
	t[CKK_CAST3] = "CKK_CAST3";
	t[CKK_CAST128] = "CKK_CAST128";
	t[CKK_RC5] = "CKK_RC5";
	t[CKK_IDEA] = "CKK_IDEA";
	t[CKK_SKIPJACK] = "CKK_SKIPJACK";
	t[CKK_BATON] = "CKK_BATON";
	t[CKK_JUNIPER] = "CKK_JUNIPER";
	t[CKK_CDMF] = "CKK_CDMF";
	t[CKK_AES] = "CKK_AES";
	t[CKK_BLOWFISH] = "CKK_BLOWFISH";
	t[CKK_TWOFISH] = "CKK_TWOFISH";
	t[CKK_SECURID] = "CKK_SECURID";
	t[CKK_HOTP] = "CKK_HOTP";
	t[CKK_ACTI] = "CKK_ACTI";
	t[CKK_CAMELLIA] = "CKK_CAMELLIA";
	t[CKK_ARIA] = "CKK_ARIA";
	t[CKK_MD5_HMAC] = "CKK_MD5_HMAC";
	t[CKK_SHA_1_HMAC] = "CKK_SHA_1_HMAC";
	t[CKK_RIPEMD128_HMAC] = "CKK_RIPEMD128_HMAC";
	t[CKK_RIPEMD160_HMAC] = "CKK_RIPEMD160_HMAC";
	t[CKK_SHA256_HMAC] = "CKK_SHA256_HMAC";
	t[CKK_SHA384_HMAC] = "CKK_SHA384_HMAC";
	t[CKK_SHA512_HMAC] = "CKK_SHA512_HMAC";
	t[CKK_SHA224_HMAC] = "CKK_SHA224_HMAC";
	t[CKK_SEED] = "CKK_SEED";
	t[CKK_GOSTR3410] = "CKK_GOSTR3410";
	t[CKK_GOSTR3411] = "CKK_GOSTR3411";
	t[CKK_GOST28147] = "CKK_GOST28147";
	t[CKK_SHA3_224_HMAC] = "CKK_SHA3_224_HMAC";
	t[CKK_SHA3_256_HMAC] = "CKK_SHA3_256_HMAC";
	t[CKK_SHA3_384_HMAC] = "CKK_SHA3_384_HMAC";
	t[CKK_SHA3_512_HMAC] = "CKK_SHA3_512_HMAC";
}

void fill_CKC_table(std::map<unsigned long, std::string> &t)
{
	t[CKC_X_509] = "CKC_X_509";
	t[CKC_X_509_ATTR_CERT] = "CKC_X_509_ATTR_CERT";
	t[CKC_WTLS] = "CKC_WTLS";
	t[CKC_OPENPGP] = "CKC_OPENPGP";
}

#endif // !_SOFTHSM_V2_TABLES_H
