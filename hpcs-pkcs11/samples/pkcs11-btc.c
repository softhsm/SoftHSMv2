/****************************************************************
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * pkcs11-btc.c
 *
 * A sample application to interact with the HPCS PKCS11 library
 *
 * Compile using:
 * gcc -o pkcs11-btc pkcs11-btc.c -ldl
 *
 * Updates to be made within this source file:
 * Replace the text <so-user-api-key> with the SO user's PIN.
 * Replace the text <normal-user-api-key> with the normal user's PIN.
 * Replace the text <pkcs11-library> with name of your pkcs11 library.
 *
 * Ensure that your pkcs11 library is in your library path (LD_LIBRARY_PATH)
 * and the grep11client.yaml PKCS11 configuration file is in the /etc/ep11client directory. You may
 * need to create the /etc/ep11client directory, if it does not exist.
 *
 * NOTE: This sample code is expecting a default library name of pkcs11-grep11.so (See the pkcs11LibName variable).
 *       Feel free to change the name to match your pkcs11 library name.
 *
 * Please refer to https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api
 * for more information about the setup of the PKCS11 library and its configuration file.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include <sys/timeb.h>
#include "sample.h"

CK_FUNCTION_LIST  *funcs;
CK_BYTE           tokenNameBuf[32];
const char        tokenName[] = "testToken";

int main( int argc, char **argv )
{
    CK_C_INITIALIZE_ARGS  initArgs;
    CK_RV                   rc;
    CK_FLAGS                flags = 0;
    CK_SESSION_HANDLE       session;
    CK_MECHANISM            mech;
    CK_OBJECT_HANDLE        publicKey, privateKey, childPublicKey, childPrivateKey, genericKey, masterKey;
    static CK_BBOOL         isTrue = TRUE;

    CK_RV                   (*pFunc)();
    void                    *pkcs11Lib;
    CK_UTF8CHAR_PTR         soPin = (unsigned char *) "<so-user-api-key>";
    CK_UTF8CHAR_PTR         userPin = (unsigned char *) "<normal-user-api-key>";
    char                    pkcs11LibName[] = "pkcs11-grep11.so";

    printf("Opening the PKCS11 library...\n");
    pkcs11Lib = dlopen(pkcs11LibName, RTLD_NOW);
    if ( pkcs11Lib == NULL ) {
        printf("%s not found. Ensure that the PKCS11 library is in the system library path or LD_LIBRARY_PATH\n", pkcs11LibName);
        return !CKR_OK;
    }

    printf("Getting the PKCS11 function list...\n");
    pFunc = (CK_RV (*)())dlsym(pkcs11Lib, "C_GetFunctionList");
    if (pFunc == NULL ) {
        printf("C_GetFunctionList() not found in module %s\n", pkcs11LibName);
        return !CKR_OK;
    }
    rc = pFunc(&funcs);
    if (rc != CKR_OK) {
        printf("error C_GetFunctionList: rc=0x%04lx\n", rc );
        return !CKR_OK;
    }

    printf("Initializing the PKCS11 environment...\n");
    memset( &initArgs, 0x0, sizeof(initArgs) );
    rc = funcs->C_Initialize( &initArgs );
    if (rc != CKR_OK) {
        printf("error C_Initialize: rc=0x%04lx\n", rc );
        return !CKR_OK;
    }

    printf("Initializing the token... \n");
    memset(tokenNameBuf, ' ', sizeof(tokenNameBuf)); /* Token name is left justified, padded with blanks */
    memcpy(tokenNameBuf, tokenName, strlen(tokenName));

    /* C_InitToken cleans up private and public keystore thus only needs to be done once.
     * Subsequent C_InitToken calls will delete any existing keys within the keystores
     */
    rc= funcs->C_InitToken(0, soPin, strlen((const char *) soPin), tokenNameBuf);
    if (rc != CKR_OK) {
        printf("error C_InitToken: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    printf("Opening a session... \n");
    rc = funcs->C_OpenSession( 0, flags, (CK_VOID_PTR) NULL, NULL, &session );
    if (rc != CKR_OK) {
        printf("error C_OpenSession: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Logging in as normal user... \n");
    rc = funcs->C_Login( session, CKU_USER, userPin, strlen((const char *) userPin));
    if (rc != CKR_OK) {
        printf("error C_Login: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    CK_ULONG genericKeyLen = 32;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_ATTRIBUTE genericTmpl[] = {
        {CKA_CLASS,           &objClass,        sizeof(objClass) },
        {CKA_KEY_TYPE,        &keyType,        sizeof(keyType) },
        {CKA_VALUE_LEN,       &genericKeyLen,  sizeof(genericKeyLen) },
        {CKA_DERIVE,          &isTrue,         sizeof(isTrue) },
        {CKA_IBM_USE_AS_DATA, &isTrue,         sizeof(isTrue) },
    };

    mech.mechanism      = CKM_GENERIC_SECRET_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;
    rc = funcs->C_GenerateKey( session, &mech, genericTmpl, sizeof(genericTmpl)/sizeof(CK_ATTRIBUTE), &genericKey);
    if (rc != CKR_OK) {
        printf("error C_GenerateKey: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Generating Master key... \n");
    objClass = CKO_PRIVATE_KEY;
    keyType = CKK_EC;
    CK_BYTE curve_name[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a};
    CK_ULONG valueLen = 0;
    CK_ATTRIBUTE masterTmpl[] = {
        {CKA_CLASS,            &objClass,        sizeof(objClass) },
        {CKA_KEY_TYPE,         &keyType,         sizeof(keyType) },
        {CKA_DERIVE,           &isTrue,          sizeof(isTrue) },
        {CKA_EC_PARAMS,        &curve_name,      sizeof(curve_name) },
        {CKA_IBM_USE_AS_DATA,  &isTrue,          sizeof(isTrue) },
        {CKA_VALUE_LEN,        &valueLen,        sizeof(valueLen) },
    };

    CK_BYTE chainCode[32] = {};
    memset(chainCode, 0, 32);
    CK_IBM_BTC_DERIVE_PARAMS btcDeriveParams = {
        .type           = (CK_ULONG)CK_IBM_BIP0032_MASTERK,
        .childKeyIndex  = 0,
        .pChainCode     = chainCode,
        .ulChainCodeLen = 0,
        .version        = XCP_BTC_VERSION,
    };

    mech.mechanism      = CKM_IBM_BTC_DERIVE;
    mech.pParameter     = (CK_VOID_PTR)&btcDeriveParams;
    mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
    rc = funcs->C_DeriveKey(session, &mech, genericKey, masterTmpl, sizeof(masterTmpl)/sizeof(CK_ATTRIBUTE), &masterKey);
    if (rc != CKR_OK) {
        printf("error C_DeriveKey: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    objClass = CKO_PRIVATE_KEY;
    keyType = CKK_EC;
    valueLen = 0;
    CK_ATTRIBUTE privDeriveTmpl[] = {
        {CKA_CLASS,            &objClass,        sizeof(objClass) },
        {CKA_KEY_TYPE,         &keyType,         sizeof(keyType) },
        {CKA_DERIVE,           &isTrue,          sizeof(isTrue) },
        {CKA_EC_PARAMS,        &curve_name,      sizeof(curve_name) },
        {CKA_IBM_USE_AS_DATA,  &isTrue,          sizeof(isTrue) },
        {CKA_VALUE_LEN,        &valueLen,        sizeof(valueLen) },
        {CKA_SIGN,             &isTrue,          sizeof(isTrue) },
    };

    btcDeriveParams.type           = (CK_ULONG)CK_IBM_BIP0032_PRV2PRV;
    btcDeriveParams.childKeyIndex  = 0;
    btcDeriveParams.pChainCode     = chainCode;
    btcDeriveParams.ulChainCodeLen = 32;
    btcDeriveParams.version        = XCP_BTC_VERSION;

    mech.mechanism      = CKM_IBM_BTC_DERIVE;
    mech.pParameter     = (CK_VOID_PTR)&btcDeriveParams;
    mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
    rc = funcs->C_DeriveKey(session, &mech, masterKey, privDeriveTmpl, sizeof(privDeriveTmpl)/sizeof(CK_ATTRIBUTE), &privateKey);
    if (rc != CKR_OK) {
        printf("error C_DeriveKey: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    objClass = CKO_PUBLIC_KEY;
    keyType = CKK_EC;
    valueLen = 0;
    CK_ATTRIBUTE pubDeriveTmpl[] = {
        {CKA_CLASS,            &objClass,        sizeof(objClass) },
        {CKA_KEY_TYPE,         &keyType,         sizeof(keyType) },
        {CKA_DERIVE,           &isTrue,          sizeof(isTrue) },
        {CKA_EC_PARAMS,        &curve_name,      sizeof(curve_name) },
        {CKA_IBM_USE_AS_DATA,  &isTrue,          sizeof(isTrue) },
        {CKA_VALUE_LEN,        &valueLen,        sizeof(valueLen) },
        {CKA_VERIFY,           &isTrue,          sizeof(isTrue) },
    };

    btcDeriveParams.type           = (CK_ULONG)CK_IBM_BIP0032_PRV2PUB;
    btcDeriveParams.childKeyIndex  = 0;
    btcDeriveParams.pChainCode     = chainCode;
    btcDeriveParams.ulChainCodeLen = 32;
    btcDeriveParams.version        = XCP_BTC_VERSION;

    mech.mechanism      = CKM_IBM_BTC_DERIVE;
    mech.pParameter     = (CK_VOID_PTR)&btcDeriveParams;
    mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
    rc = funcs->C_DeriveKey(session, &mech, masterKey, pubDeriveTmpl, sizeof(pubDeriveTmpl)/sizeof(CK_ATTRIBUTE), &publicKey);
    if (rc != CKR_OK) {
        printf("error C_DeriveKey: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Signing with ECDSA private key... \n");
    CK_BYTE dataToBeSigned[] = "This is data to be signed";
    CK_ULONG dataToBeSignedLen = sizeof(dataToBeSigned) - 1;
    CK_BYTE signature[64]; // minimum 64 bytes in P-256 case
    CK_ULONG signatureLen = sizeof(signature);

    mech.mechanism      = CKM_ECDSA;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;
    rc = funcs->C_SignInit(session, &mech, privateKey);
    if (rc != CKR_OK) {
        printf("error C_SignInit: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    rc = funcs->C_Sign(session, dataToBeSigned, dataToBeSignedLen, signature, &signatureLen);
    if (rc != CKR_OK) {
        printf("error C_Sign: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Verifying with ECDSA public key... \n");
    rc = funcs->C_VerifyInit(session, &mech, publicKey);
    if (rc != CKR_OK) {
        printf("error C_VerifyInit: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    rc = funcs->C_Verify(session, dataToBeSigned, dataToBeSignedLen, signature, signatureLen);
    if (rc != CKR_OK) {
        printf("error C_Verify: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    unsigned char checkValue[32];
    CK_ATTRIBUTE attrs_tmpl[] = {
        {CKA_CHECK_VALUE, checkValue,  sizeof(checkValue) },
    };
    funcs->C_GetAttributeValue(session, privateKey, attrs_tmpl, sizeof(attrs_tmpl)/sizeof(CK_ATTRIBUTE));
    if (rc != CKR_OK) {
        printf("error C_GetAttributeValue: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    objClass = CKO_PRIVATE_KEY;
    keyType = CKK_EC;
    valueLen = 0;
    CK_ATTRIBUTE childPrivDeriveTmpl[] = {
        {CKA_CLASS,            &objClass,        sizeof(objClass) },
        {CKA_KEY_TYPE,         &keyType,         sizeof(keyType) },
        {CKA_DERIVE,           &isTrue,          sizeof(isTrue) },
        {CKA_EC_PARAMS,        &curve_name,      sizeof(curve_name) },
        {CKA_IBM_USE_AS_DATA,  &isTrue,          sizeof(isTrue) },
        {CKA_VALUE_LEN,        &valueLen,        sizeof(valueLen) },
        {CKA_SIGN,             &isTrue,          sizeof(isTrue) },
    };

    btcDeriveParams.type           = (CK_ULONG)CK_IBM_BIP0032_PRV2PRV;
    btcDeriveParams.childKeyIndex  = 0;
    btcDeriveParams.pChainCode     = checkValue;
    btcDeriveParams.ulChainCodeLen = 32;
    btcDeriveParams.version        = XCP_BTC_VERSION;

    mech.mechanism      = CKM_IBM_BTC_DERIVE;
    mech.pParameter     = (CK_VOID_PTR)&btcDeriveParams;
    mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
    rc = funcs->C_DeriveKey(session, &mech, privateKey, childPrivDeriveTmpl, sizeof(childPrivDeriveTmpl)/sizeof(CK_ATTRIBUTE), &childPrivateKey);
    if (rc != CKR_OK) {
        printf("error C_DeriveKey: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    objClass = CKO_PUBLIC_KEY;
    keyType = CKK_EC;
    valueLen = 0;
    CK_ATTRIBUTE childPubDeriveTmpl[] = {
        {CKA_CLASS,            &objClass,        sizeof(objClass) },
        {CKA_KEY_TYPE,         &keyType,         sizeof(keyType) },
        {CKA_DERIVE,           &isTrue,          sizeof(isTrue) },
        {CKA_EC_PARAMS,        &curve_name,      sizeof(curve_name) },
        {CKA_IBM_USE_AS_DATA,  &isTrue,          sizeof(isTrue) },
        {CKA_VALUE_LEN,        &valueLen,        sizeof(valueLen) },
        {CKA_VERIFY,           &isTrue,          sizeof(isTrue) },
    };

    btcDeriveParams.type           = (CK_ULONG)CK_IBM_BIP0032_PRV2PUB;
    btcDeriveParams.childKeyIndex  = 0;
    btcDeriveParams.pChainCode     = checkValue;
    btcDeriveParams.ulChainCodeLen = 32;
    btcDeriveParams.version        = XCP_BTC_VERSION;

    mech.mechanism      = CKM_IBM_BTC_DERIVE;
    mech.pParameter     = (CK_VOID_PTR)&btcDeriveParams;
    mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
    rc = funcs->C_DeriveKey(session, &mech, privateKey, childPubDeriveTmpl, sizeof(childPubDeriveTmpl)/sizeof(CK_ATTRIBUTE), &childPublicKey);
    if (rc != CKR_OK) {
        printf("error C_DeriveKey: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    mech.mechanism      = CKM_ECDSA;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;
    rc = funcs->C_SignInit(session, &mech, childPrivateKey);
    if (rc != CKR_OK) {
        printf("error C_SignInit: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    rc = funcs->C_Sign(session, dataToBeSigned, dataToBeSignedLen, signature, &signatureLen);
    if (rc != CKR_OK) {
        printf("error C_Sign: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Verifying with ECDSA public key... \n");
    rc = funcs->C_VerifyInit(session, &mech, childPublicKey);
    if (rc != CKR_OK) {
        printf("error C_VerifyInit: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    rc = funcs->C_Verify(session, dataToBeSigned, dataToBeSignedLen, signature, signatureLen);
    if (rc != CKR_OK) {
        printf("error C_Verify: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Logging out... \n");
    rc = funcs->C_Logout(session);
    if (rc != CKR_OK) {
        printf("error C_Logout: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Closing the session... \n");
    rc = funcs->C_CloseSession( session );
    if (rc != CKR_OK) {
        printf("error C_CloseSession: rc=0x%04lx\n", rc );
        return !CKR_OK;
    }

    printf("Finalizing... \n");
    rc = funcs->C_Finalize( NULL );
    if (rc != CKR_OK) {
        printf("error C_Finalize: rc=0x%04lx\n", rc );
        return !CKR_OK;
    }
    printf("Sample completed successfully!\n");
    return 0;
}
