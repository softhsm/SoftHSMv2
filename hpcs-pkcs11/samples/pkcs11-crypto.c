/****************************************************************
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * pkcs11-crypto.c
 *
 * A sample application to interact with the HPCS PKCS11 library
 * 
 * Compile using:
 * gcc -o pkcs11-crypto pkcs11-crypto.c -ldl
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
    CK_OBJECT_HANDLE        publicKey, privateKey, aesKey;
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

    // User AES key to encrypt & decrypt
    printf("Generating AES key... \n");
    CK_ULONG aesKeyLen = 16;
    CK_ATTRIBUTE aes_tmpl[] = {
        {CKA_TOKEN,        &isTrue,     sizeof(isTrue) },
        {CKA_VALUE_LEN,    &aesKeyLen,  sizeof(aesKeyLen) },
        {CKA_ENCRYPT,      &isTrue,     sizeof(isTrue) },
        {CKA_DECRYPT,      &isTrue,     sizeof(isTrue) },
    };
    mech.mechanism      = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    rc = funcs->C_GenerateKey( session, &mech, aes_tmpl, sizeof(aes_tmpl)/sizeof(CK_ATTRIBUTE), &aesKey);
    if (rc != CKR_OK) {
        printf("error C_GenerateKey: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    CK_BYTE iv[16];
    rc = funcs->C_GenerateRandom(session, (CK_BYTE_PTR)iv, sizeof(iv));
    if (rc != CKR_OK) {
        printf("error C_GenerateRandom: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    CK_BYTE clearTxt[] = "this is clear text to be encrypted";
    CK_ULONG clearTxtLen = strlen(clearTxt);
    CK_BYTE encrypted[64]; // input length rounded up to multiple of the block size (16 bytes)
    CK_ULONG encryptedLen = sizeof(encrypted);
    CK_BYTE decrypted[64];
    CK_ULONG decryptedLen = sizeof(decrypted);

    mech.mechanism      = CKM_AES_CBC_PAD;
    mech.ulParameterLen = sizeof(iv);
    mech.pParameter     = &iv;

    printf("Encrypting with AES key by using C_EncryptInit/C_Encrypt functions... \n");
    rc = funcs->C_EncryptInit(session, &mech, aesKey);
    if (rc != CKR_OK) {
        printf("error C_EncryptInit: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    rc = funcs->C_Encrypt(session, clearTxt, clearTxtLen, encrypted, &encryptedLen);
    if (rc != CKR_OK) {
        printf("error C_Encrypt: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Decrypting with AES key by using C_DecryptInit/C_Decrypt functions... \n");
    rc = funcs->C_DecryptInit(session, &mech, aesKey);
    if (rc != CKR_OK) {
        printf("error C_DecryptInit: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    rc = funcs->C_Decrypt(session, encrypted, encryptedLen, decrypted, &decryptedLen);
    if (rc != CKR_OK) {
        printf("error C_Decrypt: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    if ( decryptedLen != clearTxtLen || memcmp(clearTxt, decrypted, decryptedLen) != 0) {
        printf("Clear text is different from decrypted data[%lu]\n", decryptedLen);
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    printf("Encrypting with AES key by using C_EncryptInit/C_EncryptUpdate/C_EncryptFinal functions... \n");
    rc = funcs->C_EncryptInit(session, &mech, aesKey);
    if (rc != CKR_OK) {
        printf("error C_EncryptInit: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    // Encrypt the first chunk, 16 bytes
    CK_BYTE tmp[64];
    CK_ULONG tmplen = sizeof(tmp);
    encryptedLen = 0;
    rc = funcs->C_EncryptUpdate(session, clearTxt, 16, tmp, &tmplen);
    if (rc != CKR_OK) {
        printf("error C_EncryptUpdate: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }
    memcpy(encrypted, tmp, tmplen);
    encryptedLen += tmplen;

    // Encrypt the second chunk, 16 bytes
    tmplen = sizeof(tmp);
    rc = funcs->C_EncryptUpdate(session, &clearTxt[16], 16, tmp, &tmplen);
    if (rc != CKR_OK) {
        printf("error C_EncryptUpdate: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }
    memcpy(&encrypted[encryptedLen], tmp, tmplen);
    encryptedLen += tmplen;

    // Encrypt the rest bytes
    tmplen = sizeof(tmp);
    rc = funcs->C_EncryptUpdate(session, &clearTxt[32], (int)clearTxtLen - 32, tmp, &tmplen);
    if (rc != CKR_OK) {
        printf("error C_EncryptUpdate: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }
    memcpy(&encrypted[encryptedLen], tmp, tmplen);
    encryptedLen += tmplen;

    tmplen = sizeof(tmp);
    rc = funcs->C_EncryptFinal(session, tmp, &tmplen);
    if (rc != CKR_OK) {
        printf("error C_EncryptFinal: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }
    memcpy(&encrypted[encryptedLen], tmp, tmplen);
    encryptedLen += tmplen;

    printf("Decrypting with AES key by using C_DecryptInit/C_DecryptUpdate/C_DecryptFinal functions... \n");
    rc = funcs->C_DecryptInit(session, &mech, aesKey);
    if (rc != CKR_OK) {
        printf("error C_DecryptInit: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    // Decrypt the first chunk, 16 bytes
    decryptedLen = 0;
    tmplen = sizeof(tmp);
    rc = funcs->C_DecryptUpdate(session, encrypted, 16, tmp, &tmplen);
    if (rc != CKR_OK) {
        printf("error C_DecryptUpdate: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }
    memcpy(decrypted, tmp, tmplen);
    decryptedLen += tmplen;

    // Decrypt the second chunk, 16 bytes
    tmplen = sizeof(tmp);
    rc = funcs->C_DecryptUpdate(session, &encrypted[16], 16, tmp, &tmplen);
    if (rc != CKR_OK) {
        printf("error C_DecryptUpdate: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }
    memcpy(&decrypted[decryptedLen], tmp, tmplen);
    decryptedLen += tmplen;

    // Decrypt the rest bytes
    tmplen = sizeof(tmp);
    rc = funcs->C_DecryptUpdate(session, &encrypted[32], (int)encryptedLen - 32, tmp, &tmplen);
    if (rc != CKR_OK) {
        printf("error C_DecryptUpdate: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }
    memcpy(&decrypted[decryptedLen], tmp, tmplen);
    decryptedLen += tmplen;

    tmplen = sizeof(tmp);
    rc = funcs->C_DecryptFinal(session, tmp, &tmplen);
    if (rc != CKR_OK) {
        printf("error C_DecryptFinal: rc=0x%04lx\n", rc );
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }
    memcpy(&decrypted[decryptedLen], tmp, tmplen);
    decryptedLen += tmplen;

    if ( decryptedLen != clearTxtLen || memcmp(clearTxt, decrypted, decryptedLen) != 0) {
        printf("Clear text is different from decrypted data[%lu]\n", decryptedLen);
        funcs->C_Finalize( NULL );
        return !CKR_OK;
    }

    // Use ECDSA key to sign & verify
    printf("Generating ECDSA key pair... \n");
    /* Attributes for the public key to be generated */
    CK_BYTE curve_name[] = "P-256";
    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_TOKEN,           &isTrue, sizeof(isTrue) },
        {CKA_EC_PARAMS,       &curve_name,   strlen( (const char *) curve_name) },
        {CKA_VERIFY,          &isTrue,  sizeof(isTrue) },
    };

    /* Attributes for the private key to be generated */
    CK_ATTRIBUTE priv_tmpl[] =
    {
        {CKA_TOKEN,    &isTrue, sizeof(isTrue) },
        {CKA_SIGN,     &isTrue, sizeof(isTrue) }
    };
    mech.mechanism      = CKM_EC_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;

    rc = funcs->C_GenerateKeyPair( session,   &mech,
            pub_tmpl,   sizeof(pub_tmpl)/sizeof(CK_ATTRIBUTE),
            priv_tmpl,  sizeof(priv_tmpl)/sizeof(CK_ATTRIBUTE),
            &publicKey, &privateKey );
    if (rc != CKR_OK) {
        printf("error C_GenerateKeyPair: rc=0x%04lx\n", rc );
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
