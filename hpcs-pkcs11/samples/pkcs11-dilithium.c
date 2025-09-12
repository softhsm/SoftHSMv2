 /****************************************************************
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * pkcs11-dilithium.c
 *
 * A sample application to interact with the HPCS PKCS11 library
 * 
 * Compile using:
 * gcc -o pkcs11-dilithium pkcs11-dilithium.c -ldl
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
   static CK_BBOOL         isFalse = FALSE;

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

   // Use Dilithium key to sign & verify
   printf("Generating Dilithium key pair... \n");
   /* Attributes for the public key to be generated */
   CK_KEY_TYPE keyType = CKK_IBM_PQC_DILITHIUM;
   CK_BYTE dilithium[] = {0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b, 0x01, 0x06, 0x05};
   CK_ATTRIBUTE pub_tmpl[] = {
      {CKA_TOKEN,           &isTrue, sizeof(isTrue) },
      {CKA_IBM_PQC_PARAMS,  &dilithium,   sizeof(dilithium) },
      {CKA_VERIFY,          &isTrue,  sizeof(isTrue) },
      {CKA_KEY_TYPE,        &keyType, sizeof(keyType) },
   };
 
   /* Attributes for the private key to be generated */
   CK_ATTRIBUTE priv_tmpl[] =
   {
      {CKA_TOKEN,           &isTrue, sizeof(isTrue) },
      {CKA_SIGN,            &isTrue, sizeof(isTrue) },
      {CKA_EXTRACTABLE,     &isFalse,  sizeof(isFalse) },
      {CKA_KEY_TYPE,        &keyType, sizeof(keyType) },
   };
   mech.mechanism      = CKM_IBM_DILITHIUM;
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

   printf("Signing with Dilithium private key... \n");
   CK_BYTE dataToBeSigned[] = "This is data to be signed";
   CK_ULONG dataToBeSignedLen = sizeof(dataToBeSigned) - 1;
   CK_BYTE signature[10240];
   CK_ULONG signatureLen = sizeof(signature);

   mech.mechanism      = CKM_IBM_DILITHIUM;
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

   printf("Verifying with Dilithium public key... \n");
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
