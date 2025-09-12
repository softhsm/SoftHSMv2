 /****************************************************************
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * pkcs11-checksum.c
 *
 * A sample application demonstrating how to verify the checksum of key using the PKCS11 library
 * 
 * Compile using:
 * gcc -o pkcs11-checksum pkcs11-checksum.c -ldl
 * 
 * Usage:
 * /pkcs11-checksum -p <path to pkcs11 library> -s <SO user API key> -u <normal user API key> -m [generate|verify]
 * Ensure that the grep11client.yaml PKCS11 configuration file is in the /etc/ep11client directory. You may
 * need to create the /etc/ep11client directory, if it does not exist.
 *
 * Steps to verify keys:
 * Step 1 /pkcs11-checksum -p <path to pkcs11 library> -s <SO user API key> -u <normal user API key> -m generate
 *        Step 1 generates AES/DES3/DES2 keys and stores their respective checksums into three files (e.g. "AES_key").
 * Step 2 /pkcs11-checksum -p <path to pkcs11 library> -s <SO user API key> -u <normal user API key> -m verify
 *        Step 2 loads the generated keys and re-calculates their respective checksums and compares them against the checksums stored in files.
 *        For example, this step loads the checksum from the "AES_key" file as checksum A. Then it retrieves the AES key from the keystore
 *        and calculates checksum B. Finally, it compares checksum A and checksum B. If they match, the key store has NOT been tampered with.
 *
 * Please refer to https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api
 * for more information about the setup of the PKCS11 library and its configuration file.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <ctype.h>
#include <memory.h>
#include <dlfcn.h>
#include <sys/timeb.h>
#include "sample.h"

const char * getKeyTypeStr(CK_KEY_TYPE keyType) {
    switch (keyType) {
    case CKK_AES:
        return "AES";
    case CKK_RSA:
        return "RSA";
    case CKK_EC:
        return "EC";
    case CKK_DES3:
        return "DES3";
    case CKK_DES2:
        return "DES2";
    default:
        return "Unknown key type";
    }
}

CK_FUNCTION_LIST  *funcs;
CK_BYTE           tokenNameBuf[32];
const char        tokenName[] = "testToken";

CK_UTF8CHAR         soPin[256] = {0};
CK_UTF8CHAR         userPin[256] = {0};
char                pkcs11LibName[1024] = {0};
char                fileName[1024] = {0};
int                 opMode = 0;

void getArgs(int argc, char **argv) {
    int c, n;

    static struct option long_options[] = {
        {"librarypath",    required_argument, NULL, 'p'},
        {"SOpin",     required_argument, NULL, 's'},
        {"userpin",   required_argument, NULL, 'u'},
        {"mode", required_argument, NULL, 'm'},
        {0, 0, 0, 0}
    };

    while (1)
    {
      c = getopt_long (argc, argv, "p:s:u:m:", long_options, NULL);

      /* Detect the end of the options. */
      if (c == -1)
        break;

      switch (c)
        {
        case 'p':
          n = snprintf(pkcs11LibName, sizeof(pkcs11LibName), "%s", optarg);
          if (n < strlen(optarg)) {
              printf("Path to library is too long\n");
              exit(1);
          }
          break;

        case 's':
            n = snprintf((char *)soPin, sizeof(soPin), "%s", optarg);
            if (n < strlen(optarg)) {
                printf("SO pin is too long\n");
                exit(1);
            }
          break;

        case 'u':
            n = snprintf((char *)userPin, sizeof(userPin), "%s", optarg);
            if (n < strlen(optarg)) {
                printf("Normal user pin is too long\n");
                exit(1);
            }
          break;

        case 'm':
            if (strncmp(optarg, "generate", strlen(optarg)) == 0) {
                opMode = 1;
            } else if (strncmp(optarg, "verify", strlen(optarg)) == 0) {
                opMode = 2;
            } else {
                printf("Usage: ./pkcs11-checksum -p <path to pkcs11 library> -s <SO user API key> -u <normal user API key> "\
                        "-m [generate|verify]\n");
                exit(1);
            }

            break;

        default:
          printf("Usage: ./pkcs11-checksum -p <path to pkcs11 library> -s <SO user API key> -u <normal user API key> "\
                  "-m [generate|verify]\n");
          exit(1);
        }
    }

    if (strlen((char *)soPin) == 0 || strlen((char *)userPin) == 0 || strlen(pkcs11LibName) == 0) {
        printf("Usage: ./pkcs11-attrs -p <path to pkcs11 library> -s <SO user API key> -u <normal user API key>\n");
        exit(1);
    }
}

const char aesLabel[] = "AES_key";
const char des3Label[] = "DES3_key";
const char des2Label[] = "DES2_key";
const char genericLable[] = "Generic_key";

//
int verifyChecksumFromFile(CK_SESSION_HANDLE session, CK_KEY_TYPE keyType) {
    CK_MECHANISM     mech;
    const char * pLabel;
    CK_ULONG plainSize = 0, cipherSize = 0;
    unsigned char plain[32]; // big enough to hold AES, DES3, DES2 and generic 00 block
    unsigned char cipher[32]; // big enough to hold AES, DES3, DES2 and generic encryption output
    unsigned char checksumFromFile[3];
    unsigned char checksum[3];
    CK_RV rc;
    int iret = -1;

    memset(plain, 0, sizeof(plain));
    CK_ATTRIBUTE attrs_tmpl[] = {
       {CKA_CHECK_VALUE, checksum,  sizeof(checksum) },
    };

    switch (keyType) {
    case CKK_AES:
        mech.mechanism = CKM_AES_ECB;
        pLabel = aesLabel;
        plainSize = 16;
        cipherSize = 16;
        break;
    case CKK_DES3:
        mech.mechanism = CKM_DES3_ECB;
        pLabel = des3Label;
        plainSize = 8;
        cipherSize = 8;
        break;
    case CKK_DES2:
        mech.mechanism = CKM_DES3_ECB; // CKM_DES3_ECB supports DES2
        pLabel = des2Label;
        plainSize = 8;
        cipherSize = 8;
        break;
    default:
        break;
    }
    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;
    printf("Verifying %s key\n", getKeyTypeStr(keyType));

    // Read checksum from file
    int hfile = -1;
    size_t ret = 0;
    hfile = open(pLabel, O_RDONLY);
    if (hfile < 0) {
        printf("error opening file %s to read\n", pLabel);
        goto exit_func;
    }
    ret = read(hfile, checksumFromFile, sizeof(checksumFromFile));
    if (ret != sizeof(checksumFromFile)) {
        printf("error reading file %s [%ld] \n", pLabel, ret);
        close(hfile);
        goto exit_func;
    }
    printf("Checksum [%02x:%02x:%02x] is loaded from file %s\n", checksumFromFile[0], checksumFromFile[1], checksumFromFile[2], pLabel);
    close(hfile);

    // Find the key
    CK_OBJECT_HANDLE handles[1];
    CK_OBJECT_HANDLE  hKey;
    CK_ATTRIBUTE find_tmpl[] = {
     {CKA_LABEL,  (CK_VOID_PTR)pLabel,    strlen(pLabel) },
    };

    rc = funcs->C_FindObjectsInit( session, find_tmpl, sizeof(find_tmpl)/sizeof(CK_ATTRIBUTE));
    if (rc != CKR_OK) {
       printf("error C_FindObjectsInit: rc=0x%04lx\n", rc);
       goto exit_func;
    }
    CK_ULONG actualHandles = 0;
    rc = funcs->C_FindObjects(session, handles, sizeof(handles)/sizeof(CK_OBJECT_HANDLE), &actualHandles);
    if (rc != CKR_OK) {
       printf("error C_FindObjects: rc=0x%04lx\n", rc );
       goto exit_func;
    }
    if (actualHandles != 1) {
        printf("error C_FindObjects: unexpected number of objects returned: %ld\n", actualHandles );
        goto exit_func;
    }
    hKey = handles[0];
    rc = funcs->C_FindObjectsFinal(session);
    if (rc != CKR_OK) {
       printf("error C_FindObjectsFinal: rc=0x%04lx\n", rc );
       goto exit_func;
    }

    // Calculate checksum with key
    rc = funcs->C_EncryptInit(session, &mech, hKey);
    if (rc != CKR_OK) {
        printf("error C_EncryptInit: rc=0x%04lx\n", rc );
        goto exit_func;
    }
    rc = funcs->C_Encrypt(session, plain, plainSize, cipher, &cipherSize);
    if (rc != CKR_OK) {
        printf("error C_Encrypt: rc=0x%04lx\n", rc );
        goto exit_func;
    }
    if (plainSize != cipherSize) {
        printf("Cipher data length [%ld] does not match plain data length [%ld]\n", cipherSize, plainSize);
        goto exit_func;
    }
    printf("Calculated checksum is [%02x:%02x:%02x]\n", cipher[0], cipher[1], cipher[2]);

    // Compare checksum
    if (memcmp(checksumFromFile, cipher, sizeof(checksumFromFile)) == 0) {
        printf("Checksum matches\n");
    } else {
        printf("Checksum does not match\n");
        goto exit_func;
    }

    iret = 1;

exit_func:
    return iret;
}

// This function returns 1, if successful. Save the key checksum into a file (e.g., AES_key)
int generateKeyChecksum(CK_SESSION_HANDLE session, CK_KEY_TYPE keyType) {
    static CK_BBOOL  isTrue = TRUE;
    CK_MECHANISM     mech;
    CK_ATTRIBUTE_PTR pGenKeyTmpl;
    int attrAmt = 0;
    const char * pLabel;
    CK_OBJECT_HANDLE  hKey;
    CK_RV rc;
    int iret = -1;

    unsigned char checksum[3];
    CK_ATTRIBUTE attrs_tmpl[] = {
            {CKA_CHECK_VALUE, checksum,  sizeof(checksum) },
    };

    // For AES
    CK_ULONG aesKeyLen = 16;
    CK_ATTRIBUTE aes_tmpl[] = {
     {CKA_LABEL,        (CK_VOID_PTR)aesLabel,    strlen(aesLabel) },
     {CKA_TOKEN,        &isTrue,     sizeof(isTrue) },
     {CKA_VALUE_LEN,    &aesKeyLen,  sizeof(aesKeyLen) },
     {CKA_ENCRYPT,      &isTrue,     sizeof(isTrue) },
     {CKA_DECRYPT,      &isTrue,     sizeof(isTrue) },
    };

    // For DES3 TBD
    CK_ATTRIBUTE des3_tmpl[] = {
     {CKA_LABEL,        (CK_VOID_PTR)des3Label,    strlen(des3Label) },
     {CKA_TOKEN,        &isTrue,     sizeof(isTrue) },
     {CKA_ENCRYPT,      &isTrue,     sizeof(isTrue) },
     {CKA_DECRYPT,      &isTrue,     sizeof(isTrue) },
    };
    // For DES2 TBD
    CK_ATTRIBUTE des2_tmpl[] = {
     {CKA_LABEL,        (CK_VOID_PTR)des2Label,    strlen(des2Label) },
     {CKA_TOKEN,        &isTrue,     sizeof(isTrue) },
     {CKA_ENCRYPT,      &isTrue,     sizeof(isTrue) },
     {CKA_DECRYPT,      &isTrue,     sizeof(isTrue) },
    };
    // For generic key

    switch (keyType) {
    case CKK_AES:
        pLabel = aesLabel;
        pGenKeyTmpl = aes_tmpl;
        attrAmt = sizeof(aes_tmpl) / sizeof(CK_ATTRIBUTE);
        mech.mechanism      = CKM_AES_KEY_GEN;
        break;
    case CKK_DES3:
        pLabel = des3Label;
        pGenKeyTmpl = des3_tmpl;
        attrAmt = sizeof(des3_tmpl) / sizeof(CK_ATTRIBUTE);
        mech.mechanism      = CKM_DES3_KEY_GEN;
        break;
    case CKK_DES2:
        pLabel = des2Label;
        pGenKeyTmpl = des2_tmpl;
        attrAmt = sizeof(des2_tmpl) / sizeof(CK_ATTRIBUTE);
        mech.mechanism      = CKM_DES2_KEY_GEN;
        break;
    default:
        break;
    }

    mech.ulParameterLen = 0;
    mech.pParameter     = NULL;
    printf("Generating %s key...\n", getKeyTypeStr(keyType));
    rc = funcs->C_GenerateKey( session, &mech, pGenKeyTmpl, attrAmt, &hKey);
    if (rc != CKR_OK) {
        goto exit_func;
    }

    funcs->C_GetAttributeValue(session, hKey, attrs_tmpl, sizeof(attrs_tmpl)/sizeof(CK_ATTRIBUTE));
    if (attrs_tmpl[0].ulValueLen == CK_UNAVAILABLE_INFORMATION)  {
        printf("CKA_CHECK_VALUE is not available\n");
    } else if (attrs_tmpl[0].ulValueLen != 3) {
        printf("CKA_CHECK_VALUE is not %d bytes [%ld]\n", 3, attrs_tmpl[0].ulValueLen);
    }

    int hfile = -1, ret = -1;
    hfile = open(pLabel, O_WRONLY|O_CREAT, 0666);
    if (hfile < 0) {
        printf("error opening file %s to write\n", pLabel);
        goto exit_func;
    }
    ret = write(hfile, checksum, sizeof(checksum));
    if (ret < 0) {
        printf("error writing file %s\n", pLabel);
        goto exit_func;
    }
    printf("checksum is saved into file %s\n", pLabel);
    close(hfile);
    iret = 1;

exit_func:
    return iret;
}

int main( int argc, char **argv )
{
   CK_C_INITIALIZE_ARGS  initArgs;
   CK_RV                   rc;
   CK_FLAGS                flags = 0;
   CK_SESSION_HANDLE       session;
   static CK_BBOOL         isTrue = TRUE;

   CK_RV                   (*pFunc)();
   void                    *pkcs11Lib;
 
   getArgs(argc, argv);

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

   /* C_InitToken cleans up private and public keystores. This only needs to be done once.
    * Subsequent C_InitToken calls will delete any existing keys within the keystores
    */
   if (opMode == 1) {
       // Only init token when generating new keys. Do not do that when finding a key
       rc = funcs->C_InitToken(0, soPin, strlen((const char *) soPin), tokenNameBuf);
       if (rc != CKR_OK) {
          printf("error C_InitToken: rc=0x%04lx\n", rc );
          funcs->C_Finalize( NULL );
          return !CKR_OK;
       }
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

   if (opMode == 1) {
       if (generateKeyChecksum(session, CKK_AES) != 1) {
           printf("Failed to generate AES key\n");
           funcs->C_Finalize( NULL );
           return !CKR_OK;
       }
       if (generateKeyChecksum(session, CKK_DES3) != 1) {
           printf("Failed to generate DES3 key\n");
           funcs->C_Finalize( NULL );
           return !CKR_OK;
       }
       if (generateKeyChecksum(session, CKK_DES2) != 1) {
           printf("Failed to generate DES2 key\n");
           funcs->C_Finalize( NULL );
           return !CKR_OK;
       }
   } else {
       if (verifyChecksumFromFile(session, CKK_AES) != 1) {
           printf("Failed to verify AES key\n");
           funcs->C_Finalize( NULL );
           return !CKR_OK;
       }
       if (verifyChecksumFromFile(session, CKK_DES3) != 1) {
           printf("Failed to verify DES3 key\n");
           funcs->C_Finalize( NULL );
           return !CKR_OK;
       }
       if (verifyChecksumFromFile(session, CKK_DES2) != 1) {
           printf("Failed to verify DES2 key\n");
           funcs->C_Finalize( NULL );
           return !CKR_OK;
       }
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

