 /****************************************************************
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * pkcs11-attrs.c
 *
 * A sample application demonstrating how to extract and display key attributes using the PKCS11 library
 * 
 * Compile using:
 * gcc -o pkcs11-attrs pkcs11-attrs.c -ldl
 * 
 * Usage:
 * ./pkcs11-attrs -p <path to pkcs11 library> -s <SO user API key> -u <normal user API key> -l <label> -m [generate|load]
 * Ensure that the grep11client.yaml PKCS11 configuration file is in the /etc/ep11client directory. You may
 * need to create the /etc/ep11client directory, if it does not exist.
 *
 * Please refer to https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api
 * for more information about the setup of the PKCS11 library and its configuration file.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <memory.h>
#include <dlfcn.h>
#include <sys/timeb.h>
#include "sample.h"

typedef enum {
    ATTR_INVALID = 0,
    ATTR_BYTEARRAY = 1,
    ATTR_INTEGER = 2,
    ATTR_BOOL = 3,
}AttrGRPCType;

typedef struct {
    CK_ATTRIBUTE_TYPE typeId;
    AttrGRPCType grpcType;
}AttrIDType;

AttrIDType attrToType[] = {
        {CKA_CLASS,                      ATTR_INTEGER},   // CK_OBJECT_CLASS,
        {CKA_TOKEN,                      ATTR_BOOL},      // CK_BBOOL,
        {CKA_PRIVATE,                    ATTR_BOOL},      // CK_BBOOL,
        {CKA_LABEL,                      ATTR_BYTEARRAY}, // CK_BYTEARRAY,

        // future
        // {CKA_VALUE,                      ATTR_BYTEARRAY}, // CK_BYTEARRAY,

        {CKA_TRUSTED,                    ATTR_BOOL},      // CK_BBOOL,
        {CKA_CHECK_VALUE,                ATTR_BYTEARRAY}, // CK_BYTEARRAY,
        {CKA_KEY_TYPE,                   ATTR_INTEGER},   // CK_KEY_TYPE,
        {CKA_SUBJECT,                    ATTR_BYTEARRAY}, // CK_BYTEARRAY,
        {CKA_ID,                         ATTR_BYTEARRAY}, // CK_BYTEARRAY,

        {CKA_ENCRYPT,                    ATTR_BOOL},      // CK_BBOOL,
        {CKA_DECRYPT,                    ATTR_BOOL},      // CK_BBOOL,
        {CKA_WRAP,                       ATTR_BOOL},      // CK_BBOOL,
        {CKA_UNWRAP,                     ATTR_BOOL},      // CK_BBOOL,
        {CKA_SIGN,                       ATTR_BOOL},      // CK_BBOOL,
        {CKA_VERIFY,                     ATTR_BOOL},      // CK_BBOOL,
        {CKA_DERIVE,                     ATTR_BOOL},      // CK_BBOOL,
        {CKA_MODULUS,                    ATTR_BYTEARRAY}, // CK_BIGINTEGER,
        {CKA_MODULUS_BITS,               ATTR_INTEGER},   // CK_ULONG,
        {CKA_PUBLIC_EXPONENT,            ATTR_BYTEARRAY}, // CK_BIGINTEGER,

        // future
        // {CKA_PRIME,                      ATTR_BYTEARRAY}, // CK_BIGINTEGER,
        // {CKA_SUBPRIME,                   ATTR_BYTEARRAY}, // CK_BIGINTEGER,
        // {CKA_BASE,                       ATTR_BYTEARRAY}, // CK_BIGINTEGER,
        // {CKA_PRIME_BITS,                 ATTR_INTEGER},   // CK_ULONG,

        {CKA_VALUE_LEN,                  ATTR_INTEGER},   // CK_ULONG,
        {CKA_EXTRACTABLE,                ATTR_BOOL},      // CK_BBOOL,
        {CKA_LOCAL,                      ATTR_BOOL},      // CK_BBOOL,
        {CKA_NEVER_EXTRACTABLE,          ATTR_BOOL},      // CK_BBOOL,
        {CKA_MODIFIABLE,                 ATTR_BOOL},      // CK_BBOOL,
        {CKA_EC_PARAMS,                  ATTR_BYTEARRAY}, // CK_BYTEARRAY,
        {CKA_EC_POINT,                   ATTR_BYTEARRAY}, // CK_BYTEARRAY,
        {CKA_WRAP_WITH_TRUSTED,          ATTR_BOOL},      // CK_BBOOL,

        // Vendor extension
        {CKA_GREP11_WKID,                ATTR_BYTEARRAY},
};

typedef struct {
    CK_ATTRIBUTE_TYPE typeId;
    char* str;
}AttrIDString;

AttrIDString attrToString[] = {
        {CKA_CLASS,                          "CKA_CLASS"},
        {CKA_TOKEN,                          "CKA_TOKEN"},
        {CKA_PRIVATE,                        "CKA_PRIVATE"},
        {CKA_LABEL,                          "CKA_LABEL"},
        // {CKA_VALUE,                          "CKA_VALUE"},
        {CKA_TRUSTED,                        "CKA_TRUSTED"},
        {CKA_CHECK_VALUE,                    "CKA_CHECK_VALUE"},
        {CKA_KEY_TYPE,                       "CKA_KEY_TYPE"},
        {CKA_SUBJECT,                        "CKA_SUBJECT"},
        {CKA_ID,                             "CKA_ID"},
        {CKA_ENCRYPT,                        "CKA_ENCRYPT"},
        {CKA_DECRYPT,                        "CKA_DECRYPT"},
        {CKA_WRAP,                           "CKA_WRAP"},
        {CKA_UNWRAP,                         "CKA_UNWRAP"},
        {CKA_SIGN,                           "CKA_SIGN"},
        {CKA_VERIFY,                         "CKA_VERIFY"},
        {CKA_DERIVE,                         "CKA_DERIVE"},
        {CKA_MODULUS,                        "CKA_MODULUS"},
        {CKA_MODULUS_BITS,                   "CKA_MODULUS_BITS"},
        {CKA_PUBLIC_EXPONENT,                "CKA_PUBLIC_EXPONENT"},
        // {CKA_PRIME,                          "CKA_PRIME"},
        // {CKA_SUBPRIME,                       "CKA_SUBPRIME"},
        // {CKA_BASE,                           "CKA_BASE"},
        // {CKA_PRIME_BITS,                     "CKA_PRIME_BITS"},
        {CKA_VALUE_LEN,                      "CKA_VALUE_LEN"},
        {CKA_EXTRACTABLE,                    "CKA_EXTRACTABLE"},
        {CKA_LOCAL,                          "CKA_LOCAL"},
        {CKA_NEVER_EXTRACTABLE,              "CKA_NEVER_EXTRACTABLE"},
        {CKA_MODIFIABLE,                     "CKA_MODIFIABLE"},
        {CKA_EC_PARAMS,                      "CKA_EC_PARAMS"},
        {CKA_EC_POINT,                       "CKA_EC_POINT"},
        {CKA_WRAP_WITH_TRUSTED,              "CKA_WRAP_WITH_TRUSTED"},
        {CKA_GREP11_WKID,                    "CKA_GREP11_WKID"},
};

CK_ATTRIBUTE_TYPE commonAttrType[] = {
        CKA_CLASS,
        CKA_TOKEN,
        CKA_PRIVATE,
        CKA_MODIFIABLE,
        CKA_LABEL,
        CKA_KEY_TYPE,
        CKA_ID,
        CKA_DERIVE,
};
const int commonAttrAmt = (sizeof(commonAttrType)) / sizeof(CK_ATTRIBUTE_TYPE);

CK_ATTRIBUTE_TYPE secretKeyAttrType[] = {
        CKA_ENCRYPT,
        CKA_DECRYPT,
        CKA_WRAP,
        CKA_UNWRAP,
        CKA_EXTRACTABLE,
        CKA_NEVER_EXTRACTABLE,
        CKA_CHECK_VALUE,
        CKA_WRAP_WITH_TRUSTED,
        CKA_TRUSTED,
        CKA_VALUE_LEN,
        CKA_LOCAL,
        CKA_GREP11_WKID,
};
const int secretKeyAttrAmt = (sizeof(secretKeyAttrType)) / sizeof(CK_ATTRIBUTE_TYPE);

CK_ATTRIBUTE_TYPE publicKeyAttrType[] = {
        CKA_SUBJECT,
        CKA_ENCRYPT,
        CKA_VERIFY,
        CKA_WRAP,
        CKA_TRUSTED,
        CKA_MODULUS_BITS,
        CKA_MODULUS,
        CKA_PUBLIC_EXPONENT,
        CKA_EC_PARAMS,
        CKA_EC_POINT,
};
const int publicKeyAttrAmt = (sizeof(publicKeyAttrType)) / sizeof(CK_ATTRIBUTE_TYPE);

CK_ATTRIBUTE_TYPE privateKeyAttrType[] = {
        CKA_SUBJECT,
        CKA_DECRYPT,
        CKA_SIGN,
        CKA_UNWRAP,
        CKA_EXTRACTABLE,
        CKA_NEVER_EXTRACTABLE,
        CKA_WRAP_WITH_TRUSTED,
        CKA_MODULUS,  // future
        CKA_PUBLIC_EXPONENT, // future
        CKA_EC_PARAMS, // future
        CKA_LOCAL,
        CKA_GREP11_WKID,
};
const int privateKeyAttrAmt = (sizeof(privateKeyAttrType)) / sizeof(CK_ATTRIBUTE_TYPE);

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

const char * getObjectClassStr(CK_OBJECT_CLASS objClass) {
    switch (objClass) {
    case CKO_PUBLIC_KEY:
        return "Public key";
    case CKO_PRIVATE_KEY:
        return "Private key";
    case CKO_SECRET_KEY:
        return "Secret key (Symmetric key)";
    default:
        return "Unknow object type";
    }
}

AttrGRPCType getAttrType(CK_ATTRIBUTE_TYPE typeId) {
    for (int i = 0; i < sizeof(attrToType)/sizeof(AttrIDType); i++) {
        if (typeId == attrToType[i].typeId) {
            return attrToType[i].grpcType;
        }
    }
    return ATTR_INVALID;
}

const char * getAttrString(CK_ATTRIBUTE_TYPE typeId) {
    for (int i = 0; i < sizeof(attrToString)/sizeof(AttrIDString); i++) {
        if (typeId == attrToString[i].typeId) {
            return attrToString[i].str;
        }
    }
    return NULL;
}

// getDecimalFromBytes returns long number for hex. Returning value is undefined if it exceeds 64 bits.
unsigned long getDecimalFromBytes(const unsigned char *src, int len) {
    unsigned long ret = 0;

    for (int i = 0; i < len; i++) {
        ret <<= 8;
        ret += (int)src[i];
    }
    return ret;
}

const static int printWidth = 25;

void PrintByteBuf(CK_ATTRIBUTE_TYPE attrType, const char * header, const unsigned char * data, unsigned long len) {
#define CH_PER_LINE (16)
    char strBuf[128];
    unsigned long i;
    //output format: 4 spaces + CH_PER_LINE * 3 HEX data divided by single colon
    char line[4 + CH_PER_LINE * 3 + 1];
    static char itohex[CH_PER_LINE] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    switch (attrType) {
    case CKA_PUBLIC_EXPONENT:
        fprintf(stdout, "%-*s: %ld\n", printWidth, header, getDecimalFromBytes(data, len));
        return;
    case CKA_EC_PARAMS:
    case CKA_LABEL:
        memcpy(strBuf, data, len);
        strBuf[len] = 0;
        fprintf(stdout, "%-*s: %s\n", printWidth, header, strBuf);
        return;
    default:
        fprintf(stdout, "%-*s[%lu]\n", printWidth, header, len);
    }

    line[sizeof(line) - 1] = 0;
    for (i = 0; i < len; i++) {
        //4 print spaces for address
        if (i % CH_PER_LINE == 0) {
            if (i > 0) {
                //last line is done
                fprintf(stdout, "%s\n", line);
            }
            memset(line, ' ', sizeof(line) - 1);
        }
        //each byte is translated into 'ab ' form, 3 print spaces
        line[4 + (i % CH_PER_LINE) * 3] = itohex[data[i] >> 4];
        line[4 + (i % CH_PER_LINE) * 3 + 1] = itohex[data[i] & 0xf];
        line[4 + (i % CH_PER_LINE) * 3 + 2] = ':';
    }
    if (i % CH_PER_LINE != 15) {
        //shorter line
        fprintf(stdout, "%s\n", line);
    }
    fprintf(stdout, "\n");
}

void freeTemplate(CK_ATTRIBUTE_PTR pAttrs, CK_ULONG amt) {
    for (int i = 0; i < amt; i++) {
        if (pAttrs[i].pValue != NULL) {
            free(pAttrs[i].pValue);
        }
    }
    free((void *)pAttrs);
    return;
}

// The returned memory pointer must be freed by freeTemplate()
CK_ATTRIBUTE_PTR allocTemplate(CK_OBJECT_CLASS objClass, CK_ULONG* amt) {
    CK_ATTRIBUTE_PTR pAttrs;

    int i, extraAttrAmt, totalAttrAmt = commonAttrAmt;

    switch (objClass) {
    case CKO_SECRET_KEY:
        extraAttrAmt = secretKeyAttrAmt;
        break;
    case CKO_PUBLIC_KEY:
        extraAttrAmt = publicKeyAttrAmt;
        break;
    case CKO_PRIVATE_KEY:
        extraAttrAmt = privateKeyAttrAmt;
        break;
    default:
        return NULL;
    }

    totalAttrAmt += extraAttrAmt;
    CK_ATTRIBUTE_TYPE allAttrIdList[totalAttrAmt];

    for (i = 0; i < commonAttrAmt; i++) {
        allAttrIdList[i] = commonAttrType[i];
    }

    switch (objClass) {
    case CKO_SECRET_KEY:
        for (i = commonAttrAmt; i < commonAttrAmt + extraAttrAmt; i++) {
            allAttrIdList[i] = secretKeyAttrType[i - commonAttrAmt];
        }
        break;
    case CKO_PUBLIC_KEY:
        for (i = commonAttrAmt; i < commonAttrAmt + extraAttrAmt; i++) {
            allAttrIdList[i] = publicKeyAttrType[i - commonAttrAmt];
        }
        break;
    case CKO_PRIVATE_KEY:
        for (i = commonAttrAmt; i < commonAttrAmt + extraAttrAmt; i++) {
            allAttrIdList[i] = privateKeyAttrType[i - commonAttrAmt];
        }
        break;
    default:
        return NULL;
    }
    size_t bufferSize = totalAttrAmt * sizeof(CK_ATTRIBUTE);
    pAttrs = (CK_ATTRIBUTE_PTR)malloc(bufferSize);
    if (pAttrs == NULL) {
        return NULL;
    }
    memset((void *)pAttrs, 0, bufferSize);

    for (i = 0; i < totalAttrAmt; i++) {
        AttrGRPCType t = getAttrType(allAttrIdList[i]);
        size_t memSize = 0;
        pAttrs[i].type = allAttrIdList[i];
        switch (t) {
        case ATTR_BOOL:
            memSize = 1;
            break;
        case ATTR_INTEGER:
            memSize = 8;
            break;
        case ATTR_BYTEARRAY:
            memSize = 1024; // enough for any byte attribute
            break;
        default:
            printf("Unexpected GRPC type for %lx\n", allAttrIdList[i]);
            exit(1);
        }
        pAttrs[i].pValue = malloc(memSize);
        if ( pAttrs[i].pValue == NULL) {
            printf("not enough memory!\n");
            exit(1);
        }
        pAttrs[i].ulValueLen = (CK_ULONG)memSize;
    }
    *amt = (CK_ULONG)totalAttrAmt;
    return pAttrs;
}

CK_FUNCTION_LIST  *funcs;
CK_BYTE           tokenNameBuf[32];
const char        tokenName[] = "testToken";

void PrintAttrs(CK_ATTRIBUTE* pAttrs, int amount) {
    CK_ATTRIBUTE* pAttr = pAttrs;
    AttrGRPCType t;
    const char *str;
    unsigned char *pCh;
    unsigned long ulongVale;
    for (int i = 0; i < amount; i++) {
        t = getAttrType(pAttr[i].type);
        if (t == ATTR_INVALID) {
            printf("Unrecognized attribute type %lx\n", pAttr[i].type);
            continue;
        }
        str = getAttrString(pAttr[i].type);
        if (str == NULL) {
            printf("Unrecognized attribute type %lx\n", pAttr[i].type);
            continue;
        }
        if (pAttr[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
            //printf("%-*s: %s\n", printWidth, str, "Unavailable");
            continue;
        }
        if (t == ATTR_BYTEARRAY && pAttr[i].ulValueLen == 0) {
            printf("%-*s: %s\n", printWidth, str, "Empty");
            continue;
        }

        switch (t) {
        case ATTR_BOOL:
            pCh = (unsigned char *)pAttr[i].pValue;
            printf("%-*s: %s\n", printWidth, str, pCh[0] == 0? "FALSE":"TRUE");
            break;
        case ATTR_INTEGER:
            if (pAttr[i].ulValueLen != sizeof(ulongVale)) {
                printf("Integer attribute is not 8 bytes: %ld\n", pAttr[i].ulValueLen);
                continue;
            }
            ulongVale = *((unsigned long *)pAttr[i].pValue);
            switch (pAttr[i].type) {
            case CKA_KEY_TYPE:
                printf("%-*s: %s\n", printWidth, str, getKeyTypeStr(ulongVale));
                break;
            case CKA_CLASS:
                printf("%-*s: %s\n", printWidth, str, getObjectClassStr(ulongVale));
                break;
            default:
                printf("%-*s: %08lx\n", printWidth, str, ulongVale);
            }

            break;
        case ATTR_BYTEARRAY:
            PrintByteBuf(pAttr[i].type, str, (const unsigned char *)pAttr[i].pValue, pAttr[i].ulValueLen);
            break;
        default:
            break;
        }
    }
    printf("\n");
}

void PrintKeyAttrs(CK_SESSION_HANDLE session, CK_OBJECT_CLASS objClass, CK_OBJECT_HANDLE hKey) {
    CK_ULONG amt = 0;
    CK_ATTRIBUTE_PTR pTemplate = NULL;
    CK_RV rc;

    pTemplate = allocTemplate(objClass, &amt);
    if (pTemplate == NULL) {
        printf("error allocTemplate\n");
        funcs->C_Finalize( NULL );
        return;
    }

    funcs->C_GetAttributeValue(session, hKey, pTemplate, amt);

    PrintAttrs(pTemplate, amt);
    freeTemplate(pTemplate, amt);
    return;
}

CK_UTF8CHAR         soPin[256] = {0};
CK_UTF8CHAR         userPin[256] = {0};
char                pkcs11LibName[1024] = {0};
char                inputKeyLabel[1024] = {0}; // There are default labels for 3 different types of keys
int                 mode = 1; // 1: generate keys (default), 2: load keys with the same label
char                strUsage[] = "./pkcs11-attrs -p <path to pkcs11 library> -s <SO user API key> -u <normal user API key> -l <label> -m [generate|load]";

void getArgs(int argc, char **argv) {
    int c, n;

    static struct option long_options[] = {
        {"librarypath",    required_argument, NULL, 'p'},
        {"SOpin",     required_argument, NULL, 's'},
        {"userpin",   required_argument, NULL, 'u'},
        {"label",   optional_argument, NULL, 'l'},
        {"mode",    optional_argument, NULL, 'm'}, // "generate" or "load"
        {0, 0, 0, 0}
    };

    while (1)
    {
      c = getopt_long (argc, argv, "p:s:u:l:m:", long_options, NULL);

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
                printf("SO PIN is too long\n");
                exit(1);
            }
          break;

        case 'u':
            n = snprintf((char *)userPin, sizeof(userPin), "%s", optarg);
            if (n < strlen(optarg)) {
                printf("Normal user PIN is too long\n");
                exit(1);
            }
          break;

        case 'l':
            n = snprintf((char *)inputKeyLabel, sizeof(inputKeyLabel), "%s", optarg);
            if (n < strlen(optarg)) {
                printf("Key label is too long\n");
                exit(1);
            }
            break;

        case 'm':
            if (strncmp(optarg, "generate", strlen("generate")) == 0) {
                mode = 1;
            } else if (strncmp(optarg, "load", strlen("load")) == 0) {
                mode = 2;
            } else {
                printf("Invalid mode %s\n", optarg);
                exit(1);
            }
            break;
        default:
          printf("%s\n", strUsage);
          exit(1);
        }
    }

    if (strlen((char *)soPin) == 0 && mode == 1) {
        printf("PIN for the SO user must be provided when generating keys\n");
        exit(1);
    }
    if (strlen((char *)userPin) == 0 || strlen(pkcs11LibName) == 0) {
        printf("%s\n", strUsage);
        exit(1);
    }
}

// find_key returns 0 if no key is found or more than one object is found
CK_OBJECT_HANDLE find_key(CK_SESSION_HANDLE session, CK_ATTRIBUTE *pTmpl, CK_ULONG tmplAmt) {
    CK_RV                   rc;
    CK_OBJECT_HANDLE        handles[64];
    CK_ULONG                amtHandle = 0;

    rc = funcs->C_FindObjectsInit(session, pTmpl, tmplAmt);
    if (rc != CKR_OK) {
       printf("error C_FindObjectsInit: rc=0x%04lx\n", rc );
       return !CKR_OK;
    }

    rc = funcs->C_FindObjects( session, handles, sizeof(handles)/ sizeof(CK_OBJECT_HANDLE), &amtHandle);
    if (rc != CKR_OK) {
       printf("error C_FindObjects: rc=0x%04lx\n", rc );
       return !CKR_OK;
    }
    funcs->C_FindObjectsFinal(session);

    if (amtHandle != 1) {
        printf("Zero or more than 1 object found: %ld\n", amtHandle);
        return 0;
    }
    return handles[0];
}

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

   if (mode == 1) {
       printf("Initializing the token... \n");
       memset(tokenNameBuf, ' ', sizeof(tokenNameBuf)); /* Token name is left justified, padded with blanks */
       memcpy(tokenNameBuf, tokenName, strlen(tokenName));

       /* C_InitToken cleans up private and public keystores. This only needs to be done once.
        * Subsequent C_InitToken calls will delete any existing keys within the keystores
        */
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

   char aesLabel[1024] = "AES key label";
   char rsaPubLabel[1024] = "RSA public key label";
   char rsaPrivLabel[1024] = "RSA private key label";
   char ecPubLabel[1024] = "ECDSA public key label";
   char ecPrivLabel[1024] = "ECDSA private key label";

   if (strlen(inputKeyLabel) > 0) {
       strcpy(aesLabel, inputKeyLabel);
       strcpy(rsaPubLabel, inputKeyLabel);
       strcpy(rsaPrivLabel, inputKeyLabel);
       strcpy(ecPubLabel, inputKeyLabel);
       strcpy(ecPrivLabel, inputKeyLabel);
   }

   // Load AES and RSA/EC public and private keys from PKCS#11 the key store
   if (mode == 2) {
        CK_OBJECT_HANDLE hKey;
        CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
        CK_KEY_TYPE keyType = CKK_AES;
        char *pLabel = aesLabel;

       CK_ATTRIBUTE find_tmpl[] = {
        {CKA_LABEL,        pLabel,    strlen(pLabel) },
        {CKA_CLASS,        &objClass,    sizeof(objClass) },
        {CKA_KEY_TYPE,     &keyType,    sizeof(keyType) },
       };

       printf("Loading AES key... \n");
       hKey = find_key(session, find_tmpl, 3);
       if (hKey != 0) {
           printf("AES key attributes\n");
           PrintKeyAttrs(session, CKO_SECRET_KEY, hKey);
       } else {
           printf("Unexpected number of AES keys found\n");
       }

       // RSA public key
       pLabel = rsaPubLabel;
       objClass = CKO_PUBLIC_KEY;
       keyType = CKK_RSA;
       printf("Loading RSA key pair... \n");
       hKey = find_key(session, find_tmpl, 3);
       if (hKey != 0) {
           printf("RSA public key attributes\n");
           PrintKeyAttrs(session, CKO_PUBLIC_KEY, hKey);
       } else {
           printf("Unexpected number of RSA public keys found\n");
       }
       // RSA private key
       pLabel = rsaPrivLabel;
       objClass = CKO_PRIVATE_KEY;
       hKey = find_key(session, find_tmpl, 3);
       if (hKey != 0) {
           printf("RSA private key attributes\n");
           PrintKeyAttrs(session, CKO_PRIVATE_KEY, hKey);
       } else {
           printf("Unexpected number of RSA private keys found\n");
       }

       // EC public key
       pLabel = ecPubLabel;
       objClass = CKO_PUBLIC_KEY;
       keyType = CKK_EC;
       printf("Loading EC key pair... \n");
       hKey = find_key(session, find_tmpl, 3);
       if (hKey != 0) {
           printf("EC public key attributes\n");
           PrintKeyAttrs(session, CKO_PUBLIC_KEY, hKey);
       } else {
           printf("Unexpected number of EC public keys found\n");
       }
       // EC private key
       pLabel = ecPrivLabel;
       objClass = CKO_PRIVATE_KEY;
       hKey = find_key(session, find_tmpl, 3);
       if (hKey != 0) {
           printf("EC private key attributes\n");
           PrintKeyAttrs(session, CKO_PRIVATE_KEY, hKey);
       } else {
           printf("Unexpected number of EC private keys found\n");
       }

       goto finished;
   }

   printf("Generating AES key... \n");
   CK_ULONG aesKeyLen = 32;

   CK_ATTRIBUTE aes_tmpl[] = {
    {CKA_LABEL,        aesLabel,    strlen(aesLabel) },
    {CKA_TOKEN,        &isTrue,     sizeof(isTrue) },
    {CKA_VALUE_LEN,    &aesKeyLen,  sizeof(aesKeyLen) },
    {CKA_ENCRYPT,      &isTrue,     sizeof(isTrue) },
    {CKA_DECRYPT,      &isTrue,     sizeof(isTrue) },
    {CKA_EXTRACTABLE,  &isFalse,    sizeof(isFalse)},
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

   printf("AES key attributes\n");
   PrintKeyAttrs(session, CKO_SECRET_KEY, aesKey);

   // Print ECDSA key attributes
   printf("Generating ECDSA key pair... \n");
   /* Attributes for the public key to be generated */
   CK_BYTE curve_name[] = "P-256";

   CK_ATTRIBUTE pub_tmpl[] = {
      {CKA_LABEL,        ecPubLabel,    strlen(ecPubLabel) },
      {CKA_TOKEN,        &isTrue, sizeof(isTrue) },
      {CKA_EC_PARAMS,    &curve_name,   strlen( (const char *) curve_name) },
      {CKA_VERIFY,       &isTrue,  sizeof(isTrue) },
   };

   /* Attributes for the private key to be generated */
   CK_ATTRIBUTE priv_tmpl[] =
   {
      {CKA_LABEL,    ecPrivLabel,    strlen(ecPrivLabel) },
      {CKA_TOKEN,    &isTrue, sizeof(isTrue) },
      {CKA_SIGN,     &isTrue, sizeof(isTrue) },
      {CKA_EXTRACTABLE,  &isFalse,    sizeof(isFalse)},
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

   printf("ECDSA public key attributes\n");
   PrintKeyAttrs(session, CKO_PUBLIC_KEY, publicKey);

   printf("ECDSA private key attributes\n");
   PrintKeyAttrs(session, CKO_PRIVATE_KEY, privateKey);

   // Print RSA key attributes
   unsigned long rsaBits = 2048;
   unsigned char pubExponent[] = {0x2, 0x0, 0x1};
   CK_ATTRIBUTE rsa_pub_tmpl[] = {
      {CKA_LABEL,           rsaPubLabel,    strlen(rsaPubLabel) },
      {CKA_MODULUS_BITS,    &rsaBits, sizeof(rsaBits)},
      {CKA_PUBLIC_EXPONENT, pubExponent, sizeof(pubExponent)},
      {CKA_TOKEN,           &isTrue, sizeof(isTrue) },
      {CKA_VERIFY,          &isTrue,  sizeof(isTrue) },
   };

   /* Attributes for the private key to be generated */
   CK_ATTRIBUTE rsa_priv_tmpl[] =
   {
      {CKA_LABEL,    rsaPrivLabel,    strlen(rsaPrivLabel) },
      {CKA_TOKEN,    &isTrue, sizeof(isTrue) },
      {CKA_SIGN,     &isTrue, sizeof(isTrue) },
      {CKA_EXTRACTABLE,  &isFalse,    sizeof(isFalse)},
   };
   mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
   mech.ulParameterLen = 0;
   mech.pParameter     = NULL;

   rc = funcs->C_GenerateKeyPair( session,   &mech,
                                  rsa_pub_tmpl,   sizeof(rsa_pub_tmpl)/sizeof(CK_ATTRIBUTE),
                                  rsa_priv_tmpl,  sizeof(rsa_priv_tmpl)/sizeof(CK_ATTRIBUTE),
                                  &publicKey, &privateKey );
   if (rc != CKR_OK) {
      printf("error C_GenerateKeyPair: rc=0x%04lx\n", rc );
      funcs->C_Finalize( NULL );
      return !CKR_OK;
   }

   printf("RSA public key attributes\n");
   PrintKeyAttrs(session, CKO_PUBLIC_KEY, publicKey);

   printf("RSA private key attributes\n");
   PrintKeyAttrs(session, CKO_PRIVATE_KEY, privateKey);

finished:

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
