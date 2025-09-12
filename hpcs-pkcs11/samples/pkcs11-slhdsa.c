/*
 * gcc -o pkcs11-eddsa pkcs11-eddsa.c -ldl
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
 * Feel free to change the name to match your pkcs11 library name.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include <sys/timeb.h>
#include "sample.h"

#define CKK_EC_EDWARDS		(0x40UL)
#define CKM_EC_EDWARDS_KEY_PAIR_GEN	(0x1055UL)
#define CKM_EDDSA			(0x1057UL)

CK_FUNCTION_LIST  *funcs;
CK_BYTE           tokenNameBuf[32];
const char        tokenName[] = "meulabel";

#define DUMP_HEXA(A, B)   \
          do {  \
            printf("%s[%d]: \n", (char *) #A, (int) B); \
            dump_hexa((const void*) A, (size_t) B);  \
          } while(0) 

void dump_hexa(const void* data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

long get_file_size(char *fname) {
    FILE *f = fopen(fname, "r");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    return size;
}

int main( int argc, char **argv )
{
  CK_C_INITIALIZE_ARGS   initArgs;
  CK_RV                  rc;
  CK_FLAGS               flags = 0;
  CK_SESSION_HANDLE      session;
  CK_MECHANISM           mech;
  CK_OBJECT_HANDLE       publicKey, privateKey;
  static CK_BBOOL        isTrue = TRUE;
  static CK_BBOOL        isFalse = FALSE;
  CK_BYTE id[] = {123};
  CK_UTF8CHAR_PTR keyLabel = (unsigned char *) "pqlabel";

  CK_RV                  (*pFunc)();
  void                   *pkcs11Lib;
  CK_UTF8CHAR_PTR        soPin = (unsigned char *) "0000";
  CK_UTF8CHAR_PTR        userPin = (unsigned char *) "0000";
  char                   pkcs11LibName[] = "libsofthsm2.so";
  
  if (argc != 2) {
      printf("Usage: %s <file_to_sign>\n", argv[0]);
      return -1;
  }
  
  char* file_to_sign = argv[1];

  printf("Opening the PKCS11 library...\n");
  pkcs11Lib = dlopen(pkcs11LibName, RTLD_LAZY);
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
  
  CK_SLOT_ID available_slots[10];
  CK_ULONG num_slots = 10;

  rc = funcs->C_GetSlotList(1, available_slots, &num_slots);
  if (rc != CKR_OK) {
    printf("Failed to get the available slots: rc=0x%04lx\n", rc);
    return 0;
  }
  
  printf("Available slots: 0x%04lx %ld\n", available_slots[0], num_slots);
  
  /* printf("Initializing the token... \n"); */
  /* memset(tokenNameBuf, ' ', sizeof(tokenNameBuf));  */
  /* memcpy(tokenNameBuf, tokenName, strlen(tokenName)); */
  /**/
  /* rc= funcs->C_InitToken(available_slots[0], soPin, strlen((const char *) soPin), tokenNameBuf); */
  /* if (rc != CKR_OK) { */
  /*   printf("error C_InitToken: rc=0x%04lx\n", rc ); */
  /*   funcs->C_Finalize( NULL ); */
  /*   return !CKR_OK; */
  /* } */

  flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  printf("Opening a session... \n");
  rc = funcs->C_OpenSession( available_slots[0], flags, (CK_VOID_PTR) NULL, NULL, &session );
  if (rc != CKR_OK) {
    printf("error C_OpenSession: rc=0x%04lx\n", rc );
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }
  
  printf("Logging in as SO... \n");
  rc = funcs->C_Login( session, CKU_SO, soPin, strlen((const char *) soPin));
  if (rc != CKR_OK) {
    printf("error C_Login: rc=0x%04lx\n", rc );
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }
  
  printf("Initing normal user pin... \n");
  rc = funcs->C_InitPIN( session, userPin, strlen((const char *) userPin));
  if (rc != CKR_OK) {
    printf("error C_InitPin: rc=0x%04lx\n", rc );
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }
  
  rc = funcs->C_Logout(session);
  if (rc != CKR_OK) {
    printf("error C_Logout: rc=0x%04lx\n", rc );
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

  // Use Ed25519 key to sign & verify
  printf("Generating Ed25519 key pair... \n");
  
  CK_KEY_TYPE keyType = CKK_EC_EDWARDS;
  CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
  /* DER OID for id-Ed25519 (1.3.101.112) */
  CK_BYTE ED25519_EC_PARAMS[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
  
/* Public key template */
CK_ATTRIBUTE pub_tmpl[] = {
    { CKA_TOKEN,     &isTrue,  sizeof(isTrue) },
    { CKA_VERIFY,    &isTrue,  sizeof(isTrue) },
    { CKA_LABEL,     keyLabel, (CK_ULONG)strlen((char*)keyLabel) },
    { CKA_ID,        id,       (CK_ULONG)sizeof(id) },
    { CKA_EC_PARAMS, (CK_VOID_PTR)ED25519_EC_PARAMS,
                     (CK_ULONG)sizeof(ED25519_EC_PARAMS) }
};

/* Private key template */
CK_ATTRIBUTE priv_tmpl[] = {
    { CKA_TOKEN,   &isTrue,  sizeof(isTrue) },
    { CKA_SIGN,    &isTrue,  sizeof(isTrue) },
    { CKA_LABEL,   keyLabel, (CK_ULONG)strlen((char*)keyLabel) },
    { CKA_ID,      id,       (CK_ULONG)sizeof(id) }
};
  
  mech.mechanism      = CKM_EC_EDWARDS_KEY_PAIR_GEN;
  mech.ulParameterLen = 0;
  mech.pParameter     = NULL;

  rc = funcs->C_GenerateKeyPair( session,    &mech,
                 pub_tmpl,   sizeof(pub_tmpl)/sizeof(CK_ATTRIBUTE),
                 priv_tmpl,  sizeof(priv_tmpl)/sizeof(CK_ATTRIBUTE),
                 &publicKey, &privateKey );
  if (rc != CKR_OK) {
    printf("error C_GenerateKeyPair: rc=0x%04lx\n", rc );
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }
  
  long file_size = get_file_size(file_to_sign);
  if (file_size == -1) {
      printf("Error: Could not open or read file %s\n", file_to_sign);
      funcs->C_Finalize( NULL );
      return !CKR_OK;
  }
  
  CK_BYTE* dataToBeSigned = (CK_BYTE*) malloc(file_size);
  if (!dataToBeSigned) {
      printf("Error: Memory allocation failed.\n");
      funcs->C_Finalize( NULL );
      return !CKR_OK;
  }
  
  FILE* fp = fopen(file_to_sign, "rb");
  if (!fp) {
      printf("Error: Could not open file %s for reading.\n", file_to_sign);
      free(dataToBeSigned);
      funcs->C_Finalize( NULL );
      return !CKR_OK;
  }
  fread(dataToBeSigned, 1, file_size, fp);
  fclose(fp);
  
  CK_ULONG dataToBeSignedLen = file_size;
  CK_BYTE signature[1024];
  CK_ULONG signatureLen = sizeof(signature);

  printf("Signing the data from %s with Ed25519 private key... \n", file_to_sign);
  mech.mechanism      = CKM_EDDSA;
  mech.ulParameterLen = 0;
  mech.pParameter     = NULL;

  rc = funcs->C_SignInit(session, &mech, privateKey);
  if (rc != CKR_OK) {
    printf("error C_SignInit: rc=0x%04lx\n", rc );
    free(dataToBeSigned);
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }

  rc = funcs->C_Sign(session, dataToBeSigned, dataToBeSignedLen, signature, &signatureLen);
  if (rc != CKR_OK) {
    printf("error C_Sign: rc=0x%04lx\n", rc );
    free(dataToBeSigned);
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }
  
  DUMP_HEXA(signature, signatureLen);

  printf("Verifying the data with Ed25519 public key... \n");
  rc = funcs->C_VerifyInit(session, &mech, publicKey);
  if (rc != CKR_OK) {
    printf("error C_VerifyInit: rc=0x%04lx\n", rc );
    free(dataToBeSigned);
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }
  
  rc = funcs->C_Verify(session, dataToBeSigned, dataToBeSignedLen, signature, signatureLen);
  if (rc != CKR_OK) {
    printf("error C_Verify: rc=0x%04lx\n", rc );
    free(dataToBeSigned);
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }
  
  printf("Signature is valid!\n");

  printf("Logging out... \n");
  rc = funcs->C_Logout(session);
  if (rc != CKR_OK) {
    printf("error C_Logout: rc=0x%04lx\n", rc );
    free(dataToBeSigned);
    funcs->C_Finalize( NULL );
    return !CKR_OK;
  }

  printf("Closing the session... \n");
  rc = funcs->C_CloseSession( session );
  if (rc != CKR_OK) {
    printf("error C_CloseSession: rc=0x%04lx\n", rc );
    free(dataToBeSigned);
    return !CKR_OK;
  }

  printf("Finalizing... \n");
  rc = funcs->C_Finalize( NULL );
  if (rc != CKR_OK) {
    printf("error C_Finalize: rc=0x%04lx\n", rc );
    free(dataToBeSigned);
    return !CKR_OK;
  }
  
  free(dataToBeSigned);
  printf("Sample completed successfully!\n");
  return 0;
}
