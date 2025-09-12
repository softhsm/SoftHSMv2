# Overview

IBM Cloud® Hyper Protect Crypto Services is a dedicated key management service and hardware security module (HSM). This service allows you to take ownership of a cloud HSM to fully manage your encryption keys and to perform cryptographic operations. Hyper Protect Crypto Services is also the only service in the cloud industry that is built on FIPS 140-2 Level 4-certified hardware.

# Installing the PKCS #11 files

The files contained in this repository allow clients to access a cloud HSM via the HPCS service using a PKCS #11 library and its associated configuration file. The files are categorized by *releases*, which can be accessed from the hpcs-pkcs11 repository's [releases URL](https://github.com/IBM-Cloud/hpcs-pkcs11/releases).

**NOTE:** The PKCS #11 library, for both the amd64 and s390x platforms, is currently supported only on Linux (GLIBC distros only, so not compatible with Alpine for now).

There are two files used along with your PKCS #11 application:
1. The PKCS #11 library:  pkcs11-grep11-**platform**.so.**major.minor.build**

   - **platform** is amd64 or s390x
  
   - **major.minor.build** refers to the version of the library

   - **NOTE:** Refer to step 1 of the IBM Cloud HPCS documentation topic, [Set up the PKCS #11 library](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api), for instructions on where to place the PKCS #11 library file.

2. The PKCS #11 client configuration file: *grep11client.yaml*
   - Before you update the configuration file, PKCS #11 users must first be set up. Follow the steps outlined in the IBM Cloud Hyper Protect Crypto Services documentation topic, [Best practices for setting up PKCS #11 user types](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-best-practice-pkcs11-access#step2-create-service-id-api-key), to complete the PKCS #11 user setup tasks.

   - Changes to the configuration file are needed after you download it. Update the *grep11client.yaml* configuration file by following step 3 of the IBM Cloud Hyper Protect Crypto Services documentation topic: [Set up the PKCS #11 configuration file](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api)

   - **NOTE:** The *grep11client.yaml* configuration file must be moved into the same directory as the application (e.g., pkcs11-tool) using the PKCS #11 library or in the directory `/etc/ep11client`.

## Verify the integrity and authenticity of the PKCS #11 library

For maximum security, you can optionally verify the integrity and authenticity of the PKCS #11 library. Hyper Protect Crypto Services enable [signed code verification](https://en.wikipedia.org/wiki/Code_signing) to ensure that the signature matches the original code. If the downloaded PKCS #11 library file is altered or corrupted, a different signature is produced and the verification fails. To make sure the files are not tampered with or corrupted during the download process, complete the following steps by using the [OpenSSL command-line tool](https://wiki.openssl.org/index.php/Binaries).

1. Download the latest version of the following files from the hpcs-pkcs11 repository's [releases URL](https://github.com/IBM-Cloud/hpcs-pkcs11/releases) to the same directory where you store the PKCS #11 library:

    - `pkcs11-grep11-<platform>.so.<version>.sig`: The signed cryptographic hash of the PKCS #11 library, where **platform** is either *amd64* or *s390x*  and **version** is the major.minor.build (e.g., 2.3.4) of the signature file. Both **platform** and **version** must match the respective **platform** and **version** of the PKCS #11 library that is used.

    - `signing_cert.pem`: The signing certificate for the HPCS PKCS #11 files.
    
    - `digicert_cert.pem`: An intermediate code signing certificate to prove the Hyper Protect Crypto Services PKCS #11 files signing certificate.

2. Extract the public key from the signing certificate `signing_cert.pem` to the `sigkey.pub` file with the following command by using the OpenSSL command-line tool:

   `openssl x509 -pubkey -noout -in signing_cert.pem -out sigkey.pub`

3. Verify the integrity of the PKCS #11 library file with the following command:

   `openssl dgst -sha256 -verify sigkey.pub -signature pkcs11-grep11-<platform>.so.<version>.sig pkcs11-grep11-<platform>.so.<version>`

   **NOTE:** Replace **platform** with either *amd64* or *s390x* and replace **version** with the major.minor.build (e.g., 2.3.4) of the library.

   When the verification is successful, `Verified OK` is displayed.

4. Verify the authenticity and validity of the signing certificate with the following command:

   `openssl ocsp -no_nonce -issuer digicert_cert.pem -cert signing_cert.pem -VAfile digicert_cert.pem -text -url http://ocsp.digicert.com -respout ocsptest`

   When the verification is successful, `Response verify OK` and `signing_cert.pem: good` are displayed in the output.

5. If the verification fails, cancel the installation and contact [IBM for support](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-getting-help).

## Initializing the Keystores

Prior to using the PKCS #11 library, the keystores must be initialized. To initialize the keystores, the security officer (SO) user needs to perform a `C_InitToken` operation. Once the keystores have been initialized, normal and anonymous users can proceed with key operations such as `C_GenerateKey` or `C_GenerateKeyPair`.

A keystore becomes an **authenticated keystore** if it is configured with a password. For more details please check [Performing cryptographic operations with the PKCS #11 API](https://cloud.ibm.com/docs/hs-crypto?topic=hs-crypto-set-up-pkcs-api#step3-setup-configuration-file).

## Getting started

The `samples` directory in this repository contains source code that could be used to test your HPCS instance, the PKCS11 library, and the PKCS11 library's configuration file.  Follow the instructions inside pkcs11-crypto.c to get started.

The sample code performs the following operations:

* Intialize a token
* Open a session
* Login as a normal user
* Create an AES key
* Create an EC key pair
* Encrypt data and decrypt data using the AES key
* Sign and verify data using the EC key pair
* Logout, close session and finalize

pkcs11-dilithium.c demonstrates how to generate a Dilithium key pair, followed by signing and verifying data using the Dilithium key pair.

# Attributes 
We support a subset of attributes of the PKCS#11 specification. The following table shows:
1. Which attributes are allowed to be used for PKCS11 requests (key generation, unwrapping, and key derivation).
2. Data type of each attribute and the key types that are applicable.
3. What attributes are generated after key or key pairs are generated.

| Attribute                                                                            | Category | Applies to key types              | Allowed in template | Value type  | Library default | Filled by HPCS | Read only<br>After generation |
| ------------------------------------------------------------------------------------ | -------- | --------------------------------- | ------------------- | ----------- | --------------- | -------------- | ----------------------------- |
| ﻿CKA\_CLASS                                                                          | 1        | All                               | y                   | Integer     | Depends <sup>[1](#cka-class)</sup>        |                | y                             |
| ﻿CKA\_TOKEN                                                                          | 3        | All                               | y                   | Bool        | FALSE           |                | y                             |
| ﻿CKA\_PRIVATE                                                                        | 3        | All                               | y                   | Bool        | Depends <sup>[2](#cka-private)</sup>        |                | y                             |
| ﻿CKA\_MODIFIABLE                                                                     | 3        | All                               | y                   | Bool        | TRUE            | y              | Read only if FALSE            |
| ﻿CKA\_LABEL                                                                          | 4        | All                               | y                   | Bytes       | empty           |                |                               |
| CKA\_KEY\_TYPE                                                                       | 1        | All                               | y                   | Integer     |                 |                | y                             |
| CKA\_ID                                                                              | 4        | All                               | y                   | Bytes       | empty           |                |                               |
| CKA\_DERIVE                                                                          | 1        | All                               | y                   | Bool        | FALSE           |                |                               |
| CKA\_LOCAL                                                                           | 1        | All but public key                |                     | Bool        |                 | y              | y                             |
| CKA\_KEY\_GEN\_MECHANISM                                                             | 2        | All                               |                     | Integer     |                 | y              | y                             |
| CKA\_GREP11\_WKID                                                                    | 2        | private key<br>secret key         |                     | Big integer |                 | y              | y                             |
| CKA\_SUBJECT                                                                         | 4        | public key<br>private key         | y                   | Bytes       | empty           |                |                               |
| CKA\_ENCRYPT<br>CKA\_DECRYPT<br>CKA\_SIGN<br>CKA\_VERIFY<br>CKA\_WRAP<br>CKA\_UNWRAP | 1        | All when allowed <br>by algorithm | y                   | Bool        |                 | y              |                               |
| ﻿CKA\_SENSITIVE                                                                      | 2        | private key<br>secret key         | y                   | Bool        |                 |                | y                             |
| CKA\_ALWAYS\_SENSITIVE                                                               | 2        | private key<br>secret key         |                     | Bool        |                 | y              | y                             |
| CKA\_WRAP\_WITH\_TRUSTED                                                             | 1        | private key<br>secret key         | y                   | Bool        | FALSE           | y              |                               |
| CKA\_EXTRACTABLE                                                                     | 1        | private key<br>secret key         | y                   | Bool        | FALSE           | y              | Read only if FALSE            |
| ﻿CKA\_NEVER\_EXTRACTABLE                                                             | 1        | private key<br>secret key         |                     | Bool        |                 | y              | y                             |
| CKA\_CHECK\_VALUE                                                                    | 2        | secret key                        |                     | Bytes       |                 | y              | y                             |
| CKA\_TRUSTED                                                                         | 1        | public key<br>secret key          | y                   | Bool        |                 | y              |                               |
| CKA\_PUBLIC\_KEY\_INFO                                                               | 2        | public key                        | y                   | Bool        |                 | y              | y                             |
| ﻿CKA\_MODULUS\_BITS                                                                  | 1        | RSA public key                    | y                   | Integer     |                 |                | y                             |
| ﻿CKA\_MODULUS                                                                        | 2        | RSA public key<br>RSA private key |                     | Big integer |                 | y              | y                             |
| ﻿CKA\_PUBLIC\_EXPONENT                                                               | 1        | RSA public key<br>RSA private key | y                   | Big integer |                 |                | y                             |
| ﻿CKA\_EC\_PARAMS                                                                     | 1        | EC public key<br>EC private key   | y                   | Bytes       |                 |                | y                             |
| ﻿CKA\_EC\_POINT                                                                      | 2        | EC public key                     |                     | Bytes       |                 | y              | y                             |
| CKA\_VALUE\_LEN                                                                      | 1        | Generate secret key<br>AES key    | y                   | integer     |                 |                | y                             |
| ﻿CKA\_IBM\_PQC\_PARAMS                                                               | 1        | Dilithium public key              | y                   | Bytes       |                 |                | y                             |

<a name="cka-class">1</a>. Default value of `CKA_CLASS` is based on mechanisms and key types:

| Function         | Mechanism                                                                                                              | Default value                                                                                  |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| GenerateKey      | CKM\_AES\_KEY\_GEN<br>CKM\_DES2\_KEY\_GEN<br>CKM\_DES3\_KEY\_GEN<br>CKM\_GENERIC\_SECRET\_KEY\_GEN                     | CKO\_SECRET\_KEY                                                                               |
| GenerateKeyPairs | CKM\_EC\_KEY\_PAIR\_GEN<br>CKM\_RSA\_PKCS\_KEY\_PAIR\_GEN<br>CKM\_RSA\_X9\_31\_KEY\_PAIR\_GEN<br>CKM\_IBM\_DILITHIUM                          | CKO\_PUBLIC\_KEY & CKO\_PRIVATE\_KEY                                                           |
| UnwrapKey        | CKM\_AES\_CBC<br>CKM\_AES\_CBC\_PAD<br>CKM\_DES3\_CBC<br>CKM\_DES3\_CBC\_PAD<br>CKM\_RSA\_PKCS<br>CKM\_RSA\_PKCS\_OAEP | CKO\_SECRET\_KEY if key type is AES, DES2 or DES3. Otherwise, the default is CKO\_PRIVATE\_KEY |
| DeriveKey        |                                                                                                                        | CKO\_SECRET\_KEY                                                                               |


<a name="cka-private">2</a>. Default value of `CKA_PRIVATE` is TRUE if the `Normal user` is logged in, otherwise, it is FALSE
 
