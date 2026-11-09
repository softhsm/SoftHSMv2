/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <openssl/evp.h>

/** Confirm that the active provider can generate and sign with SLH-DSA. */
int main(void)
{
    int result = 1;
    const unsigned char message[] = {0};
    size_t signature_len = 0;
    unsigned char *signature = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *keyctx = EVP_PKEY_CTX_new_from_name(NULL, "SLH-DSA-SHA2-128s", NULL);
    EVP_PKEY_CTX *signctx = NULL;
    EVP_SIGNATURE *algorithm = NULL;

    if (keyctx == NULL || EVP_PKEY_keygen_init(keyctx) <= 0 ||
        EVP_PKEY_generate(keyctx, &key) <= 0)
        goto cleanup;
    signctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    algorithm = EVP_SIGNATURE_fetch(NULL, "SLH-DSA-SHA2-128s", NULL);
    if (signctx == NULL || algorithm == NULL ||
        EVP_PKEY_sign_message_init(signctx, algorithm, NULL) <= 0 ||
        EVP_PKEY_sign(signctx, NULL, &signature_len, message, sizeof(message)) <= 0)
        goto cleanup;
    signature = OPENSSL_malloc(signature_len);
    if (signature != NULL &&
        EVP_PKEY_sign(signctx, signature, &signature_len, message, sizeof(message)) > 0)
        result = 0;

cleanup:
    OPENSSL_free(signature);
    EVP_SIGNATURE_free(algorithm);
    EVP_PKEY_CTX_free(signctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(keyctx);
    return result;
}
