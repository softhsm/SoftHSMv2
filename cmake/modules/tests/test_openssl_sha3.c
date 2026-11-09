/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <openssl/evp.h>
int main()
{
    const EVP_MD *md224 = EVP_sha3_224();
    const EVP_MD *md256 = EVP_sha3_256();
    const EVP_MD *md384 = EVP_sha3_384();
    const EVP_MD *md512 = EVP_sha3_512();
    if (md224 == NULL || md256 == NULL || md384 == NULL || md512 == NULL)
        return 1;
    return 0;
}
