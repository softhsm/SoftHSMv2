#include <openssl/evp.h>
#include <openssl/objects.h>
int main()
{
    EVP_PKEY_CTX *pctx =
        EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
        if (pctx == NULL)
            return 1;
        return 0;
}