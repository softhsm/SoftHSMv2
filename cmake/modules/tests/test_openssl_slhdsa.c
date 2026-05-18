#include <openssl/evp.h>
#include <openssl/objects.h>
int main()
{
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "SLH-DSA-SHA2-128s", NULL);
    
    if (ctx == NULL)
        return 1;
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
