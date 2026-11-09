AC_DEFUN([ACX_OPENSSL_SLHDSA],[
	AC_MSG_CHECKING(for OpenSSL SLH-DSA support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_CACHE_VAL([acx_cv_lib_openssl_slhdsa_support],[
		acx_cv_lib_openssl_slhdsa_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
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
			]])
		],[
			AC_MSG_RESULT([yes])
			acx_cv_lib_openssl_slhdsa_support=yes
		],[
			AC_MSG_RESULT([no])
			acx_cv_lib_openssl_slhdsa_support=no
		],[
			AC_MSG_WARN([Cannot run the SLH-DSA test while cross-compiling. With --enable-slhdsa, preset acx_cv_lib_openssl_slhdsa_support=yes only after verifying that the target can generate SLH-DSA keys and sign])
			acx_cv_lib_openssl_slhdsa_support=no
		])
	])

	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_openssl_slhdsa_support="${acx_cv_lib_openssl_slhdsa_support}"
])
