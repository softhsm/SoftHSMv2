AC_DEFUN([ACX_OPENSSL_MLDSA],[
	AC_MSG_CHECKING(for OpenSSL ML-DSA support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_CACHE_VAL([acx_cv_lib_openssl_mldsa_support],[
		acx_cv_lib_openssl_mldsa_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
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
			]])
		],[
			AC_MSG_RESULT([yes])
			acx_cv_lib_openssl_mldsa_support=yes
		],[
			AC_MSG_RESULT([no])
			acx_cv_lib_openssl_mldsa_support=no
		],[
			AC_MSG_WARN([Cannot test, ML-DSA])
			acx_cv_lib_openssl_mldsa_support=no
		])
	])

	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_openssl_mldsa_support="${acx_cv_lib_openssl_mldsa_support}"
])
