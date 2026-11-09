AC_DEFUN([ACX_OPENSSL_SHA3],[
	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C])
	AC_CACHE_CHECK([for OpenSSL SHA3 support], [acx_cv_lib_openssl_sha3_support],[
		acx_cv_lib_openssl_sha3_support=no
		AC_LINK_IFELSE([
			AC_LANG_SOURCE([[
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
			]])
		],[
			acx_cv_lib_openssl_sha3_support=yes
		],[
			acx_cv_lib_openssl_sha3_support=no
		])
	])
	AC_LANG_POP([C])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_openssl_sha3_support="${acx_cv_lib_openssl_sha3_support}"
])
