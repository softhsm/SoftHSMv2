AC_DEFUN([ACX_BOTAN_MLDSA],[
	AC_MSG_CHECKING(for Botan ML-DSA support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_CACHE_VAL([acx_cv_lib_botan_mldsa_support],[
		acx_cv_lib_botan_mldsa_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <botan/version.h>
				int main()
				{
					// TODO
					return 1;
				}
			]])
		],[
			AC_MSG_RESULT([yes])
			acx_cv_lib_botan_mldsa_support=yes
		],[
			AC_MSG_RESULT([no])
			acx_cv_lib_botan_mldsa_support=no
		],[
			AC_MSG_WARN([Cannot test, assuming no ML-DSA])
			acx_cv_lib_botan_mldsa_support=no
		])
	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_botan_mldsa_support="${acx_cv_lib_botan_mldsa_support}"
])
