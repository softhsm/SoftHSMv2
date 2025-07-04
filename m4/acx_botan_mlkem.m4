AC_DEFUN([ACX_BOTAN_MLKEM],[
	AC_MSG_CHECKING(for Botan ML-KEM support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_CACHE_VAL([acx_cv_lib_botan_mlkem_support],[
		acx_cv_lib_botan_mlkem_support=no
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
			acx_cv_lib_botan_mlkem_support=yes
		],[
			AC_MSG_RESULT([no])
			acx_cv_lib_botan_mlkem_support=no
		],[
			AC_MSG_WARN([Cannot test, assuming no ML-KEM])
			acx_cv_lib_botan_mlkem_support=no
		])
	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_botan_mlkem_support="${acx_cv_lib_botan_mlkem_support}"
])
