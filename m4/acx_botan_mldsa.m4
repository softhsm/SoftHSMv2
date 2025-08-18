AC_DEFUN([ACX_BOTAN_MLDSA],[
	AC_MSG_CHECKING(for Botan ML-DSA support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_CACHE_VAL([acx_cv_lib_botan_mldsa_support], [
		AC_COMPILE_IFELSE([
			AC_LANG_SOURCE([
			#include <botan/version.h>
			#ifndef BOTAN_HAS_ML_DSA
			# error "no ML-DSA support"
			#endif
			int main(void){ return 0; }
			])
		], [
			acx_cv_lib_botan_mldsa_support=yes
			AC_MSG_RESULT([yes])
		], [
			acx_cv_lib_botan_mldsa_support=no
			AC_MSG_RESULT([no])
		])
	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_botan_mldsa_support="${acx_cv_lib_botan_mldsa_support}"
])
