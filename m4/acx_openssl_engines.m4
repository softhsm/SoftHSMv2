AC_DEFUN([ACX_OPENSSL_ENGINES], [

    tmp_CPPFLAGS=$CPPFLAGS
    tmp_LIBS=$LIBS

    CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
    LIBS="$CRYPTO_LIBS $LIBS"

    AC_LANG_PUSH([C])
    AC_CACHE_VAL([acx_cv_lib_openssl_engines_support], [
        acx_cv_lib_openssl_engines_support=no
        AC_COMPILE_IFELSE([
            AC_LANG_SOURCE([[
                #include <openssl/engine.h>
                #ifdef OPENSSL_NO_ENGINE
                #error "Engines are disabled"
                #endif
                int main() {
                    ENGINE_load_builtin_engines();
                    return 0;
                }
            ]])
        ], [
            acx_cv_lib_openssl_engines_support=yes
        ], [
            acx_cv_lib_openssl_engines_support=no
        ])
    ])
    AC_LANG_POP([C])

    CPPFLAGS=$tmp_CPPFLAGS
    LIBS=$tmp_LIBS

    have_lib_openssl_engines_support="${acx_cv_lib_openssl_engines_support}"
])
