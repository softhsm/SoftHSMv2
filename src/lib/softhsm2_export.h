
#ifndef SOFTHSM2_EXPORT_H
#define SOFTHSM2_EXPORT_H

#ifdef SOFTHSM2_STATIC_DEFINE
#  define SOFTHSM2_EXPORT
#  define SOFTHSM2_NO_EXPORT
#else
#  ifndef SOFTHSM2_EXPORT
#    ifdef softhsm2_EXPORTS
        /* We are building this library */
#      define SOFTHSM2_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define SOFTHSM2_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef SOFTHSM2_NO_EXPORT
#    define SOFTHSM2_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef SOFTHSM2_DEPRECATED
#  define SOFTHSM2_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef SOFTHSM2_DEPRECATED_EXPORT
#  define SOFTHSM2_DEPRECATED_EXPORT SOFTHSM2_EXPORT SOFTHSM2_DEPRECATED
#endif

#ifndef SOFTHSM2_DEPRECATED_NO_EXPORT
#  define SOFTHSM2_DEPRECATED_NO_EXPORT SOFTHSM2_NO_EXPORT SOFTHSM2_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef SOFTHSM2_NO_DEPRECATED
#    define SOFTHSM2_NO_DEPRECATED
#  endif
#endif

#endif /* SOFTHSM2_EXPORT_H */
