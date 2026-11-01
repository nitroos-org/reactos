/* Force-included into every icu.dll C++ source (see CMakeLists.txt).
 * The ReactOS CRT <stddef.h> shadows GCC's and lacks ::max_align_t, which libstdc++'s <cstddef> needs. */
#ifndef ICU_COMPAT_H
#define ICU_COMPAT_H
#ifdef __cplusplus
#include <stddef.h>
#ifndef _GCC_MAX_ALIGN_T
#define _GCC_MAX_ALIGN_T
typedef struct
{
    long long __max_align_ll __attribute__((__aligned__(__alignof__(long long))));
    long double __max_align_ld __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
#endif
#endif
#endif
