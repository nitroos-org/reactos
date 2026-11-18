
spec2def(ucrtbase.dll ucrtbase.spec NO_DBG ADD_IMPORTLIB)

# Hack to replace the old CRT include directory with the UCRT include directory
get_property(INCLUDE_DIRS DIRECTORY . PROPERTY INCLUDE_DIRECTORIES)
list(REMOVE_ITEM INCLUDE_DIRS "${REACTOS_SOURCE_DIR}/sdk/include/crt")
set_property(DIRECTORY . PROPERTY INCLUDE_DIRECTORIES ${INCLUDE_DIRS})
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/ucrt)

add_compile_definitions(
    _UCRT
    _CORECRT_BUILD
    CRTDLL
)

add_library(ucrtbase SHARED
    fenv.c
    math_c99.c
    math_errno.c
    printf.c
    stubs.c
    ucrtbase.rc
    ucrtbase_stubs.c
    ucrtbase.def
    musl/acosh.c
    musl/acoshf.c
    musl/asinh.c
    musl/asinhf.c
    musl/atanh.c
    musl/atanhf.c
    musl/cbrt.c
    musl/cbrtf.c
    musl/copysign.c
    musl/copysignf.c
    musl/erf.c
    musl/erff.c
    musl/expm1.c
    musl/expm1f.c
    musl/fdim.c
    musl/fdimf.c
    musl/fmax.c
    musl/fmaxf.c
    musl/fmin.c
    musl/fminf.c
    musl/ilogb.c
    musl/ilogbf.c
    musl/lgamma.c
    musl/lgamma_r.c
    musl/lgammaf.c
    musl/lgammaf_r.c
    musl/log1p.c
    musl/log1pf.c
    musl/logb.c
    musl/logbf.c
    musl/nan.c
    musl/nanf.c
    musl/remainder.c
    musl/remainderf.c
    musl/remquo.c
    musl/remquof.c
    musl/tgamma.c
    musl/tgammaf.c
    musl/__cos.c
    musl/__cosdf.c
    musl/__sin.c
    musl/__sindf.c
)

if(NOT ARCH STREQUAL "i386")
    # The musl modff keeps the sign of a zero fraction, the one of the SSE library does not
    target_sources(ucrtbase PRIVATE musl/rint.c musl/rintf.c musl/modff.c)
endif()

if(NOT MSVC)
    target_compile_options(ucrtbase PRIVATE -Wno-builtin-declaration-mismatch)
    # GCC would replace the calls of rint by code that only rounds to nearest
    set_source_files_properties(math_c99.c PROPERTIES COMPILE_OPTIONS "-fno-builtin-rint;-fno-builtin-rintf")
    # The wrappers call the library functions of the same names
    set_source_files_properties(math_errno.c PROPERTIES COMPILE_OPTIONS "-fno-builtin")
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    # Silence warnings in ucrtbase_stubs.c
    target_compile_options(ucrtbase PRIVATE -Wno-incompatible-library-redeclaration)
endif()

set_entrypoint(ucrtbase __acrt_DllMain 12)

target_link_libraries(ucrtbase
    ucrt
    msvcrt_shared
    crtmath
    vcruntime
    vcstartup
    chkstk
    wine
)

# Implicitly link to vcstartup
target_link_libraries(libucrtbase INTERFACE vcstartup)

if(MSVC)
    target_link_libraries(ucrtbase runtmchk)
else()
    # For __cxa_guard_acquire / __cxa_guard_release
    target_link_libraries(ucrtbase libsupc++)
endif()

add_importlibs(ucrtbase kernel32 ntdll)
ros_check_unwind(ucrtbase)

add_cd_file(TARGET ucrtbase DESTINATION reactos/system32 FOR all)
