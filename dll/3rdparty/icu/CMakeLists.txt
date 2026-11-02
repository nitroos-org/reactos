# ICU4C 64.2, the version of the Windows 10 (1903 .. 22H2) system ICU: icu.dll plus the icuuc.dll / icuin.dll forwarders.
# See README.ReactOS (origin, version, local changes, data file).

# The system ICU is a Windows 10 component: it needs SRW locks and condition variables (kernel32, NT 6.0+).
if(DLL_EXPORT_VERSION LESS 0x600)
    return()
endif()

remove_definitions(-D_WIN32_WINNT=0x502 -DWINVER=0x502)
add_definitions(
    -D_WIN32_WINNT=0x601 -DWINVER=0x601
    -DU_DISABLE_RENAMING=1          # unversioned C names, as the Windows icu.dll exports them
    -DU_STATIC_IMPLEMENTATION       # no __declspec(dllexport): the exports come from icu.spec
    -DU_COMMON_IMPLEMENTATION
    -DU_I18N_IMPLEMENTATION
    -DU_ATTRIBUTE_DEPRECATED=
    -DU_HAVE_STD_STRING=1
    -DUCONFIG_USE_WINDOWS_LCID_MAPPING_API=0   # LCIDs from ICU tables, not LocaleNameToLCID (the ReactOS NLS has 146 locales, Windows 813)
    -D_CMATH_)                      # libstdc++ <cmath> supplies the float overloads; ReactOS <math.h> skips its own

# Upstream code: no warnings (the tree builds with -Werror); libstdc++ needs ::max_align_t
add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:-w>"
    "$<$<COMPILE_LANGUAGE:CXX>:SHELL:-include ${CMAKE_CURRENT_SOURCE_DIR}/icu_compat.h>")

spec2def(icu.dll icu.spec ADD_IMPORTLIB)

file(GLOB ICU_COMMON_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/common/*.cpp)
file(GLOB ICU_I18N_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/i18n/*.cpp)

add_library(icu MODULE
    ${ICU_COMMON_SOURCE}
    ${ICU_I18N_SOURCE}
    stubdata/stubdata.cpp
    icu_main.cpp
    icu_crt.cpp
    icu.rc
    ${CMAKE_CURRENT_BINARY_DIR}/icu.def)

target_include_directories(icu PRIVATE common i18n)
set_module_type(icu win32dll UNICODE)
set_target_cpp_properties(icu WITH_RTTI)
target_link_libraries(icu cppstl)
add_importlibs(icu msvcrt kernel32 ntdll)
add_cd_file(TARGET icu DESTINATION reactos/system32 FOR all)

# icuuc.dll / icuin.dll: Windows 10 splits the exports of icu.dll over these two forward-only modules
spec2def(icuuc.dll icuuc.spec)
add_library(icuuc MODULE icuuc.rc ${CMAKE_CURRENT_BINARY_DIR}/icuuc.def)
set_module_type(icuuc win32dll ENTRYPOINT 0)
add_importlibs(icuuc icu)
add_cd_file(TARGET icuuc DESTINATION reactos/system32 FOR all)

spec2def(icuin.dll icuin.spec)
add_library(icuin MODULE icuin.rc ${CMAKE_CURRENT_BINARY_DIR}/icuin.def)
set_module_type(icuin win32dll ENTRYPOINT 0)
add_importlibs(icuin icu)
add_cd_file(TARGET icuin DESTINATION reactos/system32 FOR all)

# ICU data: data/icudtl.dat is the upstream icudt64l.dat package (64.2, little endian) under the file name Windows 10
# uses; icu_main.cpp maps it from %SystemRoot%\Globalization\ICU\icudtl.dat.
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/data/icudtl.dat DESTINATION reactos/Globalization/ICU FOR all)
