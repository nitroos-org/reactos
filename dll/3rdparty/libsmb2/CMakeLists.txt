# libsmb2.dll: the SMB2/3 client library libsmb2 (LGPL-2.1-or-later), see README.NitroOS.
# lib/ and include/ are upstream files (local changes marked "NitroOS", listed in README.NitroOS);
# nitro/ holds the NitroOS porting files (SSPI authentication, bcrypt random bytes and hashes,
# error mapping).

spec2def(libsmb2.dll libsmb2.spec ADD_IMPORTLIB)

include_directories(BEFORE
    ${CMAKE_CURRENT_SOURCE_DIR}/nitro
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/smb2
    ${CMAKE_CURRENT_SOURCE_DIR}/lib)

# _WINDOWS: libsmb2's headers key their Windows paths on it (not on _WIN32).
# _WIN32_WINNT 0x600: WSAPoll. WIN32_LEAN_AND_MEAN: keeps winioctl.h out, whose FILE_DEVICE_*
# macros smb2.h defines again (a redefinition warning otherwise).
remove_definitions(-D_WIN32_WINNT=0x502)
add_definitions(-D_WIN32_WINNT=0x600 -DWIN32_LEAN_AND_MEAN -D_WINDOWS -DHAVE_CONFIG_H -D_CRT_NONSTDC_NO_DEPRECATE)
# What libsmb2's own CMake sets for Windows, and the NitroOS backends (see nitro/config.h)
add_definitions(-DNEED_GETLOGIN_R -DNEED_GETPID -DNEED_RANDOM -DNEED_SRANDOM -DHAVE_SSPI -DHAVE_ARC4RANDOM_BUF)

# AES-128-CCM (SMB 3.x encryption) and AES-128-CMAC (SMB 3.x signing): through bcrypt (SymCrypt, AES
# instructions; nitro/aes-bcrypt.c) or libsmb2's own code (lib/aes128ccm.c, lib/smb2-signing.c). Measured on
# the encrypted shares: see README.NitroOS. OFF builds libsmb2's own.
set(NITRO_SMB2_BCRYPT_AES ON)
if(NITRO_SMB2_BCRYPT_AES)
    add_definitions(-DNITRO_SMB2_BCRYPT_AES)
    set(LIBSMB2_CCM_SOURCE nitro/aes-bcrypt.c)
else()
    set(LIBSMB2_CCM_SOURCE lib/aes128ccm.c)
endif()

list(APPEND SOURCE
    lib/aes.c
    lib/aes_reference.c
    ${LIBSMB2_CCM_SOURCE}
    lib/alloc.c
    lib/asn1-ber.c
    lib/compat.c
    lib/errors.c
    lib/init.c
    lib/libsmb2.c
    lib/pdu.c
    lib/quic.c
    lib/smbdirect.c
    lib/smb2-cmd-cancel.c
    lib/smb2-cmd-close.c
    lib/smb2-cmd-create.c
    lib/smb2-cmd-echo.c
    lib/smb2-cmd-error.c
    lib/smb2-cmd-flush.c
    lib/smb2-cmd-ioctl.c
    lib/smb2-cmd-lock.c
    lib/smb2-cmd-logoff.c
    lib/smb2-cmd-negotiate.c
    lib/smb2-cmd-notify-change.c
    lib/smb2-cmd-oplock-break.c
    lib/smb2-cmd-query-directory.c
    lib/smb2-cmd-query-info.c
    lib/smb2-cmd-read.c
    lib/smb2-cmd-session-setup.c
    lib/smb2-cmd-set-info.c
    lib/smb2-cmd-tree-connect.c
    lib/smb2-cmd-tree-disconnect.c
    lib/smb2-cmd-write.c
    lib/smb2-data-file-info.c
    lib/smb2-data-filesystem-info.c
    lib/smb2-data-reparse-point.c
    lib/smb2-data-security-descriptor.c
    lib/smb2-share-enum.c
    lib/smb2-signing.c
    lib/smb3-seal.c
    lib/socket.c
    lib/spnego-wrapper.c
    lib/sync.c
    lib/timestamps.c
    lib/unicode.c
    nitro/crypto.c
    nitro/errmap.c
    nitro/ntlmssp-off.c
    nitro/sspi.c)

add_library(libsmb2 MODULE
    ${SOURCE}
    libsmb2.rc
    ${CMAKE_CURRENT_BINARY_DIR}/libsmb2.def)

if(NOT MSVC)
    # Upstream code, kept byte-identical: -Wno-pointer-sign (uint8_t * vs char * all over the codecs),
    # -Wno-unused-function (helpers only some platforms use).
    target_compile_options(libsmb2 PRIVATE -Wno-pointer-sign -Wno-unused-function)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND ARCH STREQUAL "amd64")
    # lib/smb2-signing.c has an AES-NI path for AES-CMAC on x86_64 (wmmintrin.h, cpuid.h), headers the
    # tree does not carry: take them from the compiler for that file only.
    execute_process(COMMAND ${CMAKE_C_COMPILER} -print-file-name=include
                    OUTPUT_VARIABLE _libsmb2_gcc_include OUTPUT_STRIP_TRAILING_WHITESPACE)
    set_source_files_properties(lib/smb2-signing.c PROPERTIES COMPILE_OPTIONS "-isystem;${_libsmb2_gcc_include}")
endif()

set_module_type(libsmb2 win32dll)
add_importlibs(libsmb2 secur32 bcrypt advapi32 ws2_32 msvcrt kernel32 ntdll)
add_cd_file(TARGET libsmb2 DESTINATION reactos/system32 FOR all)
