# SPDX-License-Identifier: GPL-2.0-or-later
add_executable(conhost conhost.c)
set_module_type(conhost win32cui UNICODE)
add_importlibs(conhost msvcrt kernel32 ntdll)
add_cd_file(TARGET conhost DESTINATION reactos/system32 FOR all)
