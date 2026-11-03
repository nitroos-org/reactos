
project(featmgr)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# --- CLI frontend (automation): featmgr /list /query /enable /disable ---
add_executable(featmgr cli.c engine.c components.c shelldefaults.c rapps_import.c scoop.c scoopdefaults.c featmgr.rc)
set_module_type(featmgr win32cui UNICODE)
target_link_libraries(featmgr uuid)
add_importlibs(featmgr advapi32 shlwapi shell32 ole32 user32 wininet msvcrt kernel32 ntdll)
add_cd_file(TARGET featmgr DESTINATION reactos/system32 FOR all)

# --- refreshenv: re-read PATH into the cmd / PowerShell window that is open (a child like featmgr cannot) ---
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/refreshenv.cmd DESTINATION reactos/system32 FOR all)
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/refreshenv.ps1 DESTINATION reactos/system32 FOR all)

# --- GUI applet: "Optional Features" (Turn features on/off) ---
add_executable(optfeatures gui.c featwin.c progwin.c firstboot.c engine.c components.c shelldefaults.c rapps_import.c scoop.c scoopdefaults.c optfeatures.rc)
set_module_type(optfeatures win32gui UNICODE)
target_link_libraries(optfeatures uuid)
add_importlibs(optfeatures advapi32 shlwapi shell32 ole32 comctl32 user32 gdi32 wininet msvcrt kernel32 ntdll)
add_cd_file(TARGET optfeatures DESTINATION reactos/system32 FOR all)

# --- optionalfeatures.exe: the Windows name; launches optfeatures.exe (no Control Panel icon, appwiz.cpl hosts it) ---
add_executable(optionalfeatures optionalfeatures.c optionalfeatures.rc)
set_module_type(optionalfeatures win32gui UNICODE)
add_importlibs(optionalfeatures shell32 user32 msvcrt kernel32)
add_cd_file(TARGET optionalfeatures DESTINATION reactos/system32 FOR all)

# --- ship the feature catalog + proof-feature payload into the image ---
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/gl-sw-pack.ini
            DESTINATION reactos/Featmgr/Catalog FOR all)
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/lavapipe-pack.ini
            DESTINATION reactos/Featmgr/Catalog FOR all)
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/winfsp.ini
            DESTINATION reactos/Featmgr/Catalog FOR all)
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/payload/gl-sw-pack/glsw-pack.txt
            DESTINATION reactos/Featmgr/Payload/gl-sw-pack FOR all)

# --- Claude Desktop: software-tier entry (amd64 only, Anthropic ships an x64 build) ---
# Only the manifest and a RAPPS-format entry (not a manifest: the catalog scan reads *.ini) ship in the image. The app itself is downloaded
# from Anthropic's release feed at install time (SHA1-checked) and is never bundled.
if(ARCH STREQUAL "amd64")
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/claude-desktop.ini
                DESTINATION reactos/Featmgr/Catalog FOR all)
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/claude-desktop.txt
                DESTINATION reactos/Featmgr/Catalog FOR all)
endif()

# --- PowerShell 7 (LTS) and Mozilla Firefox: software-tier entries (amd64 only; the x86 pwsh does not start yet, PS7-x86-pwsh-mscoree) ---
# Only the manifests ship; their recipes (official download address, SHA-256, size, detect rule, install and uninstall
# commands) are the [powershell-7] and [firefox] sections of Catalog\components.ini. Both are installed at first boot with
# .NET 4.8 (optfeatures /firstboot) and are downloaded from Microsoft's PowerShell release on GitHub and from Mozilla; neither
# is bundled in the image (the former build-time MSI preinstall, FEATMGR_PS7_PREINSTALL, is gone).
if(ARCH STREQUAL "amd64")
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/powershell-7.ini
                DESTINATION reactos/Featmgr/Catalog FOR all)
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/firefox.ini
                DESTINATION reactos/Featmgr/Catalog FOR all)
endif()

# --- Microsoft .NET Framework 4.8: software-tier entry (i386 and amd64) ---
# The manifest only; its recipe is the [dotnet-framework-4.8] section of Catalog\components.ini (below). The official offline installer
# is downloaded from Microsoft at install time (SHA-256 checked by featmgr) and is never bundled; the application
# compatibility database gives it the Windows 7 SP1 answer.
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/dotnet-framework-4.8.ini
            DESTINATION reactos/Featmgr/Catalog FOR all)

# --- the component list: the one data file for downloaded components (name, URL, SHA-256, size, detect rule, install
# command) and for the first-boot installer's default set ("optfeatures /firstboot", started by the HKLM Run value
# NitroComponents in hivesft.inf).
# (it sits in the Catalog folder: the catalog scan skips an .ini without a [Feature] Id)
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/components.ini
            DESTINATION reactos/Featmgr/Catalog FOR all)

# --- Scoop (SCOOP-FEATMGR-01): software-tier entry + its install/uninstall scripts (amd64 only: it needs
# PowerShell 7, which has no x86 build yet; on i386 the feature is not in the catalog and
# "featmgr /import-scoop" refuses). Only the manifest and two small scripts ship; the Scoop installer is
# downloaded at install time (pinned commit + SHA-256 checked in scoop-install.ps1) and never bundled.
if(ARCH STREQUAL "amd64")
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/scoop.ini
                DESTINATION reactos/Featmgr/Catalog FOR all)
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/scoop-install.ps1
                DESTINATION reactos/Featmgr/Catalog FOR all)
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/scoop-uninstall.ps1
                DESTINATION reactos/Featmgr/Catalog FOR all)
endif()
