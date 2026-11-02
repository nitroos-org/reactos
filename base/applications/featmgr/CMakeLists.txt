
project(featmgr)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# --- CLI frontend (automation): featmgr /list /query /enable /disable ---
add_executable(featmgr cli.c engine.c rapps_import.c scoop.c featmgr.rc)
set_module_type(featmgr win32cui UNICODE)
add_importlibs(featmgr advapi32 shlwapi shell32 user32 msvcrt kernel32 ntdll)
add_cd_file(TARGET featmgr DESTINATION reactos/system32 FOR all)

# --- refreshenv: re-read PATH into the cmd / PowerShell window that is open (a child like featmgr cannot) ---
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/refreshenv.cmd DESTINATION reactos/system32 FOR all)
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/refreshenv.ps1 DESTINATION reactos/system32 FOR all)

# --- GUI applet: "Optional Features" (Turn features on/off) ---
add_executable(optfeatures gui.c engine.c rapps_import.c scoop.c optfeatures.rc)
set_module_type(optfeatures win32gui UNICODE)
add_importlibs(optfeatures advapi32 shlwapi shell32 comctl32 user32 gdi32 msvcrt kernel32 ntdll)
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

# --- PowerShell 7 (LTS): software-tier entry + preinstall (amd64 only; the x86 pwsh does not start yet, PS7-x86-pwsh-mscoree) ---
# The manifest + RAPPS-format entry always ship. The official MSI (MIT) is NOT in git: stage-powershell7.sh downloads it
# at configure time from the pinned release URL and checks the pinned SHA-256 (POWERSHELL7_MSI=<file> for an offline
# host). When it is staged, the install image (bootcd / regtest, not the live CD) carries it, with the licence and
# ThirdPartyNotices.txt, in the feature manager's payload folder, and syssetup installs it silently during the GUI
# phase (dll/win32/syssetup/addons.c, through "featmgr /enable powershell-7", local-first). When staging fails
# (no network, no file) or -DFEATMGR_PS7_PREINSTALL=OFF, the image has no MSI, setup skips the step, and the
# Optional Features entry downloads the MSI at install time, as before.
if(ARCH STREQUAL "amd64")
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/powershell-7.ini
                DESTINATION reactos/Featmgr/Catalog FOR all)
    add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/powershell-7.txt
                DESTINATION reactos/Featmgr/Catalog FOR all)

    option(FEATMGR_PS7_PREINSTALL "amd64: bundle the PowerShell 7 MSI in the image and install it during setup (downloaded at configure)" ON)
    set(_ps7_dir ${CMAKE_CURRENT_SOURCE_DIR}/payload/powershell-7)
    set(_ps7_msi ${_ps7_dir}/PowerShell-x64.msi)
    set(_ps7_status "disabled by -DFEATMGR_PS7_PREINSTALL=OFF")
    if(FEATMGR_PS7_PREINSTALL)
        message(STATUS "PowerShell 7: staging the x64 MSI ...")
        execute_process(
            COMMAND bash ${_ps7_dir}/stage-powershell7.sh
            RESULT_VARIABLE _ps7_rc
            OUTPUT_VARIABLE _ps7_out
            ERROR_VARIABLE _ps7_out)
        string(STRIP "${_ps7_out}" _ps7_out)
        if(_ps7_rc EQUAL 0 AND EXISTS ${_ps7_msi})
            message(STATUS "PowerShell 7: ${_ps7_out}")
            set(_ps7_status "MSI bundled, installed during setup")
            # the staged file has one fixed name (cab entries cannot be renamed): syssetup tests for it; the version lives in the catalog entry
            add_cd_file(FILE ${_ps7_msi}
                        DESTINATION reactos/Featmgr/Payload/powershell-7 FOR bootcd regtest)
            add_cd_file(FILE ${_ps7_dir}/LICENSE.txt
                        DESTINATION reactos/Featmgr/Payload/powershell-7 FOR bootcd regtest)
            add_cd_file(FILE ${_ps7_dir}/ThirdPartyNotices.txt
                        DESTINATION reactos/Featmgr/Payload/powershell-7 FOR bootcd regtest)
        else()
            message(WARNING "PowerShell 7: could not stage the x64 MSI (rc=${_ps7_rc}); the image gets no preinstall, "
                            "the Optional Features entry downloads it instead. Output:\n${_ps7_out}")
            set(_ps7_status "not bundled (staging failed)")
        endif()
    endif()
    set_property(GLOBAL APPEND PROPERTY MESA3D_STATUS_LINES "PowerShell 7 amd64: ${_ps7_status}")
endif()

# --- Microsoft .NET Framework 4.8: software-tier entry (i386 and amd64) ---
# Manifest + RAPPS-format entry only. The official offline installer is downloaded from Microsoft at install time
# (SHA-256 checked) and is never bundled; the application compatibility database gives it the Windows 7 SP1 answer.
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/dotnet-framework-4.8.ini
            DESTINATION reactos/Featmgr/Catalog FOR all)
add_cd_file(FILE ${CMAKE_CURRENT_SOURCE_DIR}/catalog/dotnet-framework-4.8.txt
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
