project(appcompat)

list(APPEND SOURCE
    dispmode.c
    forcedxsetup.c
    genral_hooks.c
    globmemstatus.c
    ignorefreelib.c
    ignoreloadlib.c
    layer_hooks.c
    versionconflict.c
    sysmain.c
    manifestcompat.c
    versionmatrix.c
    procparamflags.c
    versionlie.c
    verifyversion.c
    testlist.c
    appshim_apitest.h
    vermatrix_w10.rc) # Windows 10 manifest: the tests expect the real version from the version APIs (S2 lie, see versionmatrix.c)

add_executable(appshim_apitest ${SOURCE})
set_module_type(appshim_apitest win32cui)
add_importlibs(appshim_apitest advapi32 version msvcrt kernel32 ntdll)
add_rostests_file(TARGET appshim_apitest)

add_executable(appshim_sysmain_probe sysmain_probe.c sysmain_probe.rc)
set_module_type(appshim_sysmain_probe win32cui)
add_importlibs(appshim_sysmain_probe advapi32 msvcrt kernel32)
add_rostests_file(TARGET appshim_sysmain_probe)

add_executable(appshim_sysmain_other sysmain_probe.c sysmain_other.rc)
set_module_type(appshim_sysmain_other win32cui)
add_importlibs(appshim_sysmain_other advapi32 msvcrt kernel32)
add_rostests_file(TARGET appshim_sysmain_other)

add_executable(appshim_sysmain_firefox158 sysmain_probe.c sysmain_firefox158.rc)
set_module_type(appshim_sysmain_firefox158 win32cui)
add_importlibs(appshim_sysmain_firefox158 advapi32 msvcrt kernel32)
add_rostests_file(TARGET appshim_sysmain_firefox158)

add_executable(appshim_sysmain_firefox115 sysmain_probe.c sysmain_firefox115.rc)
set_module_type(appshim_sysmain_firefox115 win32cui)
add_importlibs(appshim_sysmain_firefox115 advapi32 msvcrt kernel32)
add_rostests_file(TARGET appshim_sysmain_firefox115)

# Version resources of the .NET Framework setup programs (and look-alikes), see sysmain.c
foreach(_probe netfx48 netfx48_setup netfx48_util netfx40 netfx_tool netfx_other)
    add_executable(appshim_sysmain_${_probe} sysmain_probe.c sysmain_${_probe}.rc)
    set_module_type(appshim_sysmain_${_probe} win32cui)
    add_importlibs(appshim_sysmain_${_probe} advapi32 msvcrt kernel32)
    add_rostests_file(TARGET appshim_sysmain_${_probe})
    list(APPEND NETFX_PROBES appshim_sysmain_${_probe})
endforeach()

add_executable(appshim_manifestver_none manifestver_probe.c manifestver_none.rc)
set_module_type(appshim_manifestver_none win32cui)
add_importlibs(appshim_manifestver_none msvcrt kernel32 ntdll)
add_rostests_file(TARGET appshim_manifestver_none)

add_executable(appshim_manifestver_vista manifestver_probe.c manifestver_vista.rc)
set_module_type(appshim_manifestver_vista win32cui)
add_importlibs(appshim_manifestver_vista msvcrt kernel32 ntdll)
add_rostests_file(TARGET appshim_manifestver_vista)

add_executable(appshim_manifestver_span manifestver_probe.c manifestver_span.rc)
set_module_type(appshim_manifestver_span win32cui)
add_importlibs(appshim_manifestver_span msvcrt kernel32 ntdll)
add_rostests_file(TARGET appshim_manifestver_span)

add_executable(appshim_manifestver_vista_win10 manifestver_probe.c manifestver_vista_win10.rc)
set_module_type(appshim_manifestver_vista_win10 win32cui)
add_importlibs(appshim_manifestver_vista_win10 msvcrt kernel32 ntdll)
add_rostests_file(TARGET appshim_manifestver_vista_win10)

add_dependencies(appshim_apitest appshim_sysmain_probe appshim_sysmain_other
                 appshim_sysmain_firefox158 appshim_sysmain_firefox115 ${NETFX_PROBES}
                 appshim_manifestver_none appshim_manifestver_vista
                 appshim_manifestver_span appshim_manifestver_vista_win10)

# S2 of the version lie: what a program is told about the Windows version by its own manifest and PE header
# (versionmatrix.c). Each probe differs only in its manifest resource and the OS version of its PE header.
foreach(_vm none:-:- hdr63:-:6.3 hdr100:-:10.0
        man:manifestver_none.rc:- man_hdr63:manifestver_none.rc:6.3
        vista:manifestver_vista.rc:- w7:vermatrix_w7.rc:- w8:vermatrix_w8.rc:- w81:vermatrix_w81.rc:- w10:vermatrix_w10.rc:-
        w7w8w81:vermatrix_w7w8w81.rc:- w10w7:vermatrix_w10w7.rc:- empty:vermatrix_empty.rc:-
        hdr63_w8:vermatrix_w8.rc:6.3 hdr100_w8:vermatrix_w8.rc:10.0 hdr100_w7:vermatrix_w7.rc:10.0
        hdr63_w81:vermatrix_w81.rc:6.3 hdr40_w10:vermatrix_w10.rc:4.0)
    string(REPLACE ":" ";" _vm ${_vm})
    list(GET _vm 0 _vmname)
    list(GET _vm 1 _vmrc)
    list(GET _vm 2 _vmos)
    if(_vmrc STREQUAL "-")
        set(_vmrc "")
    endif()
    add_executable(appshim_vm_${_vmname} vermatrix_probe.c ${_vmrc})
    set_module_type(appshim_vm_${_vmname} win32cui)
    add_importlibs(appshim_vm_${_vmname} msvcrt kernel32 ntdll)
    if(NOT _vmos STREQUAL "-" AND NOT MSVC)
        string(REPLACE "." ";" _vmver ${_vmos})
        list(GET _vmver 0 _vmmaj)
        list(GET _vmver 1 _vmmin)
        target_link_options(appshim_vm_${_vmname} PRIVATE -Wl,--major-os-version,${_vmmaj} -Wl,--minor-os-version,${_vmmin})
    endif()
    add_rostests_file(TARGET appshim_vm_${_vmname})
    list(APPEND VERMATRIX_PROBES appshim_vm_${_vmname})
endforeach()
add_dependencies(appshim_apitest ${VERMATRIX_PROBES})
