# Mesa3D software drivers (prebuilt by build-mesa.sh); see README.md

# When an LLVM pack is requested (MESA3D_AMD64_LLVM / MESA3D_WOW64_LLVM, ON by default) but cannot be staged, the
# configure prints a loud banner and falls back to softpipe. With NITRO_REQUIRE_LLVM_PACKS=ON that is a configure
# error instead (release / postland configs, harness golden builds). Developer builds keep the warning only.
option(NITRO_REQUIRE_LLVM_PACKS "Fail the configure when a requested Mesa3D LLVM pack cannot be staged (no silent softpipe)" OFF)

# The OpenGL driver this build directory will ship, for the golden / harness manifest: <build dir>/mesa3d-renderer.txt
#   renderer=llvmpipe | softpipe (LLVM pack missing) | softpipe (<other reason>)
# mesa3d_record_renderer(<arch> <renderer> <detail>)
function(mesa3d_record_renderer ARCH_NAME RENDERER DETAIL)
    file(WRITE ${CMAKE_BINARY_DIR}/mesa3d-renderer.txt
        "renderer=${RENDERER}\narch=${ARCH_NAME}\ndetail=${DETAIL}\nrequire_llvm_packs=${NITRO_REQUIRE_LLVM_PACKS}\n")
endfunction()

# Runs the staging script of an llvmpipe pack on every configure (it is a no-op that needs no network when the
# directory is already staged with the script's pinned artifact, and replaces a stale one) and sets, in the caller:
#   <prefix>_OK      TRUE when the pack is staged, verified and complete (DLL, licence files and SHA256SUMS)
#   <prefix>_STATUS  the status line printed at the end of the configure
# mesa3d_stage_llvm(<prefix> <arch> <script> <dir> <enabled> <why not enabled> <files>...)
function(mesa3d_stage_llvm PREFIX ARCH_NAME SCRIPT DIRNAME ENABLED WHY_OFF)
    set(_dir ${CMAKE_CURRENT_SOURCE_DIR}/${DIRNAME})
    set(_ok FALSE)
    set(_reason "${WHY_OFF}")
    set(_stage_detail "${WHY_OFF}")
    if(ENABLED)
        message(STATUS "Mesa3D: staging the ${ARCH_NAME} llvmpipe pack ...")
        execute_process(
            COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/${SCRIPT}
            RESULT_VARIABLE _rc
            OUTPUT_VARIABLE _out
            ERROR_VARIABLE _out)
        string(STRIP "${_out}" _out)
        if(NOT _rc EQUAL 0)
            # the script's last line is its one-line reason
            string(REGEX REPLACE "^.*\n" "" _reason "${_out}")
            string(REGEX REPLACE "^stage-[a-z0-9]+-llvm: " "" _reason "${_reason}")
            set(_stage_detail "rc=${_rc}: ${_out}")
        else()
            message(STATUS "Mesa3D: ${_out}")
            set(_ok TRUE)
            # the DLLs and both notices, not only the DLL: a half-populated directory must not be accepted
            foreach(_f ${ARGN} SHA256SUMS .artifact-sha256)
                if(NOT EXISTS ${_dir}/${_f})
                    set(_ok FALSE)
                    set(_reason "staged ${DIRNAME}/ lacks ${_f}")
                endif()
            endforeach()
        endif()
    endif()
    if(_ok)
        file(STRINGS ${_dir}/.artifact-sha256 _pin LIMIT_COUNT 1)
        string(SUBSTRING "${_pin}" 0 8 _sha8)
        set(_status "Mesa3D ${ARCH_NAME}: llvmpipe (artifact ${_sha8})")
        mesa3d_record_renderer("${ARCH_NAME}" "llvmpipe" "artifact ${_sha8}")
    else()
        set(_status "Mesa3D ${ARCH_NAME}: softpipe fallback (${_reason})")
        if(ENABLED)
            # an LLVM pack was asked for (the default of the configs we ship) but is not there: never silent
            mesa3d_record_renderer("${ARCH_NAME}" "softpipe (LLVM pack missing)" "${_reason}")
            set(_banner
"\n"
"**********************************************************************\n"
"*  Mesa3D ${ARCH_NAME}: LLVM PACK MISSING -> renderer=softpipe\n"
"*  ${_reason}\n"
"*  The OpenGL driver will be softpipe: no WebGL, no Direct2D render\n"
"*  target, no Vulkan (lavapipe). GPU/WebGL/D2D smoke results from this\n"
"*  build are NOT representative of the shipped image.\n"
"*  Fix: set LAVAPIPE_ARTIFACT (amd64) / LLVMPIPE_I386_ARTIFACT (i386)\n"
"*  to the local pack tarball, or give this host rclone + remote 'vultr'.\n"
"*  Details: ${_stage_detail}\n"
"*  The fallback is recorded in ${CMAKE_BINARY_DIR}/mesa3d-renderer.txt\n"
"**********************************************************************\n")
            if(NITRO_REQUIRE_LLVM_PACKS)
                message(FATAL_ERROR ${_banner}
"*  NITRO_REQUIRE_LLVM_PACKS=ON: refusing to configure with softpipe.\n"
"*  (-DNITRO_REQUIRE_LLVM_PACKS=OFF accepts the fallback)\n")
            else()
                message(WARNING ${_banner})
            endif()
        else()
            mesa3d_record_renderer("${ARCH_NAME}" "softpipe (${_reason})" "")
        endif()
    endif()
    set(${PREFIX}_OK ${_ok} PARENT_SCOPE)
    set(${PREFIX}_STATUS "${_status}" PARENT_SCOPE)
endfunction()

# One status line per arch; the top-level CMakeLists.txt prints them at the end of the configure
function(mesa3d_report_status LINE)
    set_property(GLOBAL APPEND PROPERTY MESA3D_STATUS_LINES "${LINE}")
endfunction()

if(ARCH STREQUAL "i386" OR ARCH STREQUAL "amd64")
    set(MESA3D_GL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${ARCH})
    set(MESA3D_LICENSES ${CMAKE_CURRENT_SOURCE_DIR}/mesa3d-licenses.txt)

    # amd64 ships llvmpipe (OpenGL) + lavapipe (Vulkan) as the DEFAULT GPU of the base image. The
    # ~116 MB pack is not in git, so it is fetched from the S3 cold tier at configure time by
    # stage-amd64-llvm.sh. This is ON by default; -DMESA3D_AMD64_LLVM=OFF, or a build host without
    # rclone / network / the artifact (every public builder: the S3 remote is private), falls back to the
    # in-tree softpipe-only OpenGL driver below (no Vulkan ICD) so the build never breaks. i386 uses
    # softpipe, except SysWOW64 (below).
    option(MESA3D_AMD64_LLVM "amd64: default to llvmpipe/lavapipe (fetch the LLVM Mesa pack from S3 at configure)" ON)
    if(ARCH STREQUAL "amd64")
        mesa3d_stage_llvm(_mesa3d_amd64 amd64 stage-amd64-llvm.sh amd64-llvm ${MESA3D_AMD64_LLVM}
            "disabled by -DMESA3D_AMD64_LLVM=OFF"
            vulkan_lvp.dll lvp_icd.json libgallium_wgl.dll llvm-licenses.txt mesa3d-licenses.txt)
        mesa3d_report_status("${_mesa3d_amd64_STATUS}")
    endif()

    # amd64: when amd64-llvm/ holds the LLVM build (llvmpipe for OpenGL, lavapipe for Vulkan), it replaces the softpipe-only
    # OpenGL driver and adds the Vulkan ICD. The LLVM DLLs are 66-69 MB each, so they are an option of the image.
    if(ARCH STREQUAL "amd64" AND _mesa3d_amd64_OK)
        set(MESA3D_GL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/amd64-llvm)
        add_cd_file(FILE ${MESA3D_GL_DIR}/vulkan_lvp.dll DESTINATION reactos/system32 FOR all)
        add_cd_file(FILE ${MESA3D_GL_DIR}/lvp_icd.json DESTINATION reactos/system32 FOR all)
        add_cd_file(FILE ${MESA3D_GL_DIR}/llvm-licenses.txt DESTINATION reactos/system32 FOR all)
        set(MESA3D_LICENSES ${MESA3D_GL_DIR}/mesa3d-licenses.txt)
    endif()

    # The i386 part of SysWOW64 (the nested i386 build of an amd64 image) ships llvmpipe as well, so that 32-bit
    # programs get OpenGL 4.6 with compute shaders like the 64-bit side (wgpu needs them; softpipe stops at 3.3).
    # The 73 MB DLL is not in git: stage-i386-llvm.sh fetches it at configure time like the amd64 pack, and without
    # it (-DMESA3D_WOW64_LLVM=OFF, no rclone/network/artifact) SysWOW64 keeps the in-tree softpipe driver. A native
    # i386 image keeps softpipe.
    option(MESA3D_WOW64_LLVM "SysWOW64: ship the i386 llvmpipe OpenGL driver (fetched from S3 at configure)" ON)
    if(ARCH STREQUAL "i386")
        if(SYSWOW64_GUEST)
            mesa3d_stage_llvm(_mesa3d_i386 i386 stage-i386-llvm.sh i386-llvm ${MESA3D_WOW64_LLVM}
                "disabled by -DMESA3D_WOW64_LLVM=OFF"
                libgallium_wgl.dll mesa3d-licenses.txt)
            mesa3d_report_status("${_mesa3d_i386_STATUS}")
        else()
            mesa3d_report_status("Mesa3D i386: softpipe fallback (native i386 image, llvmpipe is staged for the SysWOW64 guest only)")
            mesa3d_record_renderer(i386 "softpipe (native i386 image)" "")
        endif()
    endif()
    if(ARCH STREQUAL "i386" AND SYSWOW64_GUEST AND _mesa3d_i386_OK)
        set(MESA3D_GL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/i386-llvm)
        set(MESA3D_LICENSES ${MESA3D_GL_DIR}/mesa3d-licenses.txt)
    endif()

    add_cd_file(FILE ${MESA3D_GL_DIR}/libgallium_wgl.dll DESTINATION reactos/system32 FOR all)
    add_cd_file(FILE ${MESA3D_LICENSES} DESTINATION reactos/system32 FOR all)
endif()
