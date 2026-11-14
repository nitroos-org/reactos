# NTFS-NG: NTFS on the vendored, unmodified Linux fs/ntfs core
# (torvalds/linux v7.3-rc6, a90ee4305c4a5df72c11b31dacfdc76e00fcf78a) behind a Linux-API shim.

list(APPEND CORE_SOURCE
    fs/ntfs/aops.c
    fs/ntfs/attrib.c
    fs/ntfs/attrlist.c
    fs/ntfs/bdev-io.c
    fs/ntfs/bitmap.c
    fs/ntfs/collate.c
    fs/ntfs/compress.c
    fs/ntfs/debug.c
    fs/ntfs/dir.c
    fs/ntfs/ea.c
    fs/ntfs/file.c
    fs/ntfs/index.c
    fs/ntfs/inode.c
    fs/ntfs/iomap.c
    fs/ntfs/lcnalloc.c
    fs/ntfs/lib/decompress_common.c
    fs/ntfs/lib/lzx_decompress.c
    fs/ntfs/lib/xpress_decompress.c
    fs/ntfs/logfile.c
    fs/ntfs/mft.c
    fs/ntfs/mst.c
    fs/ntfs/namei.c
    fs/ntfs/object_id.c
    fs/ntfs/reparse.c
    fs/ntfs/runlist.c
    fs/ntfs/super.c
    fs/ntfs/sysctl.c
    fs/ntfs/unistr.c
    fs/ntfs/upcase.c
    fs/ntfs/wof.c
    shim/kshim.c
    shim/kshim_iomap.c
    shim/kshim_printf.c
    shim/kshim_stubs.c
    shim/kshim_wb.c
    shim/kshim_jnl.c
    core/ngcore.c
    core/ngjrec.c
    core/ngfsck.c)

list(APPEND NT_SOURCE
    nt/access.c
    nt/create.c
    nt/diag.c
    nt/dirctl.c
    nt/fsctl.c
    nt/info.c
    nt/ngos_nt.c
    nt/ntfsng.c
    nt/pagefile.c
    nt/read.c
    nt/security.c
    nt/write.c
    nt/ntfsng.h)

# The Linux core and the shim see only the shim headers (no NT header), as GNU C11,
# with GCC bitfield layout (mingw defaults to MS layout) and without the tree's -Werror.
set_source_files_properties(${CORE_SOURCE} PROPERTIES COMPILE_FLAGS
    "-std=gnu11 -mno-ms-bitfields -w -D__KERNEL__ -DCONFIG_NTFS_FS_WOF_COMPRESSION -I${CMAKE_CURRENT_SOURCE_DIR}/shim/include -I${CMAKE_CURRENT_SOURCE_DIR}/fs -I${CMAKE_CURRENT_SOURCE_DIR}/core")

add_library(ntfsng MODULE ${NT_SOURCE} ${CORE_SOURCE} ntfsng.rc)
set_module_type(ntfsng kernelmodedriver)
target_link_libraries(ntfsng ${PSEH_LIB} memcmp)
add_importlibs(ntfsng ntoskrnl hal)
add_cd_file(TARGET ntfsng DESTINATION reactos/system32/drivers NO_CAB FOR all)
add_subdirectory(tools/ngchk)
add_subdirectory(tools/ngstress)
add_subdirectory(tools/ngfeat)
add_subdirectory(tools/ngbench)
add_subdirectory(tools/ngfail)
add_subdirectory(tools/ngedge)
add_subdirectory(tools/ngvol)
add_subdirectory(tools/ngfull)
add_subdirectory(tools/ngrefill)
