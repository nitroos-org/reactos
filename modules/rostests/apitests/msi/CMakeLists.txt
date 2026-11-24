spec2def(msi_cadir.dll msi_cadir.spec)
add_library(msi_cadir MODULE msi_cadir.c ${CMAKE_CURRENT_BINARY_DIR}/msi_cadir.def)
set_module_type(msi_cadir win32dll)
add_importlibs(msi_cadir msi advapi32 msvcrt kernel32)
add_rostests_file(TARGET msi_cadir)

# The client side of the installation's RPC interface, for the test that calls it from a process that is not a custom action server
add_rpc_files(client ${REACTOS_SOURCE_DIR}/dll/win32/msi/winemsi.idl)

add_executable(msi_apitest CustomActionDir.c LaunchPipe.c MsiPasswordEdit.c NoImpersonateAction.c RefusedPackageLog.c RemoteRefusal.c RemoveUnknownProduct.c Wow64Folders.c
               ${CMAKE_CURRENT_BINARY_DIR}/winemsi_c.c testlist.c)
set_module_type(msi_apitest win32cui)
target_link_libraries(msi_apitest ${PSEH_LIB})
add_importlibs(msi_apitest msi advapi32 user32 rpcrt4 msvcrt kernel32)
add_rostests_file(TARGET msi_apitest)
