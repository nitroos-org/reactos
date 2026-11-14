
list(APPEND SOURCE
    CreateSwapChainForComposition.c
    EnumWarpAdapter.c
    D3D11StencilRefOption.c
    SharedResource.c
    testlist.c)

add_executable(dxgi_apitest ${SOURCE})
target_link_libraries(dxgi_apitest wine uuid dxguid dx10guid)
set_module_type(dxgi_apitest win32cui)
add_importlibs(dxgi_apitest d3d11 dxgi ole32 user32 msvcrt kernel32 ntdll)
add_dependencies(dxgi_apitest d3d_idl_headers)
add_rostests_file(TARGET dxgi_apitest)
