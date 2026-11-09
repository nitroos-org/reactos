/* Do not edit - Machine generated */
#ifndef _INC_REACTOS_BUILDNO
#define _INC_REACTOS_BUILDNO

#define KERNEL_VERSION_BUILD        @KERNEL_VERSION_BUILD@
#define KERNEL_VERSION_BUILD_STR    "@KERNEL_VERSION_BUILD@-@REVISION@"
#define KERNEL_VERSION_BUILD_RC     "@KERNEL_VERSION_BUILD@-@REVISION@\0"

#define KERNEL_VERSION_RC           "@KERNEL_VERSION@\0"
#define KERNEL_VERSION_STR          "@KERNEL_VERSION@"

#define KERNEL_VERSION_REVISION_RC  "@REVISION@\0"
#define KERNEL_VERSION_REVISION_STR "@REVISION@"

#define KERNEL_VERSION_COMMIT_HASH  "@COMMIT_HASH@"

#define NITRO_TITLE_STR             "@NITRO_TITLE@"
#define NITRO_UPSTREAM_SHA_STR      "@NITRO_UPSTREAM_SHA@"
#define NITRO_NOTICE_STR            "@NITRO_NOTICE@"
#define NITRO_VERSION_STR           "@NITRO_VERSION@"
#define NITRO_IS_RELEASE            @NITRO_IS_RELEASE@
#define NITRO_RELEASE_URL_STR       "@NITRO_RELEASE_URL@"

#define REACTOS_DLL_VERSION_MAJOR   @REACTOS_DLL_VERSION_MAJOR@
#define REACTOS_DLL_VERSION_RC      "@DLL_VERSION_STR@\0"
#define REACTOS_DLL_VERSION_STR     "@DLL_VERSION_STR@"

/* Product name and version shown to users (NitroOS, based on ReactOS) */
#define BRAND_PRODUCT_NAME          "@NITRO_NAME@"
/* The OS identity text for the display surfaces that show a Windows-style caption (WMI Win32_OperatingSystem.Caption,
 * systeminfo "OS Name", cmd ver, dxdiag). "Windows 10" stays inside so scripts that match it keep working.
 * The version NUMBERS and the registry ProductName are NOT derived from this: they stay Windows 10. */
#define BRAND_OS_CAPTION            BRAND_PRODUCT_NAME " (Windows 10 compatible) Pro"
#define BRAND_WIDEN_(s)             L##s
#define BRAND_WIDEN(s)              BRAND_WIDEN_(s)
#define BRAND_PRODUCT_NAME_W        BRAND_WIDEN(BRAND_PRODUCT_NAME)
#define BRAND_OS_CAPTION_W          BRAND_WIDEN(BRAND_OS_CAPTION)
#define BRAND_VERSION_MAIN_STR      "@BRAND_VERSION_MAIN@"
#define BRAND_VERSION_DETAIL_STR    "@BRAND_VERSION_DETAIL@"
#define BRAND_VERSION_STR           "@BRAND_VERSION@"
#define BRAND_VERSION_FULL_STR      "@NITRO_TITLE@"
#define BRAND_VERSION_FULL_RC       "@NITRO_TITLE@\0"
#define BRAND_NOTICE_STR            "@NITRO_NOTICE@"
#define BRAND_BASED_ON_VERSION_RC   "Based on ReactOS @KERNEL_VERSION_MAJOR@.@KERNEL_VERSION_MINOR@.@KERNEL_VERSION_PATCH_LEVEL@\0"

#define REACTOS_COMPILER_NAME       "@CMAKE_C_COMPILER_ID@"
#define REACTOS_COMPILER_VERSION    "@CMAKE_C_COMPILER_VERSION@"

#endif
/* EOF */
