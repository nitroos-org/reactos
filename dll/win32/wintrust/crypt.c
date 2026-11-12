/*
 * WinTrust Cryptography functions
 *
 * Copyright 2006 James Hawkins
 * Copyright 2000-2002 Stuart Caie
 * Copyright 2002 Patrik Stridvall
 * Copyright 2003 Greg Turner
 * Copyright 2008 Juan Lang
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "windef.h"
#include "winbase.h"
#include "wintrust.h"
#include "winver.h"
#include "mscat.h"
#include "mssip.h"
#include "imagehlp.h"
#include "winternl.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wintrust);

#define CATADMIN_MAGIC 0x43415441 /* 'CATA' */
#define CATINFO_MAGIC  0x43415449 /* 'CATI' */

struct catadmin
{
    DWORD magic;
    WCHAR path[MAX_PATH];
    HANDLE find;
    ALG_ID alg;
    const WCHAR *providerName;
    DWORD providerType;
};

struct catinfo
{
    DWORD magic;
    WCHAR file[MAX_PATH];
};

static HCATINFO create_catinfo(const WCHAR *filename)
{
    struct catinfo *ci;

    if (!(ci = malloc(sizeof(*ci))))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return INVALID_HANDLE_VALUE;
    }
    lstrcpyW(ci->file, filename);
    ci->magic = CATINFO_MAGIC;
    return ci;
}

/***********************************************************************
 *      CryptCATAdminAcquireContext (WINTRUST.@)
 *
 * Get a catalog administrator context handle.
 *
 * PARAMS
 *   catAdmin  [O] Pointer to the context handle.
 *   sys       [I] Pointer to a GUID for the needed subsystem.
 *   dwFlags   [I] Reserved.
 *
 * RETURNS
 *   Success: TRUE. catAdmin contains the context handle.
 *   Failure: FALSE.
 *
 */
BOOL WINAPI CryptCATAdminAcquireContext(HCATADMIN *catAdmin,
                                        const GUID *sys, DWORD dwFlags)
{
    TRACE("%p %s %lx\n", catAdmin, debugstr_guid(sys), dwFlags);
    return CryptCATAdminAcquireContext2(catAdmin, sys, NULL, NULL, dwFlags);
}

/***********************************************************************
 *             CryptCATAdminAcquireContext2 (WINTRUST.@)
 * Get a catalog administrator context handle.
 *
 * PARAMS
 *   catAdmin  [O] Pointer to the context handle.
 *   sys       [I] Pointer to a GUID for the needed subsystem.
 *   algorithm [I] String of hashing algorithm to use for catalog (SHA1/SHA256).
 *   policy    [I] Pointer to policy structure for checking strong signatures.
 *   dwFlags   [I] Reserved.
 *
 * RETURNS
 *   Success: TRUE. catAdmin contains the context handle.
 *   Failure: FALSE.
 *
 */
BOOL WINAPI CryptCATAdminAcquireContext2(HCATADMIN *catAdmin, const GUID *sys, const WCHAR *algorithm,
                                         const CERT_STRONG_SIGN_PARA *policy, DWORD dwFlags)
{
    static const WCHAR catroot[] =
        {'\\','c','a','t','r','o','o','t',0};
    static const WCHAR fmt[] =
        {'%','s','\\','{','%','0','8','x','-','%','0','4','x','-','%','0',
         '4','x','-','%','0','2','x','%','0','2','x','-','%','0','2','x',
         '%','0','2','x','%','0','2','x','%','0','2','x','%','0','2','x',
         '%','0','2','x','}',0};
    static const GUID defsys =
        {0x127d0a1d,0x4ef2,0x11d1,{0x86,0x08,0x00,0xc0,0x4f,0xc2,0x95,0xee}};

    WCHAR catroot_dir[MAX_PATH];
    struct catadmin *ca;
    ALG_ID alg;
    const WCHAR *providerName;
    DWORD providerType;

    TRACE("%p %s %s %p %lx\n", catAdmin, debugstr_guid(sys), debugstr_w(algorithm), policy, dwFlags);

    if (!catAdmin || dwFlags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (policy != NULL)
        FIXME("strong policy parameter is unimplemented\n");

    if (algorithm == NULL || wcscmp(algorithm, BCRYPT_SHA1_ALGORITHM) == 0)
    {
        alg = CALG_SHA1;
        providerName = MS_DEF_PROV_W;
        providerType = PROV_RSA_FULL;
    }
    else if (wcscmp(algorithm, BCRYPT_SHA256_ALGORITHM) == 0)
    {
        alg = CALG_SHA_256;
        providerName = MS_ENH_RSA_AES_PROV_W;
        providerType = PROV_RSA_AES;
    }
    else
    {
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }

    if (!(ca = malloc(sizeof(*ca))))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    ca->alg = alg;
    ca->providerName = providerName;
    ca->providerType = providerType;

    GetSystemDirectoryW(catroot_dir, MAX_PATH);
    lstrcatW(catroot_dir, catroot);

    /* create the directory if it doesn't exist */
    CreateDirectoryW(catroot_dir, NULL);

    if (!sys) sys = &defsys;
    swprintf(ca->path, ARRAY_SIZE(ca->path), fmt, catroot_dir, sys->Data1, sys->Data2,
             sys->Data3, sys->Data4[0], sys->Data4[1], sys->Data4[2],
             sys->Data4[3], sys->Data4[4], sys->Data4[5], sys->Data4[6],
             sys->Data4[7]);

    /* create the directory if it doesn't exist */
    CreateDirectoryW(ca->path, NULL);

    ca->magic = CATADMIN_MAGIC;
    ca->find = INVALID_HANDLE_VALUE;

    *catAdmin = ca;
    return TRUE;
}

/***********************************************************************
 *             CryptCATAdminAddCatalog (WINTRUST.@)
 */
HCATINFO WINAPI CryptCATAdminAddCatalog(HCATADMIN catAdmin, PWSTR catalogFile,
                                        PWSTR selectBaseName, DWORD flags)
{
    static const WCHAR slashW[] = {'\\',0};
    struct catadmin *ca = catAdmin;
    struct catinfo *ci;
    WCHAR *target;
    DWORD len;

    TRACE("%p %s %s %ld\n", catAdmin, debugstr_w(catalogFile),
          debugstr_w(selectBaseName), flags);

    if (!selectBaseName)
    {
        FIXME("NULL basename not handled\n");
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (!ca || ca->magic != CATADMIN_MAGIC || !catalogFile || flags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    len = lstrlenW(ca->path) + lstrlenW(selectBaseName) + 2;
    if (!(target = malloc(len * sizeof(WCHAR))))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    lstrcpyW(target, ca->path);
    lstrcatW(target, slashW);
    lstrcatW(target, selectBaseName);

    if (!CopyFileW(catalogFile, target, FALSE))
    {
        free(target);
        return NULL;
    }
    SetFileAttributesW(target, FILE_ATTRIBUTE_SYSTEM);

    if (!(ci = malloc(sizeof(*ci))))
    {
        free(target);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }
    ci->magic = CATINFO_MAGIC;
    lstrcpyW(ci->file, target);

    free(target);
    return ci;
}

static BOOL pe_image_hash( HANDLE file, HCRYPTHASH hash )
{
    UINT32 size, offset, file_size, sig_pos;
    HANDLE mapping;
    BYTE *view;
    IMAGE_NT_HEADERS *nt;
    BOOL ret = FALSE;

    if ((file_size = GetFileSize( file, NULL )) == INVALID_FILE_SIZE) return FALSE;

    if (!(mapping = CreateFileMappingW( file, NULL, PAGE_READONLY, 0, 0, NULL )))
        return FALSE;

    if (!(view = MapViewOfFile( mapping, FILE_MAP_READ, 0, 0, 0 )))
    {
        CloseHandle( mapping );
        return FALSE;
    }
    if (!(nt = ImageNtHeader( view ))) goto done;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt;

        /* offset from start of file to checksum */
        offset = (BYTE *)&nt64->OptionalHeader.CheckSum - view;

        /* area between checksum and security directory entry */
        size = FIELD_OFFSET( IMAGE_OPTIONAL_HEADER64, DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] ) -
               FIELD_OFFSET( IMAGE_OPTIONAL_HEADER64, Subsystem );

        if (nt64->OptionalHeader.NumberOfRvaAndSizes < IMAGE_FILE_SECURITY_DIRECTORY + 1) goto done;
        sig_pos = nt64->OptionalHeader.DataDirectory[IMAGE_FILE_SECURITY_DIRECTORY].VirtualAddress;
    }
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        const IMAGE_NT_HEADERS32 *nt32 = (const IMAGE_NT_HEADERS32 *)nt;

        /* offset from start of file to checksum */
        offset = (BYTE *)&nt32->OptionalHeader.CheckSum - view;

        /* area between checksum and security directory entry */
        size = FIELD_OFFSET( IMAGE_OPTIONAL_HEADER32, DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] ) -
               FIELD_OFFSET( IMAGE_OPTIONAL_HEADER32, Subsystem );

        if (nt32->OptionalHeader.NumberOfRvaAndSizes < IMAGE_FILE_SECURITY_DIRECTORY + 1) goto done;
        sig_pos = nt32->OptionalHeader.DataDirectory[IMAGE_FILE_SECURITY_DIRECTORY].VirtualAddress;
    }
    else goto done;

    if (!CryptHashData( hash, view, offset, 0 )) goto done;
    offset += sizeof(DWORD); /* skip checksum */
    if (!CryptHashData( hash, view + offset, size, 0 )) goto done;

    offset += size + sizeof(IMAGE_DATA_DIRECTORY); /* skip security entry */
    if (offset > file_size) goto done;
    if (sig_pos)
    {
        if (sig_pos < offset) goto done;
        if (sig_pos > file_size) goto done;
        size = sig_pos - offset; /* exclude signature */
    }
    else size = file_size - offset;

    if (!CryptHashData( hash, view + offset, size, 0 )) goto done;
    ret = TRUE;

    if (!sig_pos && (size = file_size % 8))
    {
        static const BYTE pad[7];
        ret = CryptHashData( hash, pad, 8 - size, 0 );
    }

done:
    UnmapViewOfFile( view );
    CloseHandle( mapping );
    return ret;
}

/* Digest of a file as used by the catalog functions: the image hash for a PE file, otherwise the hash of the
 * whole file. *len is the size of the digest buffer on input and the digest size on output. */
BOOL WINTRUST_CalcFileDigest(HANDLE file, ALG_ID alg, DWORD *len, BYTE *digest, BOOL *pe)
{
    const WCHAR *provider = MS_DEF_PROV_W;
    DWORD provider_type = PROV_RSA_FULL, size;
    HCRYPTPROV prov;
    HCRYPTHASH hash;
    BOOL ret, is_pe;
    BYTE *buffer;

    if (alg != CALG_SHA1 && alg != CALG_MD5)
    {
        provider = MS_ENH_RSA_AES_PROV_W;
        provider_type = PROV_RSA_AES;
    }

    if (!CryptAcquireContextW(&prov, NULL, provider, provider_type, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptCreateHash(prov, alg, 0, 0, &hash))
    {
        CryptReleaseContext(prov, 0);
        return FALSE;
    }

    if (!(is_pe = pe_image_hash(file, hash)))
    {
        /* hash again from scratch, the failed attempt may have fed some data */
        CryptDestroyHash(hash);
        if (!CryptCreateHash(prov, alg, 0, 0, &hash))
        {
            CryptReleaseContext(prov, 0);
            return FALSE;
        }
        if (!(buffer = malloc(4096)))
        {
            CryptDestroyHash(hash);
            CryptReleaseContext(prov, 0);
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        SetFilePointer(file, 0, NULL, FILE_BEGIN);
        while ((ret = ReadFile(file, buffer, 4096, &size, NULL)) && size)
        {
            if (!CryptHashData(hash, buffer, size, 0))
            {
                ret = FALSE;
                break;
            }
        }
        free(buffer);
        if (!ret)
        {
            CryptDestroyHash(hash);
            CryptReleaseContext(prov, 0);
            return FALSE;
        }
    }
    ret = CryptGetHashParam(hash, HP_HASHVAL, digest, len, 0);
    if (ret && pe) *pe = is_pe;
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    if (ret) SetLastError(ERROR_SUCCESS);
    return ret;
}

static BOOL catadmin_calc_hash_from_filehandle(HCATADMIN catAdmin, HANDLE hFile, DWORD *pcbHash,
                                               BYTE *pbHash, DWORD dwFlags)
{
    struct catadmin *ca = catAdmin;
    ALG_ID alg = CALG_SHA1;
    DWORD hashLength;

    if (!hFile || !pcbHash || dwFlags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (ca) alg = ca->alg;

    switch (alg)
    {
        case CALG_SHA1:
            hashLength = 20;
            break;
        case CALG_SHA_256:
            hashLength = 32;
            break;
        default:
            FIXME("unsupported algorithm %x\n", alg);
            return FALSE;
    }

    if (*pcbHash < hashLength)
    {
        *pcbHash = hashLength;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return TRUE;
    }

    *pcbHash = hashLength;
    if (!pbHash) return FALSE;
    return WINTRUST_CalcFileDigest(hFile, alg, pcbHash, pbHash, NULL);
}

/***********************************************************************
 *             CryptCATAdminCalcHashFromFileHandle (WINTRUST.@)
 */
BOOL WINAPI CryptCATAdminCalcHashFromFileHandle(HANDLE hFile, DWORD *pcbHash, BYTE *pbHash, DWORD dwFlags)
{
    TRACE("%p %p %p %lx\n", hFile, pcbHash, pbHash, dwFlags);
    return catadmin_calc_hash_from_filehandle(NULL, hFile, pcbHash, pbHash, dwFlags);
}

/***********************************************************************
 *    CryptCATAdminCalcHashFromFileHandle2 (WINTRUST.@)
 *
 * Calculate hash for a specific file using a catalog administrator context.
 *
 * PARAMS
 *   catAdmin  [I] Catalog administrator context handle.
 *   hFile     [I] Handle for the file to hash.
 *   pcbHash   [I] Pointer to the length of the hash.
 *   pbHash    [O] Pointer to the buffer that will store that hash
 *   dwFlags   [I] Reserved.
 *
 * RETURNS
 *   Success: TRUE. If pcbHash is too small, LastError will be set to ERROR_INSUFFICIENT_BUFFER.
 *                  pbHash contains the computed hash, if supplied.
 *   Failure: FALSE.
 *
 */
BOOL WINAPI CryptCATAdminCalcHashFromFileHandle2(HCATADMIN catAdmin, HANDLE hFile,  DWORD *pcbHash,
                                                 BYTE *pbHash, DWORD dwFlags)
{
    TRACE("%p %p %p %p %lx\n", catAdmin, hFile, pcbHash, pbHash, dwFlags);

    if (!catAdmin || ((struct catadmin *)catAdmin)->magic != CATADMIN_MAGIC)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    return catadmin_calc_hash_from_filehandle(catAdmin, hFile, pcbHash, pbHash, dwFlags);
}


/***********************************************************************
 *             CryptCATAdminEnumCatalogFromHash (WINTRUST.@)
 */
HCATINFO WINAPI CryptCATAdminEnumCatalogFromHash(HCATADMIN hCatAdmin, BYTE* pbHash,
                                                 DWORD cbHash, DWORD dwFlags,
                                                 HCATINFO* phPrevCatInfo )
{
    static const WCHAR slashW[] = {'\\',0};
    static const WCHAR globW[]  = {'\\','*','.','c','a','t',0};

    struct catadmin *ca = hCatAdmin;
    WIN32_FIND_DATAW data;
    HCATINFO prev = NULL;
    HCRYPTPROV prov;
    DWORD size;
    BOOL ret;

    TRACE("%p %p %ld %lx %p\n", hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo);

    if (!ca || ca->magic != CATADMIN_MAGIC || !pbHash || cbHash != 20 || dwFlags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (phPrevCatInfo) prev = *phPrevCatInfo;

    ret = CryptAcquireContextW(&prov, NULL, MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!ret) return NULL;

    if (!prev)
    {
        WCHAR *path;

        size = lstrlenW(ca->path) * sizeof(WCHAR) + sizeof(globW);
        if (!(path = malloc(size)))
        {
            CryptReleaseContext(prov, 0);
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }
        lstrcpyW(path, ca->path);
        lstrcatW(path, globW);

        FindClose(ca->find);
        ca->find = FindFirstFileW(path, &data);

        free(path);
        if (ca->find == INVALID_HANDLE_VALUE)
        {
            CryptReleaseContext(prov, 0);
            return NULL;
        }
    }
    else if (!FindNextFileW(ca->find, &data))
    {
        CryptCATAdminReleaseCatalogContext(hCatAdmin, prev, 0);
        CryptReleaseContext(prov, 0);
        return NULL;
    }

    while (1)
    {
        WCHAR *filename;
        CRYPTCATMEMBER *member = NULL;
        struct catinfo *ci;
        HANDLE hcat;

        size = (lstrlenW(ca->path) + lstrlenW(data.cFileName) + 2) * sizeof(WCHAR);
        if (!(filename = malloc(size)))
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }
        lstrcpyW(filename, ca->path);
        lstrcatW(filename, slashW);
        lstrcatW(filename, data.cFileName);

        hcat = CryptCATOpen(filename, CRYPTCAT_OPEN_EXISTING, prov, 0, 0);
        if (hcat == INVALID_HANDLE_VALUE)
        {
            WARN("couldn't open %s (%lu)\n", debugstr_w(filename), GetLastError());
            continue;
        }
        while ((member = CryptCATEnumerateMember(hcat, member)))
        {
            if (member->pIndirectData->Digest.cbData != cbHash)
            {
                WARN("amount of hash bytes differs: %lu/%lu\n", member->pIndirectData->Digest.cbData, cbHash);
                continue;
            }
            if (!memcmp(member->pIndirectData->Digest.pbData, pbHash, cbHash))
            {
                TRACE("file %s matches\n", debugstr_w(data.cFileName));

                CryptCATClose(hcat);
                CryptReleaseContext(prov, 0);
                if (!phPrevCatInfo)
                {
                    FindClose(ca->find);
                    ca->find = INVALID_HANDLE_VALUE;
                }
                ci = create_catinfo(filename);
                free(filename);
                return ci;
            }
        }
        CryptCATClose(hcat);
        free(filename);

        if (!FindNextFileW(ca->find, &data))
        {
            FindClose(ca->find);
            ca->find = INVALID_HANDLE_VALUE;
            CryptReleaseContext(prov, 0);
            return NULL;
        }
    }
    return NULL;
}

/***********************************************************************
 *      CryptCATAdminReleaseCatalogContext (WINTRUST.@)
 *
 * Release a catalog context handle.
 *
 * PARAMS
 *   hCatAdmin [I] Context handle.
 *   hCatInfo  [I] Catalog handle.
 *   dwFlags   [I] Reserved.
 *
 * RETURNS
 *   Success: TRUE.
 *   Failure: FALSE.
 *
 */
BOOL WINAPI CryptCATAdminReleaseCatalogContext(HCATADMIN hCatAdmin,
                                               HCATINFO hCatInfo,
                                               DWORD dwFlags)
{
    struct catinfo *ci = hCatInfo;
    struct catadmin *ca = hCatAdmin;

    TRACE("%p %p %lx\n", hCatAdmin, hCatInfo, dwFlags);

    if (!ca || ca->magic != CATADMIN_MAGIC || !ci || ci->magic != CATINFO_MAGIC)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* Ensure compiler doesn't optimize out the assignment with 0. */
    SecureZeroMemory(&ci->magic, sizeof(ci->magic));
    free(ci);
    return TRUE;
}

/***********************************************************************
 *      CryptCATAdminReleaseContext (WINTRUST.@)
 *
 * Release a catalog administrator context handle.
 *
 * PARAMS
 *   catAdmin  [I] Context handle.
 *   dwFlags   [I] Reserved.
 *
 * RETURNS
 *   Success: TRUE.
 *   Failure: FALSE.
 *
 */
BOOL WINAPI CryptCATAdminReleaseContext(HCATADMIN hCatAdmin, DWORD dwFlags )
{
    struct catadmin *ca = hCatAdmin;

    TRACE("%p %lx\n", hCatAdmin, dwFlags);

    if (!ca || ca->magic != CATADMIN_MAGIC)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (ca->find != INVALID_HANDLE_VALUE) FindClose(ca->find);
    /* Ensure compiler doesn't optimize out the assignment with 0. */
    SecureZeroMemory(&ca->magic, sizeof(ca->magic));
    free(ca);
    return TRUE;
}

/***********************************************************************
 *      CryptCATAdminRemoveCatalog (WINTRUST.@)
 *
 * Remove a catalog file.
 *
 * PARAMS
 *   catAdmin         [I] Context handle.
 *   pwszCatalogFile  [I] Catalog file.
 *   dwFlags          [I] Reserved.
 *
 * RETURNS
 *   Success: TRUE.
 *   Failure: FALSE.
 *
 */
BOOL WINAPI CryptCATAdminRemoveCatalog(HCATADMIN hCatAdmin, LPCWSTR pwszCatalogFile, DWORD dwFlags)
{
    struct catadmin *ca = hCatAdmin;

    TRACE("%p %s %lx\n", hCatAdmin, debugstr_w(pwszCatalogFile), dwFlags);

    if (!ca || ca->magic != CATADMIN_MAGIC)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Only delete when there is a filename and no path */
    if (pwszCatalogFile && pwszCatalogFile[0] != 0 &&
        !wcschr(pwszCatalogFile, '\\') && !wcschr(pwszCatalogFile, '/') &&
        !wcschr(pwszCatalogFile, ':'))
    {
        static const WCHAR slashW[] = {'\\',0};
        WCHAR *target;
        DWORD len;

        len = lstrlenW(ca->path) + lstrlenW(pwszCatalogFile) + 2;
        if (!(target = malloc(len * sizeof(WCHAR))))
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        lstrcpyW(target, ca->path);
        lstrcatW(target, slashW);
        lstrcatW(target, pwszCatalogFile);

        DeleteFileW(target);

        free(target);
    }

    return TRUE;
}

/***********************************************************************
 *      CryptCATAdminResolveCatalogPath  (WINTRUST.@)
 */
BOOL WINAPI CryptCATAdminResolveCatalogPath(HCATADMIN hcatadmin, WCHAR *catalog_file,
                                            CATALOG_INFO *info, DWORD flags)
{
    static const WCHAR slashW[] = {'\\',0};
    struct catadmin *ca = hcatadmin;

    TRACE("%p %s %p %lx\n", hcatadmin, debugstr_w(catalog_file), info, flags);

    if (!ca || ca->magic != CATADMIN_MAGIC || !info || info->cbStruct != sizeof(*info) || flags)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    lstrcpyW(info->wszCatalogFile, ca->path);
    lstrcatW(info->wszCatalogFile, slashW);
    lstrcatW(info->wszCatalogFile, catalog_file);

    return TRUE;
}

/***********************************************************************
 *      CryptCATCatalogInfoFromContext  (WINTRUST.@)
 */
BOOL WINAPI CryptCATCatalogInfoFromContext(HCATINFO hcatinfo, CATALOG_INFO *info, DWORD flags)
{
    struct catinfo *ci = hcatinfo;

    TRACE("%p, %p, %lx\n", hcatinfo, info, flags);

    if (!hcatinfo || hcatinfo == INVALID_HANDLE_VALUE || ci->magic != CATINFO_MAGIC ||
        flags || !info || info->cbStruct != sizeof(*info))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    lstrcpyW(info->wszCatalogFile, ci->file);
    return TRUE;
}

static BOOL WINTRUST_GetSignedMsgFromPEFile(SIP_SUBJECTINFO *pSubjectInfo,
 DWORD *pdwEncodingType, DWORD dwIndex, DWORD *pcbSignedDataMsg,
 BYTE *pbSignedDataMsg)
{
    BOOL ret;
    WIN_CERTIFICATE *pCert = NULL;
    HANDLE file;

    TRACE("(%p %p %ld %p %p)\n", pSubjectInfo, pdwEncodingType, dwIndex,
          pcbSignedDataMsg, pbSignedDataMsg);

    if(pSubjectInfo->hFile && pSubjectInfo->hFile!=INVALID_HANDLE_VALUE)
        file = pSubjectInfo->hFile;
    else
    {
        file = CreateFileW(pSubjectInfo->pwsFileName, GENERIC_READ,
                FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if(file == INVALID_HANDLE_VALUE)
            return FALSE;
    }
 
    if (!pbSignedDataMsg)
    {
        WIN_CERTIFICATE cert;

        /* app hasn't passed buffer, just get the length */
        ret = ImageGetCertificateHeader(file, dwIndex, &cert);
        if (ret)
        {
            switch (cert.wCertificateType)
            {
            case WIN_CERT_TYPE_X509:
            case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
                *pcbSignedDataMsg = cert.dwLength;
                break;
            default:
                WARN("unknown certificate type %d\n", cert.wCertificateType);
                ret = FALSE;
            }
        }
    }
    else
    {
        DWORD len = 0;

        ret = ImageGetCertificateData(file, dwIndex, NULL, &len);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto error;
        pCert = malloc(len);
        if (!pCert)
        {
            ret = FALSE;
            goto error;
        }
        ret = ImageGetCertificateData(file, dwIndex, pCert, &len);
        if (!ret)
            goto error;
        pCert->dwLength -= FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
        if (*pcbSignedDataMsg < pCert->dwLength)
        {
            *pcbSignedDataMsg = pCert->dwLength;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            ret = FALSE;
        }
        else
        {
            memcpy(pbSignedDataMsg, pCert->bCertificate, pCert->dwLength);
            *pcbSignedDataMsg = pCert->dwLength;
            switch (pCert->wCertificateType)
            {
            case WIN_CERT_TYPE_X509:
                *pdwEncodingType = X509_ASN_ENCODING;
                break;
            case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
                *pdwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
                break;
            default:
                WARN("don't know what to do for encoding type %d\n",
                 pCert->wCertificateType);
                *pdwEncodingType = 0;
                ret = FALSE;
            }
        }
    }
error:
    if(pSubjectInfo->hFile != file)
        CloseHandle(file);
    free(pCert);
    return ret;
}

static BOOL WINTRUST_PutSignedMsgToPEFile(SIP_SUBJECTINFO* pSubjectInfo, DWORD pdwEncodingType,
        DWORD* pdwIndex, DWORD cbSignedDataMsg, BYTE* pbSignedDataMsg)
{
    WIN_CERTIFICATE *cert;
    HANDLE file;
    DWORD size;
    BOOL ret;

    if(pSubjectInfo->hFile && pSubjectInfo->hFile!=INVALID_HANDLE_VALUE)
        file = pSubjectInfo->hFile;
    else
    {
        file = CreateFileW(pSubjectInfo->pwsFileName, GENERIC_READ|GENERIC_WRITE,
                FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if(file == INVALID_HANDLE_VALUE)
            return FALSE;
    }

    /* int aligned WIN_CERTIFICATE structure with cbSignedDataMsg+1 bytes of data */
    size = FIELD_OFFSET(WIN_CERTIFICATE, bCertificate[cbSignedDataMsg+4]) & (~3);
    cert = calloc(1, size);
    if(!cert)
        return FALSE;

    cert->dwLength = size;
    cert->wRevision = WIN_CERT_REVISION_2_0;
    cert->wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
    memcpy(cert->bCertificate, pbSignedDataMsg, cbSignedDataMsg);
    ret = ImageAddCertificate(file, cert, pdwIndex);

    free(cert);
    if(file != pSubjectInfo->hFile)
        CloseHandle(file);
    return ret;
}

/* structure offsets */
#define cfhead_Signature         (0x00)
#define cfhead_CabinetSize       (0x08)
#define cfhead_MinorVersion      (0x18)
#define cfhead_MajorVersion      (0x19)
#define cfhead_Flags             (0x1E)
#define cfhead_SIZEOF            (0x24)
#define cfheadext_HeaderReserved (0x00)
#define cfheadext_SIZEOF         (0x04)
#define cfsigninfo_CertOffset    (0x04)
#define cfsigninfo_CertSize      (0x08)
#define cfsigninfo_SIZEOF        (0x0C)

/* flags */
#define cfheadRESERVE_PRESENT          (0x0004)

/* endian-neutral reading of little-endian data */
#define EndGetI32(a)  ((((a)[3])<<24)|(((a)[2])<<16)|(((a)[1])<<8)|((a)[0]))
#define EndGetI16(a)  ((((a)[1])<<8)|((a)[0]))

/* For documentation purposes only:  this is the structure in the reserved
 * area of a signed cabinet file.  The cert offset indicates where in the
 * cabinet file the signature resides, and the count indicates its size.
 */
typedef struct _CAB_SIGNINFO
{
    WORD unk0; /* always 0? */
    WORD unk1; /* always 0x0010? */
    DWORD dwCertOffset;
    DWORD cbCertBlock;
} CAB_SIGNINFO, *PCAB_SIGNINFO;

static BOOL WINTRUST_GetSignedMsgFromCabFile(SIP_SUBJECTINFO *pSubjectInfo,
 DWORD *pdwEncodingType, DWORD dwIndex, DWORD *pcbSignedDataMsg,
 BYTE *pbSignedDataMsg)
{
    int header_resv;
    LONG base_offset, cabsize;
    USHORT flags;
    BYTE buf[64];
    DWORD cert_offset, cert_size, dwRead;

    TRACE("(%p %p %ld %p %p)\n", pSubjectInfo, pdwEncodingType, dwIndex,
          pcbSignedDataMsg, pbSignedDataMsg);

    /* get basic offset & size info */
    base_offset = SetFilePointer(pSubjectInfo->hFile, 0L, NULL, SEEK_CUR);

    if (SetFilePointer(pSubjectInfo->hFile, 0, NULL, SEEK_END) == INVALID_SET_FILE_POINTER)
    {
        TRACE("seek error\n");
        return FALSE;
    }

    cabsize = SetFilePointer(pSubjectInfo->hFile, 0L, NULL, SEEK_CUR);
    if ((cabsize == -1) || (base_offset == -1) ||
     (SetFilePointer(pSubjectInfo->hFile, 0, NULL, SEEK_SET) == INVALID_SET_FILE_POINTER))
    {
        TRACE("seek error\n");
        return FALSE;
    }

    /* read in the CFHEADER */
    if (!ReadFile(pSubjectInfo->hFile, buf, cfhead_SIZEOF, &dwRead, NULL) ||
     dwRead != cfhead_SIZEOF)
    {
        TRACE("reading header failed\n");
        return FALSE;
    }

    /* check basic MSCF signature */
    if (EndGetI32(buf+cfhead_Signature) != 0x4643534d)
    {
        WARN("cabinet signature not present\n");
        return FALSE;
    }

    /* Ignore the number of folders and files and the set and cabinet IDs */

    /* check the header revision */
    if ((buf[cfhead_MajorVersion] > 1) ||
        (buf[cfhead_MajorVersion] == 1 && buf[cfhead_MinorVersion] > 3))
    {
        WARN("cabinet format version > 1.3\n");
        return FALSE;
    }

    /* pull the flags out */
    flags = EndGetI16(buf+cfhead_Flags);

    if (!(flags & cfheadRESERVE_PRESENT))
    {
        TRACE("no header present, not signed\n");
        return FALSE;
    }

    if (!ReadFile(pSubjectInfo->hFile, buf, cfheadext_SIZEOF, &dwRead, NULL) ||
     dwRead != cfheadext_SIZEOF)
    {
        ERR("bunk reserve-sizes?\n");
        return FALSE;
    }

    header_resv = EndGetI16(buf+cfheadext_HeaderReserved);
    if (!header_resv)
    {
        TRACE("no header_resv, not signed\n");
        return FALSE;
    }
    else if (header_resv < cfsigninfo_SIZEOF)
    {
        TRACE("header_resv too small, not signed\n");
        return FALSE;
    }

    if (header_resv > 60000)
    {
        WARN("WARNING; header reserved space > 60000\n");
    }

    if (!ReadFile(pSubjectInfo->hFile, buf, cfsigninfo_SIZEOF, &dwRead, NULL) ||
     dwRead != cfsigninfo_SIZEOF)
    {
        ERR("couldn't read reserve\n");
        return FALSE;
    }

    cert_offset = EndGetI32(buf+cfsigninfo_CertOffset);
    TRACE("cert_offset: %ld\n", cert_offset);
    cert_size = EndGetI32(buf+cfsigninfo_CertSize);
    TRACE("cert_size: %ld\n", cert_size);

    /* The redundant checks are to avoid wraparound */
    if (cert_offset > cabsize || cert_size > cabsize ||
     cert_offset + cert_size > cabsize)
    {
        WARN("offset beyond file, not attempting to read\n");
        return FALSE;
    }

    SetFilePointer(pSubjectInfo->hFile, base_offset, NULL, SEEK_SET);
    if (!pbSignedDataMsg)
    {
        *pcbSignedDataMsg = cert_size;
        return TRUE;
    }
    if (*pcbSignedDataMsg < cert_size)
    {
        *pcbSignedDataMsg = cert_size;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    if (SetFilePointer(pSubjectInfo->hFile, cert_offset, NULL, SEEK_SET) == INVALID_SET_FILE_POINTER)
    {
        ERR("couldn't seek to cert location\n");
        return FALSE;
    }
    if (!ReadFile(pSubjectInfo->hFile, pbSignedDataMsg, cert_size, &dwRead,
     NULL) || dwRead != cert_size)
    {
        ERR("couldn't read cert\n");
        SetFilePointer(pSubjectInfo->hFile, base_offset, NULL, SEEK_SET);
        return FALSE;
    }
    /* The encoding of the files I've seen appears to be in ASN.1
     * format, and there isn't a field indicating the type, so assume it
     * always is.
     */
    *pdwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    /* Restore base offset */
    SetFilePointer(pSubjectInfo->hFile, base_offset, NULL, SEEK_SET);
    return TRUE;
}

static BOOL WINTRUST_GetSignedMsgFromCatFile(SIP_SUBJECTINFO *pSubjectInfo,
 DWORD *pdwEncodingType, DWORD dwIndex, DWORD *pcbSignedDataMsg,
 BYTE *pbSignedDataMsg)
{
    BOOL ret;

    TRACE("(%p %p %ld %p %p)\n", pSubjectInfo, pdwEncodingType, dwIndex,
          pcbSignedDataMsg, pbSignedDataMsg);

    if (!pbSignedDataMsg)
    {
        *pcbSignedDataMsg = GetFileSize(pSubjectInfo->hFile, NULL);
         ret = TRUE;
    }
    else
    {
        DWORD len = GetFileSize(pSubjectInfo->hFile, NULL);

        if (*pcbSignedDataMsg < len)
        {
            *pcbSignedDataMsg = len;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            ret = FALSE;
        }
        else
        {
            ret = ReadFile(pSubjectInfo->hFile, pbSignedDataMsg, len,
             pcbSignedDataMsg, NULL);
            if (ret)
                *pdwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        }
    }
    return ret;
}

/* GUIDs used by CryptSIPGetSignedDataMsg and CryptSIPPutSignedDataMsg */
static const GUID unknown = { 0xC689AAB8, 0x8E78, 0x11D0, { 0x8C,0x47,
    0x00,0xC0,0x4F,0xC2,0x95,0xEE } };
static const GUID cabGUID = { 0xC689AABA, 0x8E78, 0x11D0, { 0x8C,0x47,
    0x00,0xC0,0x4F,0xC2,0x95,0xEE } };
static const GUID catGUID = { 0xDE351A43, 0x8E59, 0x11D0, { 0x8C,0x47,
     0x00,0xC0,0x4F,0xC2,0x95,0xEE }};

/***********************************************************************
 *      CryptSIPGetSignedDataMsg  (WINTRUST.@)
 */
BOOL WINAPI CryptSIPGetSignedDataMsg(SIP_SUBJECTINFO* pSubjectInfo, DWORD* pdwEncodingType,
                                       DWORD dwIndex, DWORD* pcbSignedDataMsg, BYTE* pbSignedDataMsg)
{
    BOOL ret;

    TRACE("(%p %p %ld %p %p)\n", pSubjectInfo, pdwEncodingType, dwIndex,
          pcbSignedDataMsg, pbSignedDataMsg);

    if(!pSubjectInfo)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!memcmp(pSubjectInfo->pgSubjectType, &unknown, sizeof(unknown)))
        ret = WINTRUST_GetSignedMsgFromPEFile(pSubjectInfo, pdwEncodingType,
         dwIndex, pcbSignedDataMsg, pbSignedDataMsg);
    else if (!memcmp(pSubjectInfo->pgSubjectType, &cabGUID, sizeof(cabGUID)))
        ret = WINTRUST_GetSignedMsgFromCabFile(pSubjectInfo, pdwEncodingType,
         dwIndex, pcbSignedDataMsg, pbSignedDataMsg);
    else if (!memcmp(pSubjectInfo->pgSubjectType, &catGUID, sizeof(catGUID)))
        ret = WINTRUST_GetSignedMsgFromCatFile(pSubjectInfo, pdwEncodingType,
         dwIndex, pcbSignedDataMsg, pbSignedDataMsg);
    else
    {
        FIXME("unimplemented for subject type %s\n",
         debugstr_guid(pSubjectInfo->pgSubjectType));
        ret = FALSE;
    }

    TRACE("returning %d\n", ret);
    return ret;
}

/***********************************************************************
 *      CryptSIPPutSignedDataMsg  (WINTRUST.@)
 */
BOOL WINAPI CryptSIPPutSignedDataMsg(SIP_SUBJECTINFO* pSubjectInfo, DWORD pdwEncodingType,
        DWORD* pdwIndex, DWORD cbSignedDataMsg, BYTE* pbSignedDataMsg)
{
    TRACE("(%p %ld %p %ld %p)\n", pSubjectInfo, pdwEncodingType, pdwIndex,
          cbSignedDataMsg, pbSignedDataMsg);

    if(!pSubjectInfo) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if(!memcmp(pSubjectInfo->pgSubjectType, &unknown, sizeof(unknown)))
        return WINTRUST_PutSignedMsgToPEFile(pSubjectInfo, pdwEncodingType,
                pdwIndex, cbSignedDataMsg, pbSignedDataMsg);
    else
        FIXME("unimplemented for subject type %s\n",
                debugstr_guid(pSubjectInfo->pgSubjectType));

    return FALSE;
}


/* The page hash attributes of an Authenticode signature
 * (Windows Authenticode Portable Executable Signature Format) */
#define SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID "1.3.6.1.4.1.311.2.3.1"
#define SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID "1.3.6.1.4.1.311.2.3.2"
#define PE_PAGE_SIZE 4096

static const BYTE page_hash_class_id[16] = { 0xa6,0xb5,0x86,0xd5,0xb4,0xa1,0x24,0x66,
                                             0xae,0x05,0xa2,0x17,0xda,0x8e,0x60,0xd6 };

static int pe_section_cmp(const void *a, const void *b)
{
    const IMAGE_SECTION_HEADER *x = *(IMAGE_SECTION_HEADER * const *)a, *y = *(IMAGE_SECTION_HEADER * const *)b;
    return x->PointerToRawData < y->PointerToRawData ? -1 : x->PointerToRawData > y->PointerToRawData;
}

static BOOL hash_data_buf(HCRYPTHASH hash, const BYTE *data, DWORD len, DWORD pad)
{
    static const BYTE zero[PE_PAGE_SIZE];
    return (!len || CryptHashData(hash, data, len, 0)) && (!pad || CryptHashData(hash, zero, pad, 0));
}

/* Table of (file offset, digest of the page) of a PE file, one entry per 4096 bytes of the headers and of each
 * section's raw data, closed by an entry that holds the end offset and a zero digest. */
static BOOL pe_page_hash_table(HANDLE file, ALG_ID alg, BYTE **table, DWORD *table_len)
{
    HCRYPTPROV prov;
    HCRYPTHASH hash;
    HANDLE mapping;
    BYTE *view = NULL, *out = NULL;
    const IMAGE_NT_HEADERS32 *nt;
    IMAGE_SECTION_HEADER **sorted = NULL;
    DWORD file_size, hdr_size, hash_len, hlen_size = sizeof(DWORD), entry, count = 0, cap, i, off, len;
    DWORD checksum_off, secdir_off, sig_start;
    BOOL ret = FALSE;
    IMAGE_SECTION_HEADER *sec;
    WORD nsec;

    if ((file_size = GetFileSize(file, NULL)) == INVALID_FILE_SIZE) return FALSE;
    if (!(mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL))) return FALSE;
    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(mapping);
    if (!view) return FALSE;
    if (!CryptAcquireContextW(&prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        UnmapViewOfFile(view);
        return FALSE;
    }
    if (!CryptCreateHash(prov, alg, 0, 0, &hash))
    {
        CryptReleaseContext(prov, 0);
        UnmapViewOfFile(view);
        return FALSE;
    }
    if (!CryptGetHashParam(hash, HP_HASHSIZE, (BYTE *)&hash_len, &hlen_size, 0)) goto done;
    if (!(nt = (const IMAGE_NT_HEADERS32 *)ImageNtHeader(view))) goto done;
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        hdr_size = nt->OptionalHeader.SizeOfHeaders;
        checksum_off = (const BYTE *)&nt->OptionalHeader.CheckSum - view;
        secdir_off = (const BYTE *)&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] - view;
        sig_start = nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY ?
                    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress : 0;
    }
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        const IMAGE_NT_HEADERS64 *nt64 = (const IMAGE_NT_HEADERS64 *)nt;
        hdr_size = nt64->OptionalHeader.SizeOfHeaders;
        checksum_off = (const BYTE *)&nt64->OptionalHeader.CheckSum - view;
        secdir_off = (const BYTE *)&nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] - view;
        sig_start = nt64->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY ?
                    nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress : 0;
    }
    else goto done;
    if (!sig_start || sig_start > file_size) sig_start = file_size;
    if (hdr_size > sig_start || secdir_off + sizeof(IMAGE_DATA_DIRECTORY) > hdr_size) goto done;

    nsec = nt->FileHeader.NumberOfSections;
    sec = IMAGE_FIRST_SECTION(nt);
    if ((BYTE *)(sec + nsec) > view + file_size) goto done;
    entry = 4 + hash_len;
    cap = (hdr_size / PE_PAGE_SIZE + 2) * entry;
    for (i = 0; i < nsec; i++) cap += (sec[i].SizeOfRawData / PE_PAGE_SIZE + 1) * entry;
    cap += entry;
    out = calloc(1, cap);
    sorted = calloc(nsec ? nsec : 1, sizeof(*sorted));
    if (!out || !sorted) goto done;
    for (i = 0; i < nsec; i++) sorted[i] = &sec[i];
    qsort(sorted, nsec, sizeof(*sorted), pe_section_cmp);

    /* the headers, without the checksum and the certificate table entry, padded to a page */
    for (off = 0; off < hdr_size; off += PE_PAGE_SIZE)
    {
        DWORD end = min(off + PE_PAGE_SIZE, hdr_size), pos = off;
        BYTE *e = out + count * entry;

        if (!CryptCreateHash(prov, alg, 0, 0, &hash)) goto done;
        ret = TRUE;
        while (ret && pos < end)
        {
            DWORD stop = end;
            if (pos == checksum_off) { pos += 4; continue; }
            if (pos == secdir_off) { pos += sizeof(IMAGE_DATA_DIRECTORY); continue; }
            if (pos < checksum_off && checksum_off < stop) stop = checksum_off;
            if (pos < secdir_off && secdir_off < stop) stop = secdir_off;
            ret = CryptHashData(hash, view + pos, stop - pos, 0);
            pos = stop;
        }
        if (ret && end - off < PE_PAGE_SIZE) ret = hash_data_buf(hash, NULL, 0, PE_PAGE_SIZE - (end - off));
        if (ret)
        {
            *(DWORD *)e = off;
            len = hash_len;
            ret = CryptGetHashParam(hash, HP_HASHVAL, e + 4, &len, 0);
        }
        CryptDestroyHash(hash);
        hash = 0;
        if (!ret) goto done;
        count++;
    }
    ret = FALSE;
    for (i = 0; i < nsec; i++)
    {
        DWORD start = sorted[i]->PointerToRawData, size = sorted[i]->SizeOfRawData, done_len;

        if (!size) continue;
        if (start > file_size || size > file_size - start || start + size > sig_start) goto done;
        for (done_len = 0; done_len < size; done_len += PE_PAGE_SIZE)
        {
            BYTE *e = out + count * entry;
            DWORD chunk = min(PE_PAGE_SIZE, size - done_len);

            if (!CryptCreateHash(prov, alg, 0, 0, &hash)) goto done;
            ret = hash_data_buf(hash, view + start + done_len, chunk, PE_PAGE_SIZE - chunk);
            if (ret)
            {
                *(DWORD *)e = start + done_len;
                len = hash_len;
                ret = CryptGetHashParam(hash, HP_HASHVAL, e + 4, &len, 0);
            }
            CryptDestroyHash(hash);
            hash = 0;
            if (!ret) goto done;
            count++;
        }
        ret = FALSE;
    }
    /* the closing entry: the end of the hashed data and an empty digest */
    *(DWORD *)(out + count * entry) = nsec ? max(hdr_size, sorted[nsec - 1]->PointerToRawData +
                                                 sorted[nsec - 1]->SizeOfRawData) : hdr_size;
    count++;
    *table = out;
    *table_len = count * entry;
    out = NULL;
    ret = TRUE;

done:
    if (hash) CryptDestroyHash(hash);
    free(out);
    free(sorted);
    CryptReleaseContext(prov, 0);
    UnmapViewOfFile(view);
    return ret;
}

/* DER of an OBJECT IDENTIFIER from its dotted string (crypt32 has no encoder for it) */
static BOOL der_oid(const char *oid, BYTE **out, DWORD *out_len)
{
    BYTE body[64], *p = body;
    DWORD arcs[16], n = 0, i;
    const char *s = oid;
    BYTE *ret;

    while (*s && n < ARRAY_SIZE(arcs))
    {
        char *end;
        arcs[n++] = strtoul(s, &end, 10);
        if (end == s) return FALSE;
        s = *end == '.' ? end + 1 : end;
        if (!*end) break;
    }
    if (n < 2 || arcs[0] > 2) return FALSE;
    arcs[1] += arcs[0] * 40;
    for (i = 1; i < n; i++)
    {
        DWORD v = arcs[i], shift = 28;

        if (p - body > 48) return FALSE;
        while (shift && !(v >> shift)) shift -= 7;
        for (; shift; shift -= 7) *p++ = 0x80 | ((v >> shift) & 0x7f);
        *p++ = v & 0x7f;
    }
    if (!(ret = malloc(2 + (p - body)))) return FALSE;
    ret[0] = 6;
    ret[1] = p - body;
    memcpy(ret + 2, body, p - body);
    *out = ret;
    *out_len = 2 + (p - body);
    return TRUE;
}

static BOOL der_len_encode(DWORD len, BYTE *out, DWORD *olen)
{
    if (len < 0x80) { out[0] = len; *olen = 1; }
    else if (len < 0x100) { out[0] = 0x81; out[1] = len; *olen = 2; }
    else if (len < 0x10000) { out[0] = 0x82; out[1] = len >> 8; out[2] = len; *olen = 3; }
    else { out[0] = 0x83; out[1] = len >> 16; out[2] = len >> 8; out[3] = len; *olen = 4; }
    return TRUE;
}

static BYTE *der_wrap(BYTE tag, const BYTE *a, DWORD alen, const BYTE *b, DWORD blen, DWORD *total)
{
    BYTE lenbuf[4], *ret;
    DWORD ll;

    der_len_encode(alen + blen, lenbuf, &ll);
    if (!(ret = malloc(1 + ll + alen + blen))) return NULL;
    ret[0] = tag;
    memcpy(ret + 1, lenbuf, ll);
    if (alen) memcpy(ret + 1 + ll, a, alen);
    if (blen) memcpy(ret + 1 + ll + alen, b, blen);
    *total = 1 + ll + alen + blen;
    return ret;
}

/* SET { SEQUENCE { OID, SET { OCTET STRING table } } }: the serialized data of the moniker that carries the page
 * hashes */
static BYTE *encode_page_hash_attr(const char *oid, const BYTE *table, DWORD table_len, DWORD *total)
{
    BYTE *octets = NULL, *set1 = NULL, *oidenc = NULL, *seq = NULL, *ret = NULL, *tmp = NULL;
    DWORD octets_len, set1_len, oid_len = 0, seq_len, tmp_len;

    if (!der_oid(oid, &oidenc, &oid_len)) return NULL;
    if (!(octets = der_wrap(0x04, table, table_len, NULL, 0, &octets_len))) goto done;
    if (!(set1 = der_wrap(0x31, octets, octets_len, NULL, 0, &set1_len))) goto done;
    if (!(seq = der_wrap(0x30, oidenc, oid_len, set1, set1_len, &seq_len))) goto done;
    if (!(tmp = der_wrap(0x31, seq, seq_len, NULL, 0, &tmp_len))) goto done;
    ret = tmp;
    *total = tmp_len;
done:
    free(oidenc);
    free(octets);
    free(set1);
    free(seq);
    return ret;
}

/* Layout of what CryptSIPCreateIndirectData returns: the structure, then the strings and blobs it points to */
static BOOL fill_indirect_data(const char *data_oid, const BYTE *data, DWORD data_len, const char *alg_oid,
                               const BYTE *digest, DWORD digest_len, DWORD *size, SIP_INDIRECT_DATA *out)
{
    DWORD need = sizeof(*out) + strlen(data_oid) + 1 + data_len + strlen(alg_oid) + 1 + digest_len;
    BYTE *p;

    if (!out)
    {
        *size = need;
        return TRUE;
    }
    if (*size < need)
    {
        *size = need;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memset(out, 0, sizeof(*out));
    p = (BYTE *)(out + 1);
    out->Data.pszObjId = (char *)p;
    strcpy((char *)p, data_oid);
    p += strlen(data_oid) + 1;
    out->Data.Value.cbData = data_len;
    out->Data.Value.pbData = p;
    memcpy(p, data, data_len);
    p += data_len;
    out->DigestAlgorithm.pszObjId = (char *)p;
    strcpy((char *)p, alg_oid);
    p += strlen(alg_oid) + 1;
    out->Digest.cbData = digest_len;
    out->Digest.pbData = p;
    memcpy(p, digest, digest_len);
    *size = need;
    return TRUE;
}

static HANDLE sip_open_subject(const SIP_SUBJECTINFO *info, DWORD access, BOOL *opened)
{
    *opened = FALSE;
    if (info->hFile && info->hFile != INVALID_HANDLE_VALUE) return info->hFile;
    if (!info->pwsFileName) return INVALID_HANDLE_VALUE;
    *opened = TRUE;
    return CreateFileW(info->pwsFileName, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}

static BOOL sip_pe_digest(const SIP_SUBJECTINFO *info, HANDLE file, ALG_ID *alg, BYTE *digest, DWORD *len)
{
    BOOL pe = FALSE;

    *alg = info->DigestAlgorithm.pszObjId ? CertOIDToAlgId(info->DigestAlgorithm.pszObjId) : CALG_SHA1;
    if (!*alg)
    {
        SetLastError(NTE_BAD_ALGID);
        return FALSE;
    }
    if (!WINTRUST_CalcFileDigest(file, *alg, len, digest, &pe)) return FALSE;
    if (!pe)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    return TRUE;
}

/***********************************************************************
 *      CryptSIPCreateIndirectData  (WINTRUST.@)
 *
 * Only the PE subject is handled: the data is an SpcPeImageData (the flags of the SPC_*_PE_* options and the
 * obsolete file link every signing tool writes, or the page hashes when SPC_INC_PE_PAGE_HASHES_FLAG is set) and the
 * digest is the Authenticode digest of the image.
 */
BOOL WINAPI CryptSIPCreateIndirectData(SIP_SUBJECTINFO *info, DWORD *size, SIP_INDIRECT_DATA *out)
{
    static WCHAR obsolete[] = L"<<<Obsolete>>>";
    BYTE digest[64], *encoded = NULL, *attr = NULL, *table = NULL;
    DWORD digest_len = sizeof(digest), encoded_len = 0, attr_len = 0, table_len;
    SPC_PE_IMAGE_DATA image = { { 0 } };
    SPC_LINK link = { SPC_FILE_LINK_CHOICE };
    const char *alg_oid;
    BYTE flags_byte = 0;
    HANDLE file;
    BOOL opened, ret = FALSE;
    ALG_ID alg;

    TRACE("(%p %p %p)\n", info, size, out);

    if (!info || !size || info->cbSize < sizeof(*info) || !info->pgSubjectType)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (memcmp(info->pgSubjectType, &unknown, sizeof(unknown)))
    {
        FIXME("unimplemented for subject type %s\n", debugstr_guid(info->pgSubjectType));
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    file = sip_open_subject(info, GENERIC_READ, &opened);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!sip_pe_digest(info, file, &alg, digest, &digest_len)) goto done;
    alg_oid = info->DigestAlgorithm.pszObjId ? info->DigestAlgorithm.pszObjId : szOID_OIWSEC_sha1;

    link.pwszFile = obsolete;
    image.Flags.cbData = 1;
    image.Flags.pbData = &flags_byte;
    image.pFile = &link;
    if (info->dwFlags & SPC_INC_PE_PAGE_HASHES_FLAG)
    {
        const char *oid = alg == CALG_SHA1 ? SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID : SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID;

        if (!pe_page_hash_table(file, alg, &table, &table_len)) goto done;
        if (!(attr = encode_page_hash_attr(oid, table, table_len, &attr_len)))
        {
            SetLastError(ERROR_OUTOFMEMORY);
            goto done;
        }
        link.dwLinkChoice = SPC_MONIKER_LINK_CHOICE;
        memcpy(link.Moniker.ClassId, page_hash_class_id, sizeof(page_hash_class_id));
        link.Moniker.SerializedData.cbData = attr_len;
        link.Moniker.SerializedData.pbData = attr;
    }
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, SPC_PE_IMAGE_DATA_STRUCT, &image, CRYPT_ENCODE_ALLOC_FLAG, NULL,
                             &encoded, &encoded_len)) goto done;
    ret = fill_indirect_data(SPC_PE_IMAGE_DATA_OBJID, encoded, encoded_len, alg_oid, digest, digest_len, size, out);

done:
    LocalFree(encoded);
    free(attr);
    free(table);
    if (opened) CloseHandle(file);
    return ret;
}

/***********************************************************************
 *      CryptSIPVerifyIndirectData  (WINTRUST.@)
 *
 * Compares the digest of the PE subject with the one in the indirect data.
 */
BOOL WINAPI CryptSIPVerifyIndirectData(SIP_SUBJECTINFO *info, SIP_INDIRECT_DATA *data)
{
    BYTE digest[64];
    DWORD len = sizeof(digest);
    SIP_SUBJECTINFO copy;
    HANDLE file;
    BOOL opened, ret = FALSE;
    ALG_ID alg;

    TRACE("(%p %p)\n", info, data);

    if (!info || !data || info->cbSize < sizeof(*info) || !info->pgSubjectType ||
        !data->DigestAlgorithm.pszObjId || !data->Digest.pbData)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (memcmp(info->pgSubjectType, &unknown, sizeof(unknown)))
    {
        FIXME("unimplemented for subject type %s\n", debugstr_guid(info->pgSubjectType));
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    file = sip_open_subject(info, GENERIC_READ, &opened);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    copy = *info;
    copy.DigestAlgorithm = data->DigestAlgorithm;
    if (sip_pe_digest(&copy, file, &alg, digest, &len))
    {
        if (len == data->Digest.cbData && !memcmp(digest, data->Digest.pbData, len))
            ret = TRUE;
        else
            SetLastError(TRUST_E_BAD_DIGEST);
    }
    if (opened) CloseHandle(file);
    return ret;
}

/***********************************************************************
 *      CryptSIPRemoveSignedDataMsg  (WINTRUST.@)
 */
BOOL WINAPI CryptSIPRemoveSignedDataMsg(SIP_SUBJECTINFO *info, DWORD index)
{
    HANDLE file;
    BOOL opened, ret;

    TRACE("(%p %ld)\n", info, index);

    if (!info || info->cbSize < sizeof(*info) || !info->pgSubjectType)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (memcmp(info->pgSubjectType, &unknown, sizeof(unknown)))
    {
        FIXME("unimplemented for subject type %s\n", debugstr_guid(info->pgSubjectType));
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    file = sip_open_subject(info, GENERIC_READ | GENERIC_WRITE, &opened);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    ret = ImageRemoveCertificate(file, index);
    if (opened) CloseHandle(file);
    return ret;
}
