/*
 * Copyright 2004-2007 Juan Lang
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
#include <assert.h>
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "wincrypt.h"
#include "winreg.h"
#include "winuser.h"
#include "wine/debug.h"
#include "crypt32_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(crypt);

typedef struct _WINE_REGSTOREINFO
{
    DWORD            dwOpenFlags;
    HCERTSTORE       memStore;
    HKEY             key;
    /* A system store (CertOpenStore(CERT_STORE_PROV_SYSTEM...)) keeps where its
     * key is, so key can be a read-only handle and a write opens the key for
     * write then.  A store handed a key by the caller (CERT_STORE_PROV_REG)
     * has no path and writes through key. */
    HKEY             root;
    LPWSTR           path;
    BOOL             dirty;
    DWORD            resyncThread;
    HANDLE           changeEvent;
    CRITICAL_SECTION cs;
} WINE_REGSTOREINFO;

static const WCHAR * const regSubKeys[] = { L"Certificates", L"CRLs", L"CTLs" };

/* The key to write under, for a store that writes.  Only here is write access
 * asked for: a store opened without CERT_STORE_READONLY_FLAG that is only read
 * (a standard user opening a LocalMachine store) never asks for it.  Close
 * with CRYPT_RegCloseWriteKey. */
static LONG CRYPT_RegOpenWriteKey(WINE_REGSTOREINFO *store, HKEY *key)
{
    if (!store->path)
    {
        *key = store->key;
        return ERROR_SUCCESS;
    }
    return RegOpenKeyExW(store->root, store->path, 0, KEY_READ | KEY_WRITE, key);
}

static void CRYPT_RegCloseWriteKey(WINE_REGSTOREINFO *store, HKEY key)
{
    if (store->path)
        RegCloseKey(key);
}

static void CRYPT_HashToStr(const BYTE *hash, LPWSTR asciiHash)
{
    DWORD i;

    assert(hash);
    assert(asciiHash);

    for (i = 0; i < 20; i++)
        wsprintfW(asciiHash + i * 2, L"%02X", hash[i]);
}

void CRYPT_RegReadSerializedFromReg(HKEY key, DWORD contextType, HCERTSTORE store, DWORD disposition)
{
    LONG rc;
    DWORD index = 0;
    WCHAR subKeyName[MAX_PATH];

    do {
        DWORD size = ARRAY_SIZE(subKeyName);

        rc = RegEnumKeyExW(key, index++, subKeyName, &size, NULL, NULL, NULL,
         NULL);
        if (!rc)
        {
            HKEY subKey;

            rc = RegOpenKeyExW(key, subKeyName, 0, KEY_READ, &subKey);
            if (!rc)
            {
                LPBYTE buf = NULL;

                size = 0;
                rc = RegQueryValueExW(subKey, L"Blob", NULL, NULL, NULL, &size);
                if (!rc)
                    buf = CryptMemAlloc(size);
                if (buf)
                {
                    rc = RegQueryValueExW(subKey, L"Blob", NULL, NULL, buf,
                     &size);
                    if (!rc)
                    {
                        const void *context;
                        DWORD addedType;

                        TRACE("Adding cert with hash %s\n",
                         debugstr_w(subKeyName));
                        context = CRYPT_ReadSerializedElement(buf, size,
                         contextType, &addedType);
                        if (context)
                        {
                            const WINE_CONTEXT_INTERFACE *contextInterface;
                            BYTE hash[20];

                            switch (addedType)
                            {
                            case CERT_STORE_CERTIFICATE_CONTEXT:
                                contextInterface = pCertInterface;
                                break;
                            case CERT_STORE_CRL_CONTEXT:
                                contextInterface = pCRLInterface;
                                break;
                            case CERT_STORE_CTL_CONTEXT:
                                contextInterface = pCTLInterface;
                                break;
                            default:
                                contextInterface = NULL;
                            }
                            if (contextInterface)
                            {
                                size = sizeof(hash);
                                if (contextInterface->getProp(context,
                                 CERT_HASH_PROP_ID, hash, &size))
                                {
                                    WCHAR asciiHash[20 * 2 + 1];

                                    CRYPT_HashToStr(hash, asciiHash);
                                    TRACE("comparing %s\n",
                                     debugstr_w(asciiHash));
                                    TRACE("with %s\n", debugstr_w(subKeyName));
                                    if (!wcscmp(asciiHash, subKeyName))
                                    {
                                        TRACE("hash matches, adding\n");
                                        contextInterface->addContextToStore(
                                         store, context,
                                         disposition, NULL);
                                    }
                                    else
                                        TRACE("hash doesn't match, ignoring\n");
                                }
                                Context_Release(context_from_ptr(context));
                            }
                        }
                    }
                    CryptMemFree(buf);
                }
                RegCloseKey(subKey);
            }
            /* Ignore intermediate errors, continue enumerating */
            rc = ERROR_SUCCESS;
        }
    } while (!rc);
}

static void CRYPT_RegReadFromReg(HKEY key, HCERTSTORE store, DWORD disposition)
{
    static const WCHAR * const subKeys[] = { L"Certificates", L"CRLs", L"CTLs" };
    static const DWORD contextFlags[] = { CERT_STORE_CERTIFICATE_CONTEXT_FLAG,
     CERT_STORE_CRL_CONTEXT_FLAG, CERT_STORE_CTL_CONTEXT_FLAG };
    DWORD i;

    for (i = 0; i < ARRAY_SIZE(subKeys); i++)
    {
        HKEY hKey;
        LONG rc;

        rc = RegCreateKeyExW(key, subKeys[i], 0, NULL, 0, KEY_READ, NULL,
         &hKey, NULL);
        if (!rc)
        {
            CRYPT_RegReadSerializedFromReg(hKey, contextFlags[i], store, disposition);
            RegCloseKey(hKey);
        }
    }
}

/* Hash is assumed to be 20 bytes in length (a SHA-1 hash) */
static BOOL CRYPT_WriteSerializedToReg(HKEY key, DWORD flags, const BYTE *hash, const BYTE *buf,
 DWORD len)
{
    WCHAR asciiHash[20 * 2 + 1];
    LONG rc;
    HKEY subKey;
    BOOL ret;

    CRYPT_HashToStr(hash, asciiHash);
    rc = RegCreateKeyExW(key, asciiHash, 0, NULL, flags, KEY_ALL_ACCESS, NULL,
     &subKey, NULL);
    if (!rc)
    {
        rc = RegSetValueExW(subKey, L"Blob", 0, REG_BINARY, buf, len);
        RegCloseKey(subKey);
    }
    if (!rc)
        ret = TRUE;
    else
    {
        SetLastError(rc);
        ret = FALSE;
    }
    return ret;
}

BOOL CRYPT_SerializeContextsToReg(HKEY key, DWORD flags,
 const WINE_CONTEXT_INTERFACE *contextInterface, HCERTSTORE memStore)
{
    const void *context = NULL;
    BOOL ret;

    do {
        context = contextInterface->enumContextsInStore(memStore, context);
        if (context)
        {
            BYTE hash[20];
            DWORD hashSize = sizeof(hash);

            ret = contextInterface->getProp(context, CERT_HASH_PROP_ID, hash,
             &hashSize);
            if (ret)
            {
                DWORD size = 0;
                LPBYTE buf = NULL;

                ret = contextInterface->serialize(context, 0, NULL, &size);
                if (size)
                    buf = CryptMemAlloc(size);
                if (buf)
                {
                    ret = contextInterface->serialize(context, 0, buf, &size);
                    if (ret)
                        ret = CRYPT_WriteSerializedToReg(key, flags, hash, buf, size);
                }
                CryptMemFree(buf);
            }
        }
        else
            ret = TRUE;
    } while (ret && context != NULL);
    if (context)
        Context_Release(context_from_ptr(context));
    return ret;
}

/* Serializes a single context and writes it under the store's subkey
 * regSubKeys[type] (type indexes certs, CRLs and CTLs).
 */
static BOOL CRYPT_RegWriteOneContext(WINE_REGSTOREINFO *store, DWORD type,
 const WINE_CONTEXT_INTERFACE *contextInterface, const void *context)
{
    BYTE hash[20];
    DWORD hashSize = sizeof(hash), size = 0;
    LPBYTE buf = NULL;
    HKEY key, storeKey;
    LONG rc;
    BOOL ret;

    ret = contextInterface->getProp(context, CERT_HASH_PROP_ID, hash, &hashSize);
    if (!ret)
        return FALSE;
    ret = contextInterface->serialize(context, 0, NULL, &size);
    if (ret && size)
        buf = CryptMemAlloc(size);
    if (!buf)
    {
        if (ret)
            SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    ret = contextInterface->serialize(context, 0, buf, &size);
    if (ret)
    {
        rc = CRYPT_RegOpenWriteKey(store, &storeKey);
        if (!rc)
        {
            rc = RegCreateKeyExW(storeKey, regSubKeys[type], 0, NULL, 0,
             KEY_ALL_ACCESS, NULL, &key, NULL);
            CRYPT_RegCloseWriteKey(store, storeKey);
        }
        if (!rc)
        {
            ret = CRYPT_WriteSerializedToReg(key, 0, hash, buf, size);
            RegCloseKey(key);
        }
        else
        {
            SetLastError(rc);
            ret = FALSE;
        }
    }
    CryptMemFree(buf);
    return ret;
}

/* Writes all the contexts of the in-memory store to the registry. */
static BOOL CRYPT_RegWriteToReg(WINE_REGSTOREINFO *store)
{
    const WINE_CONTEXT_INTERFACE * const interfaces[] = { pCertInterface,
     pCRLInterface, pCTLInterface };
    BOOL ret = TRUE;
    DWORD i;

    for (i = 0; ret && i < ARRAY_SIZE(regSubKeys); i++)
    {
        HKEY key, storeKey;
        LONG rc = CRYPT_RegOpenWriteKey(store, &storeKey);

        if (!rc)
        {
            rc = RegCreateKeyExW(storeKey, regSubKeys[i], 0, NULL, 0,
             KEY_ALL_ACCESS, NULL, &key, NULL);
            CRYPT_RegCloseWriteKey(store, storeKey);
        }
        if (!rc)
        {
            ret = CRYPT_SerializeContextsToReg(key, 0, interfaces[i], store->memStore);
            RegCloseKey(key);
        }
        else
        {
            SetLastError(rc);
            ret = FALSE;
        }
    }
    return ret;
}

/* Rewrites the registry entry of a context if the entry exists (under key,
 * the subkey of the context's type) and differs from the context's current
 * serialization.  An entry that is gone (removed through another handle) is
 * not recreated.
 */
static BOOL CRYPT_RegUpdateContext(HKEY key,
 const WINE_CONTEXT_INTERFACE *contextInterface, const void *context)
{
    BYTE hash[20];
    DWORD hashSize = sizeof(hash), size = 0, regSize = 0;
    WCHAR asciiHash[20 * 2 + 1];
    HKEY subKey;
    LPBYTE buf, regBuf = NULL;
    BOOL ret = TRUE, same = FALSE;

    if (!contextInterface->getProp(context, CERT_HASH_PROP_ID, hash, &hashSize))
        return TRUE;
    CRYPT_HashToStr(hash, asciiHash);
    if (RegOpenKeyExW(key, asciiHash, 0, KEY_READ, &subKey))
        return TRUE;
    if (!contextInterface->serialize(context, 0, NULL, &size) || !size)
    {
        RegCloseKey(subKey);
        return TRUE;
    }
    buf = CryptMemAlloc(size);
    if (!buf)
    {
        RegCloseKey(subKey);
        return TRUE;
    }
    if (contextInterface->serialize(context, 0, buf, &size))
    {
        if (!RegQueryValueExW(subKey, L"Blob", NULL, NULL, NULL, &regSize) &&
         regSize == size && (regBuf = CryptMemAlloc(regSize)))
        {
            if (!RegQueryValueExW(subKey, L"Blob", NULL, NULL, regBuf, &regSize))
                same = regSize == size && !memcmp(regBuf, buf, size);
            CryptMemFree(regBuf);
        }
        RegCloseKey(subKey);
        subKey = NULL;
        if (!same)
            ret = CRYPT_WriteSerializedToReg(key, 0, hash, buf, size);
    }
    if (subKey)
        RegCloseKey(subKey);
    CryptMemFree(buf);
    return ret;
}

/* Adds, deletes and replacements are already in the registry when they
 * return.  This brings the registry up to date with the changes made to the
 * contexts since (their properties).
 */
static BOOL CRYPT_RegUpdateChanged(WINE_REGSTOREINFO *store)
{
    const WINE_CONTEXT_INTERFACE * const interfaces[] = { pCertInterface,
     pCRLInterface, pCTLInterface };
    BOOL ret = TRUE;
    DWORD i;

    for (i = 0; ret && i < ARRAY_SIZE(regSubKeys); i++)
    {
        HKEY key, storeKey;
        const void *context = NULL;
        LONG rc = CRYPT_RegOpenWriteKey(store, &storeKey);

        if (!rc)
        {
            rc = RegOpenKeyExW(storeKey, regSubKeys[i], 0, KEY_ALL_ACCESS, &key);
            CRYPT_RegCloseWriteKey(store, storeKey);
        }
        if (rc)
            continue;
        while (ret && (context = interfaces[i]->enumContextsInStore(store->memStore, context)))
            ret = CRYPT_RegUpdateContext(key, interfaces[i], context);
        if (context)
            Context_Release(context_from_ptr(context));
        RegCloseKey(key);
    }
    return ret;
}

/* If force is true, writes the contents of the store to the registry.
 * Otherwise, if anything was added or removed through this handle, brings
 * the registry up to date with later changes to the contexts.
 */
static BOOL CRYPT_RegFlushStore(WINE_REGSTOREINFO *store, BOOL force)
{
    BOOL ret;

    TRACE("(%p, %d)\n", store, force);

    if (force)
        ret = CRYPT_RegWriteToReg(store);
    else if (store->dirty && !(store->dwOpenFlags & CERT_STORE_READONLY_FLAG))
        ret = CRYPT_RegUpdateChanged(store);
    else
        ret = TRUE;
    if (ret)
        store->dirty = FALSE;
    return ret;
}

static void WINAPI CRYPT_RegCloseStore(HCERTSTORE hCertStore, DWORD dwFlags)
{
    WINE_REGSTOREINFO *store = hCertStore;
    DWORD err;

    TRACE("(%p, %08lx)\n", store, dwFlags);
    if (dwFlags)
        FIXME("Unimplemented flags: %08lx\n", dwFlags);

    /* Closing a store does not change the last error, which the enumeration
     * in the flush does. */
    err = GetLastError();
    CRYPT_RegFlushStore(store, FALSE);
    SetLastError(err);
    RegCloseKey(store->key);
    CryptMemFree(store->path);
    if (store->changeEvent)
        CloseHandle(store->changeEvent);
    store->cs.DebugInfo->Spare[0] = 0;
    DeleteCriticalSection(&store->cs);
    CryptMemFree(store);
}

/* Like Windows, additions are written to the registry immediately, so other
 * handles on the same store and other processes see them without this
 * handle being committed or closed.
 */
static BOOL CRYPT_RegWriteContext(WINE_REGSTOREINFO *store, DWORD type,
 const void *context, const WINE_CONTEXT_INTERFACE *contextInterface,
 DWORD dwFlags)
{
    BOOL ret;

    if (!(dwFlags & CERT_STORE_PROV_WRITE_ADD_FLAG))
        return FALSE;
    if (store->resyncThread == GetCurrentThreadId())
        return TRUE;
    if (store->dwOpenFlags & CERT_STORE_READONLY_FLAG)
    {
        SetLastError(E_ACCESSDENIED);
        return FALSE;
    }
    EnterCriticalSection(&store->cs);
    ret = CRYPT_RegWriteOneContext(store, type, contextInterface, context);
    if (ret)
        store->dirty = TRUE;
    LeaveCriticalSection(&store->cs);
    return ret;
}

/* Removes the context's registry entry immediately.  An entry that is already
 * gone (removed through another handle) is not an error.
 */
static BOOL CRYPT_RegDeleteContext(WINE_REGSTOREINFO *store, DWORD type,
 const void *context, const WINE_CONTEXT_INTERFACE *contextInterface)
{
    BYTE hash[20];
    DWORD size = sizeof(hash);
    WCHAR asciiHash[20 * 2 + 1];
    HKEY key, storeKey;
    LONG rc;

    if (store->resyncThread == GetCurrentThreadId())
        return TRUE;
    if (store->dwOpenFlags & CERT_STORE_READONLY_FLAG)
    {
        SetLastError(E_ACCESSDENIED);
        return FALSE;
    }
    if (!contextInterface->getProp(context, CERT_HASH_PROP_ID, hash, &size))
        return FALSE;
    CRYPT_HashToStr(hash, asciiHash);
    EnterCriticalSection(&store->cs);
    rc = CRYPT_RegOpenWriteKey(store, &storeKey);
    if (!rc)
    {
        rc = RegOpenKeyExW(storeKey, regSubKeys[type], 0, KEY_ALL_ACCESS, &key);
        CRYPT_RegCloseWriteKey(store, storeKey);
    }
    if (!rc)
    {
        TRACE("Removing %s\n", debugstr_w(asciiHash));
        rc = RegDeleteKeyW(key, asciiHash);
        RegCloseKey(key);
    }
    if (rc == ERROR_FILE_NOT_FOUND)
        rc = ERROR_SUCCESS;
    if (!rc)
        store->dirty = TRUE;
    LeaveCriticalSection(&store->cs);
    if (rc)
    {
        SetLastError(rc);
        return FALSE;
    }
    return TRUE;
}

static BOOL WINAPI CRYPT_RegWriteCert(HCERTSTORE hCertStore,
 PCCERT_CONTEXT cert, DWORD dwFlags)
{
    WINE_REGSTOREINFO *store = hCertStore;

    TRACE("(%p, %p, %ld)\n", hCertStore, cert, dwFlags);

    return CRYPT_RegWriteContext(store, 0, cert, pCertInterface, dwFlags);
}

static BOOL WINAPI CRYPT_RegDeleteCert(HCERTSTORE hCertStore,
 PCCERT_CONTEXT pCertContext, DWORD dwFlags)
{
    WINE_REGSTOREINFO *store = hCertStore;

    TRACE("(%p, %p, %08lx)\n", store, pCertContext, dwFlags);

    return CRYPT_RegDeleteContext(store, 0, pCertContext, pCertInterface);
}

static BOOL WINAPI CRYPT_RegWriteCRL(HCERTSTORE hCertStore,
 PCCRL_CONTEXT crl, DWORD dwFlags)
{
    WINE_REGSTOREINFO *store = hCertStore;

    TRACE("(%p, %p, %ld)\n", hCertStore, crl, dwFlags);

    return CRYPT_RegWriteContext(store, 1, crl, pCRLInterface, dwFlags);
}

static BOOL WINAPI CRYPT_RegDeleteCRL(HCERTSTORE hCertStore,
 PCCRL_CONTEXT pCrlContext, DWORD dwFlags)
{
    WINE_REGSTOREINFO *store = hCertStore;

    TRACE("(%p, %p, %08lx)\n", store, pCrlContext, dwFlags);

    return CRYPT_RegDeleteContext(store, 1, pCrlContext, pCRLInterface);
}

static BOOL WINAPI CRYPT_RegWriteCTL(HCERTSTORE hCertStore,
 PCCTL_CONTEXT ctl, DWORD dwFlags)
{
    WINE_REGSTOREINFO *store = hCertStore;

    TRACE("(%p, %p, %ld)\n", hCertStore, ctl, dwFlags);

    return CRYPT_RegWriteContext(store, 2, ctl, pCTLInterface, dwFlags);
}

static BOOL WINAPI CRYPT_RegDeleteCTL(HCERTSTORE hCertStore,
 PCCTL_CONTEXT pCtlContext, DWORD dwFlags)
{
    WINE_REGSTOREINFO *store = hCertStore;

    TRACE("(%p, %p, %08lx)\n", store, pCtlContext, dwFlags);

    return CRYPT_RegDeleteContext(store, 2, pCtlContext, pCTLInterface);
}

/* Like Windows, a property change is written to the registry immediately. */
static BOOL CRYPT_RegSetContextProperty(WINE_REGSTOREINFO *store, DWORD type,
 const void *context, const WINE_CONTEXT_INTERFACE *contextInterface)
{
    HKEY key, storeKey;
    BOOL ret = TRUE;
    LONG rc;

    if (store->dwOpenFlags & CERT_STORE_READONLY_FLAG || store->resyncThread == GetCurrentThreadId())
        return TRUE;
    EnterCriticalSection(&store->cs);
    rc = CRYPT_RegOpenWriteKey(store, &storeKey);
    if (!rc)
    {
        rc = RegOpenKeyExW(storeKey, regSubKeys[type], 0, KEY_ALL_ACCESS, &key);
        CRYPT_RegCloseWriteKey(store, storeKey);
    }
    if (!rc)
    {
        ret = CRYPT_RegUpdateContext(key, contextInterface, context);
        RegCloseKey(key);
    }
    /* If it could not be written, the next flush tries again. */
    if (!ret)
        store->dirty = TRUE;
    LeaveCriticalSection(&store->cs);
    return ret;
}

static BOOL WINAPI CRYPT_RegSetCertProperty(HCERTSTORE hCertStore,
 PCCERT_CONTEXT cert, DWORD dwPropId, DWORD dwFlags, const void *pvData)
{
    TRACE("(%p, %p, %ld, %08lx, %p)\n", hCertStore, cert, dwPropId, dwFlags, pvData);

    return CRYPT_RegSetContextProperty(hCertStore, 0, cert, pCertInterface);
}

static BOOL WINAPI CRYPT_RegSetCRLProperty(HCERTSTORE hCertStore,
 PCCRL_CONTEXT crl, DWORD dwPropId, DWORD dwFlags, const void *pvData)
{
    TRACE("(%p, %p, %ld, %08lx, %p)\n", hCertStore, crl, dwPropId, dwFlags, pvData);

    return CRYPT_RegSetContextProperty(hCertStore, 1, crl, pCRLInterface);
}

static BOOL WINAPI CRYPT_RegSetCTLProperty(HCERTSTORE hCertStore,
 PCCTL_CONTEXT ctl, DWORD dwPropId, DWORD dwFlags, const void *pvData)
{
    TRACE("(%p, %p, %ld, %08lx, %p)\n", hCertStore, ctl, dwPropId, dwFlags, pvData);

    return CRYPT_RegSetContextProperty(hCertStore, 2, ctl, pCTLInterface);
}

/* Has changeEvent signalled when anything under the store's key changes. */
static BOOL CRYPT_RegWatch(WINE_REGSTOREINFO *store)
{
    LONG rc = RegNotifyChangeKeyValue(store->key, TRUE,
     REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
     store->changeEvent, TRUE);

    if (rc)
        SetLastError(rc);
    return !rc;
}

/* Replaces the cached contents with what the registry holds. */
static void CRYPT_RegResync(WINE_REGSTOREINFO *store)
{
    HCERTSTORE memStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);

    CRYPT_RegFlushStore(store, FALSE);
    CRYPT_RegReadFromReg(store->key, memStore, CERT_STORE_ADD_REPLACE_EXISTING);
    /* Replacing the contents of the cache must not touch the registry, which
     * is where the new contents come from: contexts handed out by the store
     * would write their removal through. */
    store->resyncThread = GetCurrentThreadId();
    I_CertUpdateStore(store->memStore, memStore, 0, 0);
    store->resyncThread = 0;
    CertCloseStore(memStore, 0);
}

static BOOL WINAPI CRYPT_RegControl(HCERTSTORE hCertStore, DWORD dwFlags,
 DWORD dwCtrlType, void const *pvCtrlPara)
{
    WINE_REGSTOREINFO *store = hCertStore;
    BOOL ret = TRUE;

    TRACE("(%p, %08lx, %ld, %p)\n", hCertStore, dwFlags, dwCtrlType,
     pvCtrlPara);

    switch (dwCtrlType)
    {
    case CERT_STORE_CTRL_RESYNC:
        CRYPT_RegResync(store);
        break;
    case CRYPT_STORE_CTRL_RESYNC_IF_CHANGED:
        if (store->changeEvent && WaitForSingleObject(store->changeEvent, 0) == WAIT_OBJECT_0)
        {
            /* Watch again before reading, so a change made meanwhile is not lost. */
            ResetEvent(store->changeEvent);
            CRYPT_RegWatch(store);
            CRYPT_RegResync(store);
        }
        break;
    case CERT_STORE_CTRL_COMMIT:
        ret = CRYPT_RegFlushStore(store,
         dwFlags & CERT_STORE_CTRL_COMMIT_FORCE_FLAG);
        break;
    case CERT_STORE_CTRL_AUTO_RESYNC:
        /* From now on the contents are brought up to date when they are enumerated */
        if (!store->changeEvent)
        {
            store->changeEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!store->changeEvent || !CRYPT_RegWatch(store))
            {
                if (store->changeEvent)
                    CloseHandle(store->changeEvent);
                store->changeEvent = NULL;
                ret = FALSE;
            }
        }
        break;
    case CERT_STORE_CTRL_NOTIFY_CHANGE:
        FIXME("CERT_STORE_CTRL_NOTIFY_CHANGE: stub\n");
        break;
    default:
        FIXME("%lu: stub\n", dwCtrlType);
        ret = FALSE;
    }
    return ret;
}

static void *regProvFuncs[] = {
    CRYPT_RegCloseStore,
    NULL, /* CERT_STORE_PROV_READ_CERT_FUNC */
    CRYPT_RegWriteCert,
    CRYPT_RegDeleteCert,
    CRYPT_RegSetCertProperty,
    NULL, /* CERT_STORE_PROV_READ_CRL_FUNC */
    CRYPT_RegWriteCRL,
    CRYPT_RegDeleteCRL,
    CRYPT_RegSetCRLProperty,
    NULL, /* CERT_STORE_PROV_READ_CTL_FUNC */
    CRYPT_RegWriteCTL,
    CRYPT_RegDeleteCTL,
    CRYPT_RegSetCTLProperty,
    CRYPT_RegControl,
};

static WINECRYPT_CERTSTORE *CRYPT_RegOpenStoreAt(HCRYPTPROV hCryptProv,
 DWORD dwFlags, const void *pvPara, HKEY root, LPCWSTR path)
{
    WINECRYPT_CERTSTORE *store = NULL;

    TRACE("(%Id, %08lx, %p)\n", hCryptProv, dwFlags, pvPara);

    if (dwFlags & CERT_STORE_DELETE_FLAG)
    {
        DWORD rc = RegDeleteTreeW((HKEY)pvPara, L"Certificates");

        if (rc == ERROR_SUCCESS || rc == ERROR_NO_MORE_ITEMS)
            rc = RegDeleteTreeW((HKEY)pvPara, L"CRLs");
        if (rc == ERROR_SUCCESS || rc == ERROR_NO_MORE_ITEMS)
            rc = RegDeleteTreeW((HKEY)pvPara, L"CTLs");
        if (rc == ERROR_NO_MORE_ITEMS)
            rc = ERROR_SUCCESS;
        SetLastError(rc);
    }
    else
    {
        HKEY key;

        if (DuplicateHandle(GetCurrentProcess(), (HANDLE)pvPara,
         GetCurrentProcess(), (LPHANDLE)&key,
         dwFlags & CERT_STORE_READONLY_FLAG || path ? KEY_READ : KEY_ALL_ACCESS,
         TRUE, 0))
        {
            WINECRYPT_CERTSTORE *memStore;

            memStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, hCryptProv,
             CERT_STORE_CREATE_NEW_FLAG, NULL);
            if (memStore)
            {
                WINE_REGSTOREINFO *regInfo = CryptMemAlloc(
                 sizeof(WINE_REGSTOREINFO));

                if (regInfo)
                {
                    CERT_STORE_PROV_INFO provInfo = { 0 };

                    regInfo->dwOpenFlags = dwFlags;
                    regInfo->memStore = memStore;
                    regInfo->key = key;
                    regInfo->root = root;
                    regInfo->path = NULL;
                    if (path && (regInfo->path = CryptMemAlloc((lstrlenW(path) + 1) * sizeof(WCHAR))))
                        lstrcpyW(regInfo->path, path);
                    else
                        regInfo->root = NULL;
                    InitializeCriticalSectionEx(&regInfo->cs, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);
                    regInfo->cs.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": PWINE_REGSTOREINFO->cs");
                    CRYPT_RegReadFromReg(regInfo->key, regInfo->memStore, CERT_STORE_ADD_ALWAYS);
                    regInfo->dirty = FALSE;
                    regInfo->resyncThread = 0;
                    regInfo->changeEvent = NULL;
                    provInfo.cbSize = sizeof(provInfo);
                    provInfo.dwStoreProvFlags = CRYPT_PROV_STORE_AUTO_RESYNC_CHECK;
                    provInfo.cStoreProvFunc = ARRAY_SIZE(regProvFuncs);
                    provInfo.rgpvStoreProvFunc = regProvFuncs;
                    provInfo.hStoreProv = regInfo;
                    store = CRYPT_ProvCreateStore(dwFlags, memStore, &provInfo);
                    /* Reg store doesn't need crypto provider, so close it */
                    if (hCryptProv &&
                     !(dwFlags & CERT_STORE_NO_CRYPT_RELEASE_FLAG))
                        CryptReleaseContext(hCryptProv, 0);
                }
            }
        }
    }
    TRACE("returning %p\n", store);
    return store;
}

WINECRYPT_CERTSTORE *CRYPT_RegOpenStore(HCRYPTPROV hCryptProv, DWORD dwFlags,
 const void *pvPara)
{
    return CRYPT_RegOpenStoreAt(hCryptProv, dwFlags, pvPara, NULL, NULL);
}

/* A system store: key is the store's key opened for read, root and path say
 * where it is, so a write can open it for write. */
WINECRYPT_CERTSTORE *CRYPT_RegOpenSystemStore(HCRYPTPROV hCryptProv,
 DWORD dwFlags, HKEY key, HKEY root, LPCWSTR path)
{
    return CRYPT_RegOpenStoreAt(hCryptProv, dwFlags, key, root, path);
}
