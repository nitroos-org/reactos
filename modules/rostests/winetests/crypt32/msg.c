/*
 * Unit test suite for crypt32.dll's CryptMsg functions
 *
 * Copyright 2007 Juan Lang
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

#include <stdio.h>
#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#define CMSG_SIGNER_ENCODE_INFO_HAS_CMS_FIELDS
#define CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS
#include <wincrypt.h>

#include "wine/test.h"

static char oid_rsa_md5[] = szOID_RSA_MD5;

static void test_msg_open_to_encode(void)
{
    HCRYPTMSG msg;

    /* Crash
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, NULL,
     NULL, NULL);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, NULL, NULL,
     NULL);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, NULL, NULL,
     NULL);
     */

    /* Bad encodings */
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(0, 0, 0, NULL, NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(X509_ASN_ENCODING, 0, 0, NULL, NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());

    /* Bad message types */
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, 0, NULL, NULL, NULL);
    ok(!msg && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0,
     NULL, NULL, NULL);
    ok(!msg && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0,
     CMSG_SIGNED_AND_ENVELOPED, NULL, NULL, NULL);
    ok(!msg && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENCRYPTED, NULL,
     NULL, NULL);
    ok(!msg && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
}

static void test_msg_open_to_decode(void)
{
    HCRYPTMSG msg;
    CMSG_STREAM_INFO streamInfo = { 0 };

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToDecode(0, 0, 0, 0, NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());

    /* Bad encodings */
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToDecode(X509_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToDecode(X509_ASN_ENCODING, 0, CMSG_DATA, 0, NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());

    /* The message type can be explicit... */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0,
     CMSG_SIGNED_AND_ENVELOPED, 0, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* or implicit.. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* or even invalid. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENCRYPTED, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 1000, 0, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* And even though the stream info parameter "must be set to NULL" for
     * CMSG_HASHED, it's still accepted.
     */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL,
     &streamInfo);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
}

static void test_msg_get_param(void)
{
    BOOL ret;
    HCRYPTMSG msg;
    DWORD size, i, value;

    /* Crash
    ret = CryptMsgGetParam(NULL, 0, 0, NULL, NULL);
    ret = CryptMsgGetParam(NULL, 0, 0, NULL, &size);
    ret = CryptMsgGetParam(msg, 0, 0, NULL, NULL);
     */

    /* Decoded messages */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    /* For decoded messages, the type is always available */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    /* For this (empty) message, the type isn't set */
    ok(value == 0, "Expected type 0, got %ld\n", value);
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    /* For explicitly typed messages, the type is known. */
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    ok(value == CMSG_DATA, "Expected CMSG_DATA, got %ld\n", value);
    for (i = CMSG_CONTENT_PARAM; i <= CMSG_CMS_SIGNER_INFO_PARAM; i++)
    {
        size = 0;
        ret = CryptMsgGetParam(msg, i, 0, NULL, &size);
        ok(!ret, "Parameter %ld: expected failure\n", i);
    }
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    ok(value == CMSG_ENVELOPED, "Expected CMSG_ENVELOPED, got %ld\n", value);
    for (i = CMSG_CONTENT_PARAM; i <= CMSG_CMS_SIGNER_INFO_PARAM; i++)
    {
        size = 0;
        ret = CryptMsgGetParam(msg, i, 0, NULL, &size);
        ok(!ret, "Parameter %ld: expected failure\n", i);
    }
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    ok(value == CMSG_HASHED, "Expected CMSG_HASHED, got %ld\n", value);
    for (i = CMSG_CONTENT_PARAM; i <= CMSG_CMS_SIGNER_INFO_PARAM; i++)
    {
        size = 0;
        ret = CryptMsgGetParam(msg, i, 0, NULL, &size);
        ok(!ret, "Parameter %ld: expected failure\n", i);
    }
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    ok(value == CMSG_SIGNED, "Expected CMSG_SIGNED, got %ld\n", value);
    for (i = CMSG_CONTENT_PARAM; i <= CMSG_CMS_SIGNER_INFO_PARAM; i++)
    {
        size = 0;
        ret = CryptMsgGetParam(msg, i, 0, NULL, &size);
        ok(!ret, "Parameter %ld: expected failure\n", i);
    }
    CryptMsgClose(msg);

    /* Explicitly typed messages get their types set, even if they're invalid */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENCRYPTED, 0, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    ok(value == CMSG_ENCRYPTED, "Expected CMSG_ENCRYPTED, got %ld\n", value);
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 1000, 0, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToDecode failed: %lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    ok(value == 1000, "Expected 1000, got %ld\n", value);
    CryptMsgClose(msg);
}

static void test_msg_close(void)
{
    BOOL ret;
    HCRYPTMSG msg;

    /* NULL succeeds.. */
    ret = CryptMsgClose(NULL);
    ok(ret, "CryptMsgClose failed: %lx\n", GetLastError());
    /* but an arbitrary pointer crashes. */
    if (0)
        ret = CryptMsgClose((HCRYPTMSG)1);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    ret = CryptMsgClose(msg);
    ok(ret, "CryptMsgClose failed: %lx\n", GetLastError());
}

static void check_param(LPCSTR test, HCRYPTMSG msg, DWORD param,
 const BYTE *expected, DWORD expectedSize)
{
    DWORD size;
    LPBYTE buf;
    BOOL ret;

    size = 0xdeadbeef;
    ret = CryptMsgGetParam(msg, param, 0, NULL, &size);
    ok(ret, "%s: CryptMsgGetParam failed: %08lx\n", test, GetLastError());

    buf = malloc(size);
    ret = CryptMsgGetParam(msg, param, 0, buf, &size);
    ok(ret, "%s: CryptMsgGetParam failed: %08lx\n", test, GetLastError());
    ok(size == expectedSize, "%s: expected size %ld, got %ld\n", test,
     expectedSize, size);
    if (size == expectedSize && size)
        ok(!memcmp(buf, expected, size), "%s: unexpected data\n", test);
    free(buf);
}

static void test_data_msg_open(void)
{
    HCRYPTMSG msg;
    CMSG_HASHED_ENCODE_INFO hashInfo = { 0 };
    CMSG_STREAM_INFO streamInfo = { 0 };
    char oid[] = "1.2.3";

    /* The data message type takes no additional info */
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, &hashInfo,
     NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* An empty stream info is allowed. */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     &streamInfo);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Passing a bogus inner OID succeeds for a non-streamed message.. */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, oid,
     NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* and still succeeds when CMSG_DETACHED_FLAG is passed.. */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_DATA, NULL, oid, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* and when a stream info is given, even though you're not supposed to be
     * able to use anything but szOID_RSA_data when streaming is being used.
     */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_DATA, NULL, oid, &streamInfo);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
}

static const BYTE msgData[] = { 1, 2, 3, 4 };

static BOOL WINAPI nop_stream_output(const void *pvArg, BYTE *pb, DWORD cb,
 BOOL final)
{
    return TRUE;
}

static const BYTE dataEmptyBareContent[] = { 0x04,0x00 };

static void test_data_msg_update(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    CMSG_STREAM_INFO streamInfo = { 0 };

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     NULL);
    /* Can't update a message that wasn't opened detached with final = FALSE */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    /* Updating it with final = TRUE succeeds */
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* Any subsequent update will fail, as the last was final */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     NULL);
    /* Starting with Vista, can update a message with no data. */
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    if (ret)
    {
        DWORD size;

        ret = CryptMsgGetParam(msg, CMSG_BARE_CONTENT_PARAM, 0, NULL, &size);
        ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
        if (ret)
        {
            LPBYTE buf = CryptMemAlloc(size);

            if (buf)
            {
                ret = CryptMsgGetParam(msg, CMSG_BARE_CONTENT_PARAM, 0, buf,
                 &size);
                ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
                if (ret)
                {
                    ok(size == sizeof(dataEmptyBareContent),
                     "unexpected size %ld\n", size);
                    ok(!memcmp(buf, dataEmptyBareContent, size),
                     "unexpected value\n");
                }
                CryptMemFree(buf);
            }
        }
    }
    CryptMsgClose(msg);

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_DATA, NULL, NULL, NULL);

    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());

    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Calling update after opening with an empty stream info (with a bogus
     * output function) yields an error:
     */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     &streamInfo);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(!ret && GetLastError() == STATUS_ACCESS_VIOLATION,
     "Expected STATUS_ACCESS_VIOLATION, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Calling update with a valid output function succeeds, even if the data
     * exceeds the size specified in the stream info.
     */
    streamInfo.pfnStreamOutput = nop_stream_output;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     &streamInfo);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
}

static void test_data_msg_get_param(void)
{
    HCRYPTMSG msg;
    DWORD size;
    BOOL ret;
    CMSG_STREAM_INFO streamInfo = { 0, nop_stream_output, NULL };

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     NULL);

    /* Content and bare content are always gettable when not streaming */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_BARE_CONTENT_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    /* But for this type of message, the signer and hash aren't applicable,
     * and the type isn't available.
     */
    size = 0;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_ENCODED_SIGNER, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Can't get content or bare content when streaming */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL,
     NULL, &streamInfo);
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_BARE_CONTENT_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    CryptMsgClose(msg);
}

static const BYTE dataEmptyContent[] = {
0x30,0x0f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x02,
0x04,0x00 };
static const BYTE dataBareContent[] = { 0x04,0x04,0x01,0x02,0x03,0x04 };
static const BYTE dataContent[] = {
0x30,0x13,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x06,
0x04,0x04,0x01,0x02,0x03,0x04 };

struct update_accum
{
    DWORD cUpdates;
    CRYPT_DATA_BLOB *updates;
};

static BOOL WINAPI accumulating_stream_output(const void *pvArg, BYTE *pb,
 DWORD cb, BOOL final)
{
    struct update_accum *accum = (struct update_accum *)pvArg;
    BOOL ret = FALSE;

    if (accum->cUpdates)
        accum->updates = CryptMemRealloc(accum->updates,
         (accum->cUpdates + 1) * sizeof(CRYPT_DATA_BLOB));
    else
        accum->updates = CryptMemAlloc(sizeof(CRYPT_DATA_BLOB));
    if (accum->updates)
    {
        CRYPT_DATA_BLOB *blob = &accum->updates[accum->cUpdates];

        blob->pbData = CryptMemAlloc(cb);
        if (blob->pbData)
        {
            memcpy(blob->pbData, pb, cb);
            blob->cbData = cb;
            ret = TRUE;
        }
        accum->cUpdates++;
    }
    return ret;
}

/* The updates of a (bogus) definite-length encoded message */
static BYTE u1[] = { 0x30,0x0f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
 0x07,0x01,0xa0,0x02,0x04,0x00 };
static BYTE u2[] = { 0x01,0x02,0x03,0x04 };
static CRYPT_DATA_BLOB b1[] = {
    { sizeof(u1), u1 },
    { sizeof(u2), u2 },
    { sizeof(u2), u2 },
};
static const struct update_accum a1 = { ARRAY_SIZE(b1), b1 };
/* The updates of a definite-length encoded message */
static BYTE u3[] = { 0x30,0x13,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
 0x07,0x01,0xa0,0x06,0x04,0x04 };
static CRYPT_DATA_BLOB b2[] = {
    { sizeof(u3), u3 },
    { sizeof(u2), u2 },
};
static const struct update_accum a2 = { ARRAY_SIZE(b2), b2 };
/* The updates of an indefinite-length encoded message */
static BYTE u4[] = { 0x30,0x80,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
 0x07,0x01,0xa0,0x80,0x24,0x80 };
static BYTE u5[] = { 0x04,0x04 };
static BYTE u6[] = { 0x00,0x00,0x00,0x00,0x00,0x00 };
static CRYPT_DATA_BLOB b3[] = {
    { sizeof(u4), u4 },
    { sizeof(u5), u5 },
    { sizeof(u2), u2 },
    { sizeof(u5), u5 },
    { sizeof(u2), u2 },
    { sizeof(u6), u6 },
};
static const struct update_accum a3 = { ARRAY_SIZE(b3), b3 };

static void check_updates(LPCSTR header, const struct update_accum *expected,
 const struct update_accum *got)
{
    DWORD i;

    ok(expected->cUpdates == got->cUpdates,
     "%s: expected %ld updates, got %ld\n", header, expected->cUpdates,
     got->cUpdates);
    if (expected->cUpdates == got->cUpdates)
        for (i = 0; i < min(expected->cUpdates, got->cUpdates); i++)
        {
            ok(expected->updates[i].cbData == got->updates[i].cbData,
             "%s, update %ld: expected %ld bytes, got %ld\n", header, i,
             expected->updates[i].cbData, got->updates[i].cbData);
            if (expected->updates[i].cbData && expected->updates[i].cbData ==
             got->updates[i].cbData)
                ok(!memcmp(expected->updates[i].pbData, got->updates[i].pbData,
                 got->updates[i].cbData), "%s, update %ld: unexpected value\n",
                 header, i);
        }
}

/* Frees the updates stored in accum */
static void free_updates(struct update_accum *accum)
{
    DWORD i;

    for (i = 0; i < accum->cUpdates; i++)
        CryptMemFree(accum->updates[i].pbData);
    CryptMemFree(accum->updates);
    accum->updates = NULL;
    accum->cUpdates = 0;
}

static void test_data_msg_encoding(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    static char oid[] = "1.2.3";
    struct update_accum accum = { 0, NULL };
    CMSG_STREAM_INFO streamInfo = { 0, accumulating_stream_output, &accum };

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     NULL);
    check_param("data empty bare content", msg, CMSG_BARE_CONTENT_PARAM,
     dataEmptyBareContent, sizeof(dataEmptyBareContent));
    check_param("data empty content", msg, CMSG_CONTENT_PARAM, dataEmptyContent,
     sizeof(dataEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("data bare content", msg, CMSG_BARE_CONTENT_PARAM,
     dataBareContent, sizeof(dataBareContent));
    check_param("data content", msg, CMSG_CONTENT_PARAM, dataContent,
     sizeof(dataContent));
    CryptMsgClose(msg);
    /* Same test, but with CMSG_BARE_CONTENT_FLAG set */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_BARE_CONTENT_FLAG,
     CMSG_DATA, NULL, NULL, NULL);
    check_param("data empty bare content", msg, CMSG_BARE_CONTENT_PARAM,
     dataEmptyBareContent, sizeof(dataEmptyBareContent));
    check_param("data empty content", msg, CMSG_CONTENT_PARAM, dataEmptyContent,
     sizeof(dataEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("data bare content", msg, CMSG_BARE_CONTENT_PARAM,
     dataBareContent, sizeof(dataBareContent));
    check_param("data content", msg, CMSG_CONTENT_PARAM, dataContent,
     sizeof(dataContent));
    CryptMsgClose(msg);
    /* The inner OID is apparently ignored */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, oid,
     NULL);
    check_param("data bogus oid bare content", msg, CMSG_BARE_CONTENT_PARAM,
     dataEmptyBareContent, sizeof(dataEmptyBareContent));
    check_param("data bogus oid content", msg, CMSG_CONTENT_PARAM,
     dataEmptyContent, sizeof(dataEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("data bare content", msg, CMSG_BARE_CONTENT_PARAM,
     dataBareContent, sizeof(dataBareContent));
    check_param("data content", msg, CMSG_CONTENT_PARAM, dataContent,
     sizeof(dataContent));
    CryptMsgClose(msg);
    /* A streaming message is DER encoded if the length is not 0xffffffff, but
     * curiously, updates aren't validated to make sure they don't exceed the
     * stated length.  (The resulting output will of course fail to decode.)
     */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL,
     NULL, &streamInfo);
    CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    CryptMsgClose(msg);
    check_updates("bogus data message with definite length", &a1, &accum);
    free_updates(&accum);
    /* A valid definite-length encoding: */
    streamInfo.cbContent = sizeof(msgData);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL,
     NULL, &streamInfo);
    CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    CryptMsgClose(msg);
    check_updates("data message with definite length", &a2, &accum);
    free_updates(&accum);
    /* An indefinite-length encoding: */
    streamInfo.cbContent = 0xffffffff;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL,
     NULL, &streamInfo);
    CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    CryptMsgClose(msg);
    check_updates("data message with indefinite length", &a3, &accum);
    free_updates(&accum);
}

static void test_data_msg(void)
{
    test_data_msg_open();
    test_data_msg_update();
    test_data_msg_get_param();
    test_data_msg_encoding();
}

static void test_hash_msg_open(void)
{
    HCRYPTMSG msg;
    CMSG_HASHED_ENCODE_INFO hashInfo = { 0 };
    CMSG_STREAM_INFO streamInfo = { 0, nop_stream_output, NULL };

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    hashInfo.cbSize = sizeof(hashInfo);
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, NULL);
    ok(!msg && GetLastError() == CRYPT_E_UNKNOWN_ALGO,
     "Expected CRYPT_E_UNKNOWN_ALGO, got %lx\n", GetLastError());
    hashInfo.HashAlgorithm.pszObjId = oid_rsa_md5;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_HASHED, &hashInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_HASHED, &hashInfo, NULL, &streamInfo);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
}

static void test_hash_msg_update(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    CMSG_HASHED_ENCODE_INFO hashInfo = { sizeof(hashInfo), 0,
     { oid_rsa_md5, { 0, NULL } }, NULL };
    CMSG_STREAM_INFO streamInfo = { 0, nop_stream_output, NULL };

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_HASHED, &hashInfo, NULL, NULL);
    /* Detached hashed messages opened in non-streaming mode allow non-final
     * updates..
     */
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* including non-final updates with no data.. */
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* and final updates with no data. */
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* But no updates are allowed after the final update. */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* Non-detached messages, in contrast, don't allow non-final updates in
     * non-streaming mode.
     */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    /* Final updates (including empty ones) are allowed. */
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* And, of course, streaming mode allows non-final updates */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, &streamInfo);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* Setting pfnStreamOutput to NULL results in no error.  (In what appears
     * to be a bug, it isn't actually used - see encoding tests.)
     */
    streamInfo.pfnStreamOutput = NULL;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, &streamInfo);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
}

static const BYTE emptyHashParam[] = {
0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,
0x7e };

static void test_hash_msg_get_param(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    CMSG_HASHED_ENCODE_INFO hashInfo = { sizeof(hashInfo), 0,
     { oid_rsa_md5, { 0, NULL } }, NULL };
    DWORD size, value;
    CMSG_STREAM_INFO streamInfo = { 0, nop_stream_output, NULL };
    BYTE buf[16];

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, NULL);
    /* Content and bare content are always gettable for non-streamed messages */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_BARE_CONTENT_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    /* For an encoded hash message, the hash data aren't available */
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_HASH_DATA_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n",
     GetLastError());
    /* The hash is also available. */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(size == sizeof(buf), "Unexpected size %ld\n", size);
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 0, buf, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(size == sizeof(buf), "Unexpected size %ld\n", size);
    if (size == sizeof(buf))
        ok(!memcmp(buf, emptyHashParam, size), "Unexpected value\n");
    /* By getting the hash, further updates are not allowed */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(!ret && (GetLastError() == NTE_BAD_HASH_STATE || GetLastError() == CRYPT_E_MSG_ERROR),
       "Expected CRYPT_E_MSG_ERROR, got 0x%lx\n", GetLastError());

    /* Even after a final update, the hash data aren't available */
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_HASH_DATA_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    /* The version is also available, and should be zero for this message. */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_VERSION_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_VERSION_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    if (ret)
        ok(value == 0, "Expected version 0, got %ld\n", value);
    /* As usual, the type isn't available. */
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, NULL, &size);
    ok(!ret, "Expected failure\n");
    CryptMsgClose(msg);

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, &streamInfo);
    /* Streamed messages don't allow you to get the content or bare content. */
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_BARE_CONTENT_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    /* The hash is still available. */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(size == sizeof(buf), "Unexpected size %ld\n", size);
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 0, buf, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    if (size == sizeof(buf))
        ok(!memcmp(buf, emptyHashParam, size), "Unexpected value\n");
    /* After updating the hash, further updates aren't allowed on streamed
     * messages either.
     */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(!ret && (GetLastError() == NTE_BAD_HASH_STATE || GetLastError() == CRYPT_E_MSG_ERROR),
       "Expected CRYPT_E_MSG_ERROR, got 0x%lx\n", GetLastError());

    CryptMsgClose(msg);
}

static const BYTE hashEmptyBareContent[] = {
0x30,0x17,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0x04,0x00 };
static const BYTE hashEmptyContent[] = {
0x30,0x26,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x05,0xa0,0x19,
0x30,0x17,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0x04,0x00 };
static const BYTE hashBareContent[] = {
0x30,0x38,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,0x04,0x10,0x08,0xd6,0xc0,
0x5a,0x21,0x51,0x2a,0x79,0xa1,0xdf,0xeb,0x9d,0x2a,0x8f,0x26,0x2f };
static const BYTE hashContent[] = {
0x30,0x47,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x05,0xa0,0x3a,
0x30,0x38,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,0x04,0x10,0x08,0xd6,0xc0,
0x5a,0x21,0x51,0x2a,0x79,0xa1,0xdf,0xeb,0x9d,0x2a,0x8f,0x26,0x2f };

static const BYTE detachedHashNonFinalBareContent[] = {
0x30,0x20,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x0b,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x07,0x01,0x04,0x00 };
static const BYTE detachedHashNonFinalContent[] = {
0x30,0x2f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x05,0xa0,0x22,
0x30,0x20,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x0b,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x07,0x01,0x04,0x00 };
static const BYTE detachedHashBareContent[] = {
0x30,0x30,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x0b,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x07,0x01,0x04,0x10,0x08,0xd6,0xc0,0x5a,0x21,0x51,0x2a,0x79,0xa1,0xdf,0xeb,
0x9d,0x2a,0x8f,0x26,0x2f };
static const BYTE detachedHashContent[] = {
0x30,0x3f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x05,0xa0,0x32,
0x30,0x30,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x0b,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x07,0x01,0x04,0x10,0x08,0xd6,0xc0,0x5a,0x21,0x51,0x2a,0x79,0xa1,0xdf,0xeb,
0x9d,0x2a,0x8f,0x26,0x2f };

static void test_hash_msg_encoding(void)
{
    HCRYPTMSG msg;
    CMSG_HASHED_ENCODE_INFO hashInfo = { sizeof(hashInfo), 0 };
    BOOL ret;
    struct update_accum accum = { 0, NULL }, empty_accum = { 0, NULL };
    CMSG_STREAM_INFO streamInfo = { 0, accumulating_stream_output, &accum };

    hashInfo.HashAlgorithm.pszObjId = oid_rsa_md5;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, NULL);
    check_param("hash empty bare content", msg, CMSG_BARE_CONTENT_PARAM,
     hashEmptyBareContent, sizeof(hashEmptyBareContent));
    check_param("hash empty content", msg, CMSG_CONTENT_PARAM,
     hashEmptyContent, sizeof(hashEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("hash bare content", msg, CMSG_BARE_CONTENT_PARAM,
     hashBareContent, sizeof(hashBareContent));
    check_param("hash content", msg, CMSG_CONTENT_PARAM,
     hashContent, sizeof(hashContent));
    CryptMsgClose(msg);
    /* Same test, but with CMSG_BARE_CONTENT_FLAG set */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_BARE_CONTENT_FLAG,
     CMSG_HASHED, &hashInfo, NULL, NULL);
    check_param("hash empty bare content", msg, CMSG_BARE_CONTENT_PARAM,
     hashEmptyBareContent, sizeof(hashEmptyBareContent));
    check_param("hash empty content", msg, CMSG_CONTENT_PARAM,
     hashEmptyContent, sizeof(hashEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("hash bare content", msg, CMSG_BARE_CONTENT_PARAM,
     hashBareContent, sizeof(hashBareContent));
    check_param("hash content", msg, CMSG_CONTENT_PARAM,
     hashContent, sizeof(hashContent));
    CryptMsgClose(msg);
    /* Same test, but with CMSG_DETACHED_FLAG set */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_HASHED, &hashInfo, NULL, NULL);
    check_param("detached hash empty bare content", msg,
     CMSG_BARE_CONTENT_PARAM, hashEmptyBareContent,
     sizeof(hashEmptyBareContent));
    check_param("detached hash empty content", msg, CMSG_CONTENT_PARAM,
     hashEmptyContent, sizeof(hashEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("detached hash not final bare content", msg,
     CMSG_BARE_CONTENT_PARAM, detachedHashNonFinalBareContent,
     sizeof(detachedHashNonFinalBareContent));
    check_param("detached hash not final content", msg, CMSG_CONTENT_PARAM,
     detachedHashNonFinalContent, sizeof(detachedHashNonFinalContent));
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    check_param("detached hash bare content", msg, CMSG_BARE_CONTENT_PARAM,
     detachedHashBareContent, sizeof(detachedHashBareContent));
    check_param("detached hash content", msg, CMSG_CONTENT_PARAM,
     detachedHashContent, sizeof(detachedHashContent));
    check_param("detached hash bare content", msg, CMSG_BARE_CONTENT_PARAM,
     detachedHashBareContent, sizeof(detachedHashBareContent));
    check_param("detached hash content", msg, CMSG_CONTENT_PARAM,
     detachedHashContent, sizeof(detachedHashContent));
    CryptMsgClose(msg);
    /* In what appears to be a bug, streamed updates to hash messages don't
     * call the output function.
     */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, &streamInfo);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    check_updates("empty hash message", &empty_accum, &accum);
    free_updates(&accum);

    streamInfo.cbContent = sizeof(msgData);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, &streamInfo);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    check_updates("hash message", &empty_accum, &accum);
    free_updates(&accum);

    streamInfo.cbContent = sizeof(msgData);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_HASHED, &hashInfo, NULL, &streamInfo);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    check_updates("detached hash message", &empty_accum, &accum);
    free_updates(&accum);
}

static void test_hash_msg(void)
{
    test_hash_msg_open();
    test_hash_msg_update();
    test_hash_msg_get_param();
    test_hash_msg_encoding();
}

static const CHAR cspNameA[] = { 'W','i','n','e','C','r','y','p','t','T','e',
 'm','p',0 };
static BYTE serialNum[] = { 1 };
static BYTE encodedCommonName[] = { 0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,
 0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00 };

static void test_signed_msg_open(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    CMSG_SIGNED_ENCODE_INFO signInfo = { 0 };
    CMSG_SIGNER_ENCODE_INFO signer = { sizeof(signer), 0 };
    CERT_INFO certInfo = { 0 };

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got %lx\n", GetLastError());
    signInfo.cbSize = sizeof(signInfo);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    signInfo.cSigners = 1;
    signInfo.rgSigners = &signer;
    /* With signer.pCertInfo unset, attempting to open this message this
     * crashes.
     */
    signer.pCertInfo = &certInfo;
    /* The cert info must contain a serial number and an issuer. */
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    /* NT: E_INVALIDARG, 9x: unchanged or CRYPT_E_UNKNOWN_ALGO */
    ok(!msg && (GetLastError() == E_INVALIDARG || GetLastError() == 0xdeadbeef
     || GetLastError() == CRYPT_E_UNKNOWN_ALGO),
     "Expected E_INVALIDARG or 0xdeadbeef or CRYPT_E_UNKNOWN_ALGO, got 0x%lx\n",
     GetLastError());

    certInfo.SerialNumber.cbData = sizeof(serialNum);
    certInfo.SerialNumber.pbData = serialNum;
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "Expected E_INVALIDARG, got 0x%lx\n", GetLastError());

    certInfo.Issuer.cbData = sizeof(encodedCommonName);
    certInfo.Issuer.pbData = encodedCommonName;
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(!msg && (GetLastError() == E_INVALIDARG || GetLastError() == CRYPT_E_UNKNOWN_ALGO),
     "Expected E_INVALIDARG or CRYPT_E_UNKNOWN_ALGO, got %lx\n", GetLastError());

    /* The signer's hCryptProv must be set to something.  Whether it's usable
     * or not will be checked after the hash algorithm is checked (see next
     * test.)
     */
    signer.hCryptProv = 1;
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(!msg && GetLastError() == CRYPT_E_UNKNOWN_ALGO,
     "Expected CRYPT_E_UNKNOWN_ALGO, got %lx\n", GetLastError());
    /* The signer's hash algorithm must also be set. */
    signer.HashAlgorithm.pszObjId = oid_rsa_md5;
    SetLastError(0xdeadbeef);
    /* Crashes in advapi32 in wine, don't do it */
    if (0) {
        msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED,
         &signInfo, NULL, NULL);
        ok(!msg && GetLastError() == ERROR_INVALID_PARAMETER,
         "Expected ERROR_INVALID_PARAMETER, got %lx\n", GetLastError());
    }
    /* The signer's hCryptProv must also be valid. */
    ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
                                PROV_RSA_FULL, CRYPT_NEWKEYSET);
    if (!ret && GetLastError() == NTE_EXISTS) {
        ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
                                    PROV_RSA_FULL, 0);
    }
    ok(ret, "CryptAcquireContext failed: 0x%lx\n", GetLastError());

    if (ret) {
        msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
                                   NULL, NULL);
        ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
        CryptMsgClose(msg);
    }

    /* pCertInfo must still be set, but can be empty if the SignerId's issuer
     * and serial number are set.
     */
    certInfo.Issuer.cbData = 0;
    certInfo.SerialNumber.cbData = 0;
    signer.SignerId.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;
    signer.SignerId.IssuerSerialNumber.Issuer.cbData = sizeof(encodedCommonName);
    signer.SignerId.IssuerSerialNumber.Issuer.pbData = encodedCommonName;
    signer.SignerId.IssuerSerialNumber.SerialNumber.cbData = sizeof(serialNum);
    signer.SignerId.IssuerSerialNumber.SerialNumber.pbData = serialNum;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    CryptReleaseContext(signer.hCryptProv, 0);
    CryptAcquireContextA(&signer.hCryptProv, cspNameA, MS_DEF_PROV_A,
     PROV_RSA_FULL, CRYPT_DELETEKEYSET);
}

static const BYTE privKey[] = {
 0x07, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x52, 0x53, 0x41, 0x32, 0x00,
 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x79, 0x10, 0x1c, 0xd0, 0x6b, 0x10,
 0x18, 0x30, 0x94, 0x61, 0xdc, 0x0e, 0xcb, 0x96, 0x4e, 0x21, 0x3f, 0x79, 0xcd,
 0xa9, 0x17, 0x62, 0xbc, 0xbb, 0x61, 0x4c, 0xe0, 0x75, 0x38, 0x6c, 0xf3, 0xde,
 0x60, 0x86, 0x03, 0x97, 0x65, 0xeb, 0x1e, 0x6b, 0xdb, 0x53, 0x85, 0xad, 0x68,
 0x21, 0xf1, 0x5d, 0xe7, 0x1f, 0xe6, 0x53, 0xb4, 0xbb, 0x59, 0x3e, 0x14, 0x27,
 0xb1, 0x83, 0xa7, 0x3a, 0x54, 0xe2, 0x8f, 0x65, 0x8e, 0x6a, 0x4a, 0xcf, 0x3b,
 0x1f, 0x65, 0xff, 0xfe, 0xf1, 0x31, 0x3a, 0x37, 0x7a, 0x8b, 0xcb, 0xc6, 0xd4,
 0x98, 0x50, 0x36, 0x67, 0xe4, 0xa1, 0xe8, 0x7e, 0x8a, 0xc5, 0x23, 0xf2, 0x77,
 0xf5, 0x37, 0x61, 0x49, 0x72, 0x59, 0xe8, 0x3d, 0xf7, 0x60, 0xb2, 0x77, 0xca,
 0x78, 0x54, 0x6d, 0x65, 0x9e, 0x03, 0x97, 0x1b, 0x61, 0xbd, 0x0c, 0xd8, 0x06,
 0x63, 0xe2, 0xc5, 0x48, 0xef, 0xb3, 0xe2, 0x6e, 0x98, 0x7d, 0xbd, 0x4e, 0x72,
 0x91, 0xdb, 0x31, 0x57, 0xe3, 0x65, 0x3a, 0x49, 0xca, 0xec, 0xd2, 0x02, 0x4e,
 0x22, 0x7e, 0x72, 0x8e, 0xf9, 0x79, 0x84, 0x82, 0xdf, 0x7b, 0x92, 0x2d, 0xaf,
 0xc9, 0xe4, 0x33, 0xef, 0x89, 0x5c, 0x66, 0x99, 0xd8, 0x80, 0x81, 0x47, 0x2b,
 0xb1, 0x66, 0x02, 0x84, 0x59, 0x7b, 0xc3, 0xbe, 0x98, 0x45, 0x4a, 0x3d, 0xdd,
 0xea, 0x2b, 0xdf, 0x4e, 0xb4, 0x24, 0x6b, 0xec, 0xe7, 0xd9, 0x0c, 0x45, 0xb8,
 0xbe, 0xca, 0x69, 0x37, 0x92, 0x4c, 0x38, 0x6b, 0x96, 0x6d, 0xcd, 0x86, 0x67,
 0x5c, 0xea, 0x54, 0x94, 0xa4, 0xca, 0xa4, 0x02, 0xa5, 0x21, 0x4d, 0xae, 0x40,
 0x8f, 0x9d, 0x51, 0x83, 0xf2, 0x3f, 0x33, 0xc1, 0x72, 0xb4, 0x1d, 0x94, 0x6e,
 0x7d, 0xe4, 0x27, 0x3f, 0xea, 0xff, 0xe5, 0x9b, 0xa7, 0x5e, 0x55, 0x8e, 0x0d,
 0x69, 0x1c, 0x7a, 0xff, 0x81, 0x9d, 0x53, 0x52, 0x97, 0x9a, 0x76, 0x79, 0xda,
 0x93, 0x32, 0x16, 0xec, 0x69, 0x51, 0x1a, 0x4e, 0xc3, 0xf1, 0x72, 0x80, 0x78,
 0x5e, 0x66, 0x4a, 0x8d, 0x85, 0x2f, 0x3f, 0xb2, 0xa7 };
static BYTE pubKey[] = {
0x30,0x48,0x02,0x41,0x00,0xe2,0x54,0x3a,0xa7,0x83,0xb1,0x27,0x14,0x3e,0x59,
0xbb,0xb4,0x53,0xe6,0x1f,0xe7,0x5d,0xf1,0x21,0x68,0xad,0x85,0x53,0xdb,0x6b,
0x1e,0xeb,0x65,0x97,0x03,0x86,0x60,0xde,0xf3,0x6c,0x38,0x75,0xe0,0x4c,0x61,
0xbb,0xbc,0x62,0x17,0xa9,0xcd,0x79,0x3f,0x21,0x4e,0x96,0xcb,0x0e,0xdc,0x61,
0x94,0x30,0x18,0x10,0x6b,0xd0,0x1c,0x10,0x79,0x02,0x03,0x01,0x00,0x01 };

static void test_signed_msg_update(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    CMSG_SIGNED_ENCODE_INFO signInfo = { sizeof(signInfo), 0 };
    CMSG_SIGNER_ENCODE_INFO signer = { sizeof(signer), 0 };
    CERT_INFO certInfo = { 0 };
    HCRYPTKEY key;

    certInfo.SerialNumber.cbData = sizeof(serialNum);
    certInfo.SerialNumber.pbData = serialNum;
    certInfo.Issuer.cbData = sizeof(encodedCommonName);
    certInfo.Issuer.pbData = encodedCommonName;
    signer.pCertInfo = &certInfo;
    signer.HashAlgorithm.pszObjId = oid_rsa_md5;
    signInfo.cSigners = 1;
    signInfo.rgSigners = &signer;

    ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
                                PROV_RSA_FULL, CRYPT_NEWKEYSET);
    if (!ret && GetLastError() == NTE_EXISTS) {
        ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
                                    PROV_RSA_FULL, 0);
    }
    ok(ret, "CryptAcquireContext failed: 0x%lx\n", GetLastError());

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING,
     CMSG_DETACHED_FLAG, CMSG_SIGNED, &signInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    /* Detached CMSG_SIGNED allows non-final updates. */
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* Detached CMSG_SIGNED also allows non-final updates with no data. */
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* The final update requires a private key in the hCryptProv, in order to
     * generate the signature.
     */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(!ret && (GetLastError() == NTE_BAD_KEYSET || GetLastError() == NTE_NO_KEY),
     "Expected NTE_BAD_KEYSET or NTE_NO_KEY, got %lx\n", GetLastError());
    ret = CryptImportKey(signer.hCryptProv, privKey, sizeof(privKey),
     0, 0, &key);
    ok(ret, "CryptImportKey failed: %08lx\n", GetLastError());
    /* The final update should be able to succeed now that a key exists, but
     * the previous (invalid) final update prevents it.
     */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING,
     CMSG_DETACHED_FLAG, CMSG_SIGNED, &signInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    /* Detached CMSG_SIGNED allows non-final updates. */
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* Detached CMSG_SIGNED also allows non-final updates with no data. */
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* Now that the private key exists, the final update can succeed (even
     * with no data.)
     */
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* But no updates are allowed after the final update. */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    /* Non-detached messages don't allow non-final updates.. */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    /* but they do allow final ones. */
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    /* They also allow final updates with no data. */
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    CryptDestroyKey(key);
    CryptReleaseContext(signer.hCryptProv, 0);
    CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
}

static const BYTE unsignedEmptyBareContent[] = {
0x30,0x0b,0x02,0x01,0x01,0x31,0x00,0x30,0x02,0x06,0x00,0x31,0x00 };
static const BYTE unsignedEmptyContent[] = {
0x30,0x1a,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,0xa0,0x0d,
0x30,0x0b,0x02,0x01,0x01,0x31,0x00,0x30,0x02,0x06,0x00,0x31,0x00 };
static const BYTE detachedUnsignedBareContent[] = {
0x30,0x14,0x02,0x01,0x01,0x31,0x00,0x30,0x0b,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x07,0x01,0x31,0x00 };
static const BYTE detachedUnsignedContent[] = {
0x30,0x23,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,0xa0,0x16,
0x30,0x14,0x02,0x01,0x01,0x31,0x00,0x30,0x0b,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x07,0x01,0x31,0x00 };
static const BYTE signedEmptyBareContent[] = {
0x30,0x50,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0x31,0x37,0x30,0x35,0x02,
0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,
0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,
0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,
0x04,0x06,0x00,0x05,0x00,0x04,0x00 };
static const BYTE signedEmptyContent[] = {
0x30,0x5f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,0xa0,0x52,
0x30,0x50,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0x31,0x37,0x30,0x35,0x02,
0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,
0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,
0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,
0x04,0x06,0x00,0x05,0x00,0x04,0x00 };
static const BYTE detachedSignedBareContent[] = {
0x30,0x81,0x99,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x0b,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x07,0x01,0x31,0x77,0x30,0x75,0x02,0x01,0x01,0x30,0x1a,0x30,
0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,
0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,
0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,
0x04,0x40,0x81,0xa6,0x70,0xb3,0xef,0x59,0xd1,0x66,0xd1,0x9b,0xc0,0x9a,0xb6,
0x9a,0x5e,0x6d,0x6f,0x6d,0x0d,0x59,0xa9,0xaa,0x6e,0xe9,0x2c,0xa0,0x1e,0xee,
0xc2,0x60,0xbc,0x59,0xbe,0x3f,0x63,0x06,0x8d,0xc9,0x11,0x1d,0x23,0x64,0x92,
0xef,0x2e,0xfc,0x57,0x29,0xa4,0xaf,0xe0,0xee,0x93,0x19,0x39,0x51,0xe4,0x44,
0xb8,0x0b,0x28,0xf4,0xa8,0x0d };
static const BYTE detachedSignedContent[] = {
0x30,0x81,0xaa,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,0xa0,
0x81,0x9c,0x30,0x81,0x99,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,
0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x0b,0x06,0x09,0x2a,0x86,
0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0x31,0x77,0x30,0x75,0x02,0x01,0x01,0x30,
0x1a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,
0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,
0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,
0x05,0x00,0x04,0x40,0x81,0xa6,0x70,0xb3,0xef,0x59,0xd1,0x66,0xd1,0x9b,0xc0,
0x9a,0xb6,0x9a,0x5e,0x6d,0x6f,0x6d,0x0d,0x59,0xa9,0xaa,0x6e,0xe9,0x2c,0xa0,
0x1e,0xee,0xc2,0x60,0xbc,0x59,0xbe,0x3f,0x63,0x06,0x8d,0xc9,0x11,0x1d,0x23,
0x64,0x92,0xef,0x2e,0xfc,0x57,0x29,0xa4,0xaf,0xe0,0xee,0x93,0x19,0x39,0x51,
0xe4,0x44,0xb8,0x0b,0x28,0xf4,0xa8,0x0d };
static const BYTE signedBareContent[] = {
0x30,0x81,0xa1,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,0x31,0x77,
0x30,0x75,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,
0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,
0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,
0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,0x40,0x81,0xa6,0x70,0xb3,0xef,
0x59,0xd1,0x66,0xd1,0x9b,0xc0,0x9a,0xb6,0x9a,0x5e,0x6d,0x6f,0x6d,0x0d,0x59,
0xa9,0xaa,0x6e,0xe9,0x2c,0xa0,0x1e,0xee,0xc2,0x60,0xbc,0x59,0xbe,0x3f,0x63,
0x06,0x8d,0xc9,0x11,0x1d,0x23,0x64,0x92,0xef,0x2e,0xfc,0x57,0x29,0xa4,0xaf,
0xe0,0xee,0x93,0x19,0x39,0x51,0xe4,0x44,0xb8,0x0b,0x28,0xf4,0xa8,0x0d };
static const BYTE signedContent[] = {
0x30,0x81,0xb2,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,0xa0,
0x81,0xa4,0x30,0x81,0xa1,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,
0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,
0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,
0x31,0x77,0x30,0x75,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,0x40,0x81,0xa6,0x70,
0xb3,0xef,0x59,0xd1,0x66,0xd1,0x9b,0xc0,0x9a,0xb6,0x9a,0x5e,0x6d,0x6f,0x6d,
0x0d,0x59,0xa9,0xaa,0x6e,0xe9,0x2c,0xa0,0x1e,0xee,0xc2,0x60,0xbc,0x59,0xbe,
0x3f,0x63,0x06,0x8d,0xc9,0x11,0x1d,0x23,0x64,0x92,0xef,0x2e,0xfc,0x57,0x29,
0xa4,0xaf,0xe0,0xee,0x93,0x19,0x39,0x51,0xe4,0x44,0xb8,0x0b,0x28,0xf4,0xa8,
0x0d };
static const BYTE signedHash[] = {
0x08,0xd6,0xc0,0x5a,0x21,0x51,0x2a,0x79,0xa1,0xdf,0xeb,0x9d,0x2a,0x8f,0x26,
0x2f };
static const BYTE signedKeyIdEmptyContent[] = {
0x30,0x46,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,0xa0,0x39,
0x30,0x37,0x02,0x01,0x03,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0x31,0x1e,0x30,0x1c,0x02,
0x01,0x03,0x80,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,0x00 };
static const BYTE signedEncodedSigner[] = {
0x30,0x75,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,
0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,
0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,
0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,0x40,0x81,0xa6,0x70,0xb3,0xef,
0x59,0xd1,0x66,0xd1,0x9b,0xc0,0x9a,0xb6,0x9a,0x5e,0x6d,0x6f,0x6d,0x0d,0x59,
0xa9,0xaa,0x6e,0xe9,0x2c,0xa0,0x1e,0xee,0xc2,0x60,0xbc,0x59,0xbe,0x3f,0x63,
0x06,0x8d,0xc9,0x11,0x1d,0x23,0x64,0x92,0xef,0x2e,0xfc,0x57,0x29,0xa4,0xaf,
0xe0,0xee,0x93,0x19,0x39,0x51,0xe4,0x44,0xb8,0x0b,0x28,0xf4,0xa8,0x0d };
static const BYTE signedWithAuthAttrsBareContent[] = {
0x30,0x82,0x01,0x00,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,
0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,0x31,
0x81,0xd5,0x30,0x81,0xd2,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,
0x0d,0x02,0x05,0x05,0x00,0xa0,0x5b,0x30,0x18,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x09,0x03,0x31,0x0b,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x01,0x07,0x01,0x30,0x1e,0x06,0x03,0x55,0x04,0x03,0x31,0x17,0x30,0x15,0x31,
0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,
0x4c,0x61,0x6e,0x67,0x00,0x30,0x1f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x01,0x09,0x04,0x31,0x12,0x04,0x10,0x08,0xd6,0xc0,0x5a,0x21,0x51,0x2a,0x79,
0xa1,0xdf,0xeb,0x9d,0x2a,0x8f,0x26,0x2f,0x30,0x04,0x06,0x00,0x05,0x00,0x04,
0x40,0xbf,0x65,0xde,0x7a,0x3e,0xa2,0x19,0x59,0xc3,0xc7,0x02,0x53,0xc9,0x72,
0xcd,0x74,0x96,0x70,0x0b,0x3b,0xcf,0x8b,0xd9,0x17,0x5c,0xc5,0xd1,0x83,0x41,
0x32,0x93,0xa6,0xf3,0x52,0x83,0x94,0xa9,0x6b,0x0a,0x92,0xcf,0xaf,0x12,0xfa,
0x40,0x53,0x12,0x84,0x03,0xab,0x10,0xa2,0x3d,0xe6,0x9f,0x5a,0xbf,0xc5,0xb8,
0xff,0xc6,0x33,0x63,0x34 };
static BYTE cert[] = {
0x30,0x7a,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,
0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,
0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,
0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,
0x00,0x30,0x07,0x30,0x02,0x06,0x00,0x03,0x01,0x00,0xa3,0x16,0x30,0x14,0x30,
0x12,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,
0xff,0x02,0x01,0x01 };
static BYTE v1CertWithPubKey[] = {
0x30,0x81,0x95,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,
0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,
0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x01,0x01,0x05,0x00,0x03,0x11,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xa3,0x16,0x30,0x14,0x30,0x12,0x06,
0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,0xff,0x02,
0x01,0x01 };
static const BYTE signedWithCertEmptyBareContent[] = {
0x30,0x81,0xce,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0xa0,0x7c,0x30,0x7a,
0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,
0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,
0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,
0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,
0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,
0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x30,
0x07,0x30,0x02,0x06,0x00,0x03,0x01,0x00,0xa3,0x16,0x30,0x14,0x30,0x12,0x06,
0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,0xff,0x02,
0x01,0x01,0x31,0x37,0x30,0x35,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,
0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,
0x61,0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,0x00 };
static const BYTE signedWithCertBareContent[] = {
0x30,0x82,0x01,0x1f,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,
0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,0xa0,
0x7c,0x30,0x7a,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,
0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,
0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x07,0x30,0x02,0x06,0x00,0x03,0x01,0x00,0xa3,0x16,0x30,0x14,
0x30,0x12,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,
0x01,0xff,0x02,0x01,0x01,0x31,0x77,0x30,0x75,0x02,0x01,0x01,0x30,0x1a,0x30,
0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,
0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,
0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,
0x04,0x40,0x81,0xa6,0x70,0xb3,0xef,0x59,0xd1,0x66,0xd1,0x9b,0xc0,0x9a,0xb6,
0x9a,0x5e,0x6d,0x6f,0x6d,0x0d,0x59,0xa9,0xaa,0x6e,0xe9,0x2c,0xa0,0x1e,0xee,
0xc2,0x60,0xbc,0x59,0xbe,0x3f,0x63,0x06,0x8d,0xc9,0x11,0x1d,0x23,0x64,0x92,
0xef,0x2e,0xfc,0x57,0x29,0xa4,0xaf,0xe0,0xee,0x93,0x19,0x39,0x51,0xe4,0x44,
0xb8,0x0b,0x28,0xf4,0xa8,0x0d };
static BYTE crl[] = { 0x30,0x2c,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,
0x30,0x30,0x30,0x30,0x5a };
static const BYTE signedWithCrlEmptyBareContent[] = {
0x30,0x81,0x80,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0xa1,0x2e,0x30,0x2c,
0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,
0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x18,0x0f,0x31,
0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x31,
0x37,0x30,0x35,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,
0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,
0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,
0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,0x00 };
static const BYTE signedWithCrlBareContent[] = {
0x30,0x81,0xd1,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,0xa1,0x2e,
0x30,0x2c,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,
0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x18,
0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,
0x5a,0x31,0x77,0x30,0x75,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,
0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,0x40,0x81,0xa6,
0x70,0xb3,0xef,0x59,0xd1,0x66,0xd1,0x9b,0xc0,0x9a,0xb6,0x9a,0x5e,0x6d,0x6f,
0x6d,0x0d,0x59,0xa9,0xaa,0x6e,0xe9,0x2c,0xa0,0x1e,0xee,0xc2,0x60,0xbc,0x59,
0xbe,0x3f,0x63,0x06,0x8d,0xc9,0x11,0x1d,0x23,0x64,0x92,0xef,0x2e,0xfc,0x57,
0x29,0xa4,0xaf,0xe0,0xee,0x93,0x19,0x39,0x51,0xe4,0x44,0xb8,0x0b,0x28,0xf4,
0xa8,0x0d };
static const BYTE signedWithCertAndCrlEmptyBareContent[] = {
0x30,0x81,0xfe,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0xa0,0x7c,0x30,0x7a,
0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,
0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,
0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,
0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,
0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,
0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x30,
0x07,0x30,0x02,0x06,0x00,0x03,0x01,0x00,0xa3,0x16,0x30,0x14,0x30,0x12,0x06,
0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,0xff,0x02,
0x01,0x01,0xa1,0x2e,0x30,0x2c,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,
0x30,0x30,0x30,0x30,0x5a,0x31,0x37,0x30,0x35,0x02,0x01,0x01,0x30,0x1a,0x30,
0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,
0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,
0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,
0x04,0x00 };
static const BYTE signedWithCertAndCrlBareContent[] = {
0x30,0x82,0x01,0x4f,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,
0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,0xa0,
0x7c,0x30,0x7a,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,
0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,
0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x07,0x30,0x02,0x06,0x00,0x03,0x01,0x00,0xa3,0x16,0x30,0x14,
0x30,0x12,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,
0x01,0xff,0x02,0x01,0x01,0xa1,0x2e,0x30,0x2c,0x30,0x02,0x06,0x00,0x30,0x15,
0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,
0x20,0x4c,0x61,0x6e,0x67,0x00,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,
0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x31,0x77,0x30,0x75,0x02,0x01,0x01,
0x30,0x1a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,
0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,
0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,
0x00,0x05,0x00,0x04,0x40,0x81,0xa6,0x70,0xb3,0xef,0x59,0xd1,0x66,0xd1,0x9b,
0xc0,0x9a,0xb6,0x9a,0x5e,0x6d,0x6f,0x6d,0x0d,0x59,0xa9,0xaa,0x6e,0xe9,0x2c,
0xa0,0x1e,0xee,0xc2,0x60,0xbc,0x59,0xbe,0x3f,0x63,0x06,0x8d,0xc9,0x11,0x1d,
0x23,0x64,0x92,0xef,0x2e,0xfc,0x57,0x29,0xa4,0xaf,0xe0,0xee,0x93,0x19,0x39,
0x51,0xe4,0x44,0xb8,0x0b,0x28,0xf4,0xa8,0x0d };
static const BYTE signedWithCertWithPubKeyBareContent[] = {
0x30,0x81,0xeb,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x02,0x06,0x00,0xa0,0x81,0x98,0x30,
0x81,0x95,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,
0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,
0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,0x06,
0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,
0x00,0x30,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,
0x01,0x05,0x00,0x03,0x11,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xa3,0x16,0x30,0x14,0x30,0x12,0x06,0x03,
0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,0xff,0x02,0x01,
0x01,0x31,0x37,0x30,0x35,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,
0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,0x00 };
static BYTE v1CertWithValidPubKey[] = {
0x30,0x81,0xcf,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,0x15,0x31,0x13,0x30,
0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,
0x6e,0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,
0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,0x30,0x31,0x30,0x31,
0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,0x31,0x13,0x30,0x11,
0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,
0x67,0x00,0x30,0x5c,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x01,0x01,0x05,0x00,0x03,0x4b,0x00,0x30,0x48,0x02,0x41,0x00,0xe2,0x54,0x3a,
0xa7,0x83,0xb1,0x27,0x14,0x3e,0x59,0xbb,0xb4,0x53,0xe6,0x1f,0xe7,0x5d,0xf1,
0x21,0x68,0xad,0x85,0x53,0xdb,0x6b,0x1e,0xeb,0x65,0x97,0x03,0x86,0x60,0xde,
0xf3,0x6c,0x38,0x75,0xe0,0x4c,0x61,0xbb,0xbc,0x62,0x17,0xa9,0xcd,0x79,0x3f,
0x21,0x4e,0x96,0xcb,0x0e,0xdc,0x61,0x94,0x30,0x18,0x10,0x6b,0xd0,0x1c,0x10,
0x79,0x02,0x03,0x01,0x00,0x01,0xa3,0x16,0x30,0x14,0x30,0x12,0x06,0x03,0x55,
0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,0xff,0x02,0x01,0x01 };
static const BYTE signedWithCertWithValidPubKeyEmptyContent[] = {
0x30,0x82,0x01,0x38,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,
0xa0,0x82,0x01,0x29,0x30,0x82,0x01,0x25,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,
0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x02,0x06,
0x00,0xa0,0x81,0xd2,0x30,0x81,0xcf,0x02,0x01,0x01,0x30,0x02,0x06,0x00,0x30,
0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,
0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,0x30,0x31,
0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,0x31,0x36,
0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x15,
0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,
0x20,0x4c,0x61,0x6e,0x67,0x00,0x30,0x5c,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,
0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x4b,0x00,0x30,0x48,0x02,0x41,
0x00,0xe2,0x54,0x3a,0xa7,0x83,0xb1,0x27,0x14,0x3e,0x59,0xbb,0xb4,0x53,0xe6,
0x1f,0xe7,0x5d,0xf1,0x21,0x68,0xad,0x85,0x53,0xdb,0x6b,0x1e,0xeb,0x65,0x97,
0x03,0x86,0x60,0xde,0xf3,0x6c,0x38,0x75,0xe0,0x4c,0x61,0xbb,0xbc,0x62,0x17,
0xa9,0xcd,0x79,0x3f,0x21,0x4e,0x96,0xcb,0x0e,0xdc,0x61,0x94,0x30,0x18,0x10,
0x6b,0xd0,0x1c,0x10,0x79,0x02,0x03,0x01,0x00,0x01,0xa3,0x16,0x30,0x14,0x30,
0x12,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,0x01,0x01,
0xff,0x02,0x01,0x01,0x31,0x37,0x30,0x35,0x02,0x01,0x01,0x30,0x1a,0x30,0x15,
0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,0x61,0x6e,
0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,
0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,0x00,0x04,
0x00 };
static const BYTE signedWithCertWithValidPubKeyContent[] = {
0x30,0x82,0x01,0x89,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,
0xa0,0x82,0x01,0x7a,0x30,0x82,0x01,0x76,0x02,0x01,0x01,0x31,0x0e,0x30,0x0c,
0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x13,0x06,
0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0xa0,0x06,0x04,0x04,0x01,
0x02,0x03,0x04,0xa0,0x81,0xd2,0x30,0x81,0xcf,0x02,0x01,0x01,0x30,0x02,0x06,
0x00,0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,
0x75,0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x30,0x22,0x18,0x0f,0x31,0x36,
0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x18,0x0f,
0x31,0x36,0x30,0x31,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,
0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,
0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x30,0x5c,0x30,0x0d,0x06,0x09,0x2a,
0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x4b,0x00,0x30,0x48,
0x02,0x41,0x00,0xe2,0x54,0x3a,0xa7,0x83,0xb1,0x27,0x14,0x3e,0x59,0xbb,0xb4,
0x53,0xe6,0x1f,0xe7,0x5d,0xf1,0x21,0x68,0xad,0x85,0x53,0xdb,0x6b,0x1e,0xeb,
0x65,0x97,0x03,0x86,0x60,0xde,0xf3,0x6c,0x38,0x75,0xe0,0x4c,0x61,0xbb,0xbc,
0x62,0x17,0xa9,0xcd,0x79,0x3f,0x21,0x4e,0x96,0xcb,0x0e,0xdc,0x61,0x94,0x30,
0x18,0x10,0x6b,0xd0,0x1c,0x10,0x79,0x02,0x03,0x01,0x00,0x01,0xa3,0x16,0x30,
0x14,0x30,0x12,0x06,0x03,0x55,0x1d,0x13,0x01,0x01,0xff,0x04,0x08,0x30,0x06,
0x01,0x01,0xff,0x02,0x01,0x01,0x31,0x77,0x30,0x75,0x02,0x01,0x01,0x30,0x1a,
0x30,0x15,0x31,0x13,0x30,0x11,0x06,0x03,0x55,0x04,0x03,0x13,0x0a,0x4a,0x75,
0x61,0x6e,0x20,0x4c,0x61,0x6e,0x67,0x00,0x02,0x01,0x01,0x30,0x0c,0x06,0x08,
0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x30,0x04,0x06,0x00,0x05,
0x00,0x04,0x40,0x81,0xa6,0x70,0xb3,0xef,0x59,0xd1,0x66,0xd1,0x9b,0xc0,0x9a,
0xb6,0x9a,0x5e,0x6d,0x6f,0x6d,0x0d,0x59,0xa9,0xaa,0x6e,0xe9,0x2c,0xa0,0x1e,
0xee,0xc2,0x60,0xbc,0x59,0xbe,0x3f,0x63,0x06,0x8d,0xc9,0x11,0x1d,0x23,0x64,
0x92,0xef,0x2e,0xfc,0x57,0x29,0xa4,0xaf,0xe0,0xee,0x93,0x19,0x39,0x51,0xe4,
0x44,0xb8,0x0b,0x28,0xf4,0xa8,0x0d };

static void test_signed_msg_encoding(void)
{
    HCRYPTMSG msg;
    CMSG_SIGNED_ENCODE_INFO signInfo = { sizeof(signInfo), 0 };
    CMSG_SIGNER_ENCODE_INFO signer = { sizeof(signer), 0 };
    CERT_INFO certInfo = { 0 };
    CERT_BLOB encodedCert = { sizeof(cert), cert };
    CRL_BLOB encodedCrl = { sizeof(crl), crl };
    char oid_common_name[] = szOID_COMMON_NAME;
    CRYPT_ATTR_BLOB commonName = { sizeof(encodedCommonName),
     encodedCommonName };
    CRYPT_ATTRIBUTE attr = { oid_common_name, 1, &commonName };
    BOOL ret;
    HCRYPTKEY key;
    DWORD size;

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING,
     CMSG_DETACHED_FLAG, CMSG_SIGNED, &signInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    check_param("detached unsigned empty bare content", msg,
     CMSG_BARE_CONTENT_PARAM, unsignedEmptyBareContent,
     sizeof(unsignedEmptyBareContent));
    check_param("detached unsigned empty content", msg, CMSG_CONTENT_PARAM,
     unsignedEmptyContent, sizeof(unsignedEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("detached unsigned bare content", msg, CMSG_BARE_CONTENT_PARAM,
     detachedUnsignedBareContent, sizeof(detachedUnsignedBareContent));
    check_param("detached unsigned content", msg, CMSG_CONTENT_PARAM,
     detachedUnsignedContent, sizeof(detachedUnsignedContent));
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "Expected CRYPT_E_INVALID_INDEX, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_ENCODED_SIGNER, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "Expected CRYPT_E_INVALID_INDEX, got %lx\n", GetLastError());

    CryptMsgClose(msg);

    certInfo.SerialNumber.cbData = sizeof(serialNum);
    certInfo.SerialNumber.pbData = serialNum;
    certInfo.Issuer.cbData = sizeof(encodedCommonName);
    certInfo.Issuer.pbData = encodedCommonName;
    signer.pCertInfo = &certInfo;
    signer.HashAlgorithm.pszObjId = oid_rsa_md5;
    signInfo.cSigners = 1;
    signInfo.rgSigners = &signer;

    ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
                                PROV_RSA_FULL, CRYPT_NEWKEYSET);
    if (!ret && GetLastError() == NTE_EXISTS) {
        ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
                                    PROV_RSA_FULL, 0);
    }
    ok(ret, "CryptAcquireContext failed: 0x%lx\n", GetLastError());

    ret = CryptImportKey(signer.hCryptProv, privKey, sizeof(privKey),
     0, 0, &key);
    ok(ret, "CryptImportKey failed: %08lx\n", GetLastError());

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING,
     CMSG_DETACHED_FLAG, CMSG_SIGNED, &signInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    check_param("detached signed empty bare content", msg,
     CMSG_BARE_CONTENT_PARAM, signedEmptyBareContent,
     sizeof(signedEmptyBareContent));
    check_param("detached signed empty content", msg, CMSG_CONTENT_PARAM,
     signedEmptyContent, sizeof(signedEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("detached signed hash", msg, CMSG_COMPUTED_HASH_PARAM,
     signedHash, sizeof(signedHash));
    check_param("detached signed bare content", msg, CMSG_BARE_CONTENT_PARAM,
     detachedSignedBareContent, sizeof(detachedSignedBareContent));
    check_param("detached signed content", msg, CMSG_CONTENT_PARAM,
     detachedSignedContent, sizeof(detachedSignedContent));
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 1, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "Expected CRYPT_E_INVALID_INDEX, got %lx\n", GetLastError());
    check_param("detached signed encoded signer", msg, CMSG_ENCODED_SIGNER,
     signedEncodedSigner, sizeof(signedEncodedSigner));

    CryptMsgClose(msg);

    certInfo.SerialNumber.cbData = 0;
    certInfo.Issuer.cbData = 0;
    signer.SignerId.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
    signer.SignerId.KeyId.cbData = sizeof(serialNum);
    signer.SignerId.KeyId.pbData = serialNum;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    check_param("signed key id empty content", msg, CMSG_CONTENT_PARAM,
     signedKeyIdEmptyContent, sizeof(signedKeyIdEmptyContent));
    CryptMsgClose(msg);

    certInfo.SerialNumber.cbData = sizeof(serialNum);
    certInfo.SerialNumber.pbData = serialNum;
    certInfo.Issuer.cbData = sizeof(encodedCommonName);
    certInfo.Issuer.pbData = encodedCommonName;
    signer.SignerId.dwIdChoice = 0;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    check_param("signed empty bare content", msg, CMSG_BARE_CONTENT_PARAM,
     signedEmptyBareContent, sizeof(signedEmptyBareContent));
    check_param("signed empty content", msg, CMSG_CONTENT_PARAM,
     signedEmptyContent, sizeof(signedEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("signed bare content", msg, CMSG_BARE_CONTENT_PARAM,
     signedBareContent, sizeof(signedBareContent));
    check_param("signed content", msg, CMSG_CONTENT_PARAM,
     signedContent, sizeof(signedContent));

    CryptMsgClose(msg);

    signer.cAuthAttr = 1;
    signer.rgAuthAttr = &attr;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    check_param("signed with auth attrs bare content", msg,
     CMSG_BARE_CONTENT_PARAM, signedWithAuthAttrsBareContent,
     sizeof(signedWithAuthAttrsBareContent));

    CryptMsgClose(msg);

    signer.cAuthAttr = 0;
    signInfo.rgCertEncoded = &encodedCert;
    signInfo.cCertEncoded = 1;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    check_param("signed with cert empty bare content", msg,
     CMSG_BARE_CONTENT_PARAM, signedWithCertEmptyBareContent,
     sizeof(signedWithCertEmptyBareContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("signed with cert bare content", msg, CMSG_BARE_CONTENT_PARAM,
     signedWithCertBareContent, sizeof(signedWithCertBareContent));

    CryptMsgClose(msg);

    signInfo.cCertEncoded = 0;
    signInfo.rgCrlEncoded = &encodedCrl;
    signInfo.cCrlEncoded = 1;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    check_param("signed with crl empty bare content", msg,
     CMSG_BARE_CONTENT_PARAM, signedWithCrlEmptyBareContent,
     sizeof(signedWithCrlEmptyBareContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("signed with crl bare content", msg, CMSG_BARE_CONTENT_PARAM,
     signedWithCrlBareContent, sizeof(signedWithCrlBareContent));

    CryptMsgClose(msg);

    signInfo.cCertEncoded = 1;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    check_param("signed with cert and crl empty bare content", msg,
     CMSG_BARE_CONTENT_PARAM, signedWithCertAndCrlEmptyBareContent,
     sizeof(signedWithCertAndCrlEmptyBareContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    check_param("signed with cert and crl bare content", msg,
     CMSG_BARE_CONTENT_PARAM, signedWithCertAndCrlBareContent,
     sizeof(signedWithCertAndCrlBareContent));

    CryptMsgClose(msg);

    /* Test with a cert with a (bogus) public key */
    signInfo.cCrlEncoded = 0;
    encodedCert.cbData = sizeof(v1CertWithPubKey);
    encodedCert.pbData = v1CertWithPubKey;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    check_param("signedWithCertWithPubKeyBareContent", msg,
     CMSG_BARE_CONTENT_PARAM, signedWithCertWithPubKeyBareContent,
     sizeof(signedWithCertWithPubKeyBareContent));
    CryptMsgClose(msg);

    encodedCert.cbData = sizeof(v1CertWithValidPubKey);
    encodedCert.pbData = v1CertWithValidPubKey;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    check_param("signedWithCertWithValidPubKeyEmptyContent", msg,
     CMSG_CONTENT_PARAM, signedWithCertWithValidPubKeyEmptyContent,
     sizeof(signedWithCertWithValidPubKeyEmptyContent));
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    check_param("signedWithCertWithValidPubKeyContent", msg,
     CMSG_CONTENT_PARAM, signedWithCertWithValidPubKeyContent,
     sizeof(signedWithCertWithValidPubKeyContent));
    CryptMsgClose(msg);

    CryptDestroyKey(key);
    CryptReleaseContext(signer.hCryptProv, 0);
    CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL, PROV_RSA_FULL,
     CRYPT_DELETEKEYSET);
}

static void test_signed_msg_get_param(void)
{
    BOOL ret;
    HCRYPTMSG msg;
    DWORD size, value = 0;
    CMSG_SIGNED_ENCODE_INFO signInfo = { sizeof(signInfo), 0 };
    CMSG_SIGNER_ENCODE_INFO signer = { sizeof(signer), 0 };
    CERT_INFO certInfo = { 0 };

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    /* Content and bare content are always gettable */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());

    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_BARE_CONTENT_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    /* For "signed" messages, so is the version. */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_VERSION_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_VERSION_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(value == CMSG_SIGNED_DATA_V1, "Expected version 1, got %ld\n", value);
    /* But for this message, with no signers, the hash and signer aren't
     * available.
     */
    size = 0;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_ENCODED_SIGNER, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "Expected CRYPT_E_INVALID_INDEX, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "Expected CRYPT_E_INVALID_INDEX, got %lx\n", GetLastError());
    /* As usual, the type isn't available. */
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());

    CryptMsgClose(msg);

    certInfo.SerialNumber.cbData = sizeof(serialNum);
    certInfo.SerialNumber.pbData = serialNum;
    certInfo.Issuer.cbData = sizeof(encodedCommonName);
    certInfo.Issuer.pbData = encodedCommonName;
    signer.pCertInfo = &certInfo;
    signer.HashAlgorithm.pszObjId = oid_rsa_md5;
    signInfo.cSigners = 1;
    signInfo.rgSigners = &signer;

    ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
                                PROV_RSA_FULL, CRYPT_NEWKEYSET);
    if (!ret && GetLastError() == NTE_EXISTS) {
        ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
                                    PROV_RSA_FULL, 0);
    }
    ok(ret, "CryptAcquireContext failed: 0x%lx\n", GetLastError());

    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());

    /* This message, with one signer, has the hash and signer for index 0
     * available, but not for other indexes.
     */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_ENCODED_SIGNER, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %lx\n", GetLastError());
    size = 0;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_ENCODED_SIGNER, 1, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "Expected CRYPT_E_INVALID_INDEX, got %lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 1, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "Expected CRYPT_E_INVALID_INDEX, got %lx\n", GetLastError());
    /* As usual, the type isn't available. */
    ret = CryptMsgGetParam(msg, CMSG_TYPE_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());

    CryptMsgClose(msg);

    /* Opening the message using the CMS fields.. */
    certInfo.SerialNumber.cbData = 0;
    certInfo.Issuer.cbData = 0;
    signer.SignerId.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;
    signer.SignerId.IssuerSerialNumber.Issuer.cbData = sizeof(encodedCommonName);
    signer.SignerId.IssuerSerialNumber.Issuer.pbData = encodedCommonName;
    signer.SignerId.IssuerSerialNumber.SerialNumber.cbData = sizeof(serialNum);
    signer.SignerId.IssuerSerialNumber.SerialNumber.pbData = serialNum;
    ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
     PROV_RSA_FULL, CRYPT_NEWKEYSET);
    if (!ret && GetLastError() == NTE_EXISTS)
        ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
         PROV_RSA_FULL, 0);
    ok(ret, "CryptAcquireContextA failed: %lx\n", GetLastError());
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING,
     CMSG_CRYPT_RELEASE_CONTEXT_FLAG, CMSG_SIGNED, &signInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    /* still results in the version being 1 when the issuer and serial number
     * are used and no additional CMS fields are used.
     */
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_VERSION_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    if (ret)
        ok(value == CMSG_SIGNED_DATA_V1, "expected version 1, got %ld\n", value);
    /* Apparently the encoded signer can be retrieved.. */
    ret = CryptMsgGetParam(msg, CMSG_ENCODED_SIGNER, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    /* but the signer info, CMS signer info, and cert ID can't be. */
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_CMS_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_CERT_ID_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Using the KeyId field of the SignerId results in the version becoming
     * the CMS version.
     */
    signer.SignerId.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
    signer.SignerId.KeyId.cbData = sizeof(serialNum);
    signer.SignerId.KeyId.pbData = serialNum;
    ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
     PROV_RSA_FULL, CRYPT_NEWKEYSET);
    if (!ret && GetLastError() == NTE_EXISTS)
        ret = CryptAcquireContextA(&signer.hCryptProv, cspNameA, NULL,
         PROV_RSA_FULL, 0);
    ok(ret, "CryptAcquireContextA failed: %lx\n", GetLastError());
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING,
     CMSG_CRYPT_RELEASE_CONTEXT_FLAG, CMSG_SIGNED, &signInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_VERSION_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    if (ret)
        ok(value == CMSG_SIGNED_DATA_V3, "expected version 3, got %ld\n", value);
    /* Even for a CMS message, the signer can be retrieved.. */
    ret = CryptMsgGetParam(msg, CMSG_ENCODED_SIGNER, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    /* but the signer info, CMS signer info, and cert ID can't be. */
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_CMS_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_CERT_ID_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    CryptReleaseContext(signer.hCryptProv, 0);
    CryptAcquireContextA(&signer.hCryptProv, cspNameA, MS_DEF_PROV_A,
     PROV_RSA_FULL, CRYPT_DELETEKEYSET);
}

static void test_signed_msg(void)
{
    test_signed_msg_open();
    test_signed_msg_update();
    test_signed_msg_encoding();
    test_signed_msg_get_param();
}

static char oid_rsa_rc4[] = szOID_RSA_RC4;

static void test_enveloped_msg_open(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    CMSG_ENVELOPED_ENCODE_INFO envelopedInfo = { 0 };
    PCCERT_CONTEXT context;

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "expected E_INVALIDARG, got %08lx\n", GetLastError());

    envelopedInfo.cbSize = sizeof(envelopedInfo);
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(!msg && GetLastError() == CRYPT_E_UNKNOWN_ALGO,
     "expected CRYPT_E_UNKNOWN_ALGO, got %08lx\n", GetLastError());

    envelopedInfo.ContentEncryptionAlgorithm.pszObjId = oid_rsa_rc4;
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    envelopedInfo.cRecipients = 1;
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG,
     "expected E_INVALIDARG, got %08lx\n", GetLastError());

    context = CertCreateCertificateContext(X509_ASN_ENCODING,
     v1CertWithValidPubKey, sizeof(v1CertWithValidPubKey));

    envelopedInfo.rgpRecipientCert = (PCERT_INFO *)&context->pCertInfo;
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
    SetLastError(0xdeadbeef);
    ret = CryptAcquireContextA(&envelopedInfo.hCryptProv, NULL, NULL,
     PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    ok(ret, "CryptAcquireContextA failed: %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
    CryptReleaseContext(envelopedInfo.hCryptProv, 0);
    CertFreeCertificateContext(context);
}

static void test_enveloped_msg_update(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    CMSG_ENVELOPED_ENCODE_INFO envelopedInfo = { sizeof(envelopedInfo), 0,
     { oid_rsa_rc4, { 0, NULL } }, NULL };
    CMSG_STREAM_INFO streamInfo = { 0, nop_stream_output, NULL };

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "expected CRYPT_E_MSG_ERROR, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "expected CRYPT_E_MSG_ERROR, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "expected CRYPT_E_MSG_ERROR, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "expected CRYPT_E_MSG_ERROR, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_ENVELOPED, &envelopedInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "expected E_INVALIDARG, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG,
     CMSG_ENVELOPED, &envelopedInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "expected E_INVALIDARG, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, &streamInfo);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, &streamInfo);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
}

static const BYTE envelopedEmptyBareContent[] = {
0x30,0x22,0x02,0x01,0x00,0x31,0x00,0x30,0x1b,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x07,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x03,0x04,0x05,0x00,0x80,0x00 };
static const BYTE envelopedEmptyContent[] = {
0x30,0x31,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x03,0xa0,0x24,
0x30,0x22,0x02,0x01,0x00,0x31,0x00,0x30,0x1b,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x07,0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x03,0x04,0x05,0x00,0x80,0x00 };

static void test_enveloped_msg_encoding(void)
{
    HCRYPTMSG msg;
    CMSG_ENVELOPED_ENCODE_INFO envelopedInfo = { sizeof(envelopedInfo), 0,
     { oid_rsa_rc4, { 0, NULL } }, NULL };

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED,
     &envelopedInfo, NULL, NULL);
    ok(msg != NULL, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());
    check_param("enveloped empty bare content", msg,
     CMSG_BARE_CONTENT_PARAM, envelopedEmptyBareContent,
     sizeof(envelopedEmptyBareContent));
    check_param("enveloped empty content", msg, CMSG_CONTENT_PARAM,
     envelopedEmptyContent, sizeof(envelopedEmptyContent));
    CryptMsgClose(msg);
}

static void test_enveloped_msg(void)
{
    test_enveloped_msg_open();
    test_enveloped_msg_update();
    test_enveloped_msg_encoding();
}

static CRYPT_DATA_BLOB b4 = { 0, NULL };
static const struct update_accum a4 = { 1, &b4 };

static const BYTE bogusOIDContent[] = {
0x30,0x0f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x07,0xa0,0x02,
0x04,0x00 };
static const BYTE bogusHashContent[] = {
0x30,0x47,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x05,0xa0,0x3a,
0x30,0x38,0x02,0x01,0x00,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,
0x02,0x05,0x05,0x00,0x30,0x13,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x07,0x01,0xa0,0x06,0x04,0x04,0x01,0x02,0x03,0x04,0x04,0x10,0x00,0xd6,0xc0,
0x5a,0x21,0x51,0x2a,0x79,0xa1,0xdf,0xeb,0x9d,0x2a,0x8f,0x26,0x2f };
static const BYTE envelopedBareContentWithoutData[] = {
0x30,0x81,0xdb,0x02,0x01,0x00,0x31,0x81,0xba,0x30,0x81,0xb7,0x02,0x01,0x00,
0x30,0x20,0x30,0x0c,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x13,0x01,
0x4e,0x02,0x10,0x63,0x75,0x75,0x7a,0x53,0x36,0xa9,0xba,0x41,0xa5,0xcc,0x01,
0x7f,0x76,0x4c,0xd9,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x01,0x01,0x05,0x00,0x04,0x81,0x80,0x87,0x46,0x26,0x56,0xe3,0xf3,0xa5,0x5b,
0xd4,0x2c,0x03,0xcc,0x52,0x7e,0xf7,0x55,0xf1,0x34,0x9f,0x63,0xf6,0x04,0x9f,
0xc5,0x13,0xf1,0xc9,0x57,0x0a,0xbc,0xa9,0x33,0xd2,0xf2,0x93,0xb6,0x5c,0x94,
0xc3,0x49,0xd6,0xd6,0x6d,0xc4,0x91,0x38,0x80,0xdd,0x0d,0x82,0xef,0xe5,0x72,
0x55,0x40,0x0a,0xdd,0x35,0xfe,0xdc,0x87,0x47,0x92,0xb1,0xbd,0x05,0xc9,0x18,
0x0e,0xde,0x4b,0x00,0x70,0x40,0x31,0x1f,0x5d,0x6c,0x8f,0x3a,0xfb,0x9a,0xc3,
0xb3,0x06,0xe7,0x68,0x3f,0x20,0x14,0x1c,0xf9,0x28,0x4b,0x0f,0x01,0x01,0xb6,
0xfe,0x07,0xe5,0xd8,0xf0,0x7c,0x17,0xbc,0xec,0xfb,0xd7,0x73,0x8a,0x71,0x49,
0x79,0x62,0xe4,0xbf,0xb5,0xe3,0x56,0xa6,0xb4,0x49,0x1e,0xdc,0xaf,0xd7,0x0e,
0x30,0x19,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0x30,0x0c,
0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x04,0x05,0x00 };

static void test_decode_msg_update(void)
{
    HCRYPTMSG msg;
    BOOL ret;
    CMSG_STREAM_INFO streamInfo = { 0 };
    DWORD i;
    struct update_accum accum = { 0, NULL };

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    /* Update with a full message in a final update */
    ret = CryptMsgUpdate(msg, dataEmptyContent, sizeof(dataEmptyContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* Can't update after a final update */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, dataEmptyContent, sizeof(dataEmptyContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    /* Can't send a non-final update without streaming */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, dataEmptyContent, sizeof(dataEmptyContent),
     FALSE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "Expected CRYPT_E_MSG_ERROR, got %lx\n", GetLastError());
    /* A subsequent final update succeeds */
    ret = CryptMsgUpdate(msg, dataEmptyContent, sizeof(dataEmptyContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, &streamInfo);
    /* Updating a message that has a NULL stream callback fails */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, dataEmptyContent, sizeof(dataEmptyContent), FALSE);
    todo_wine
    ok(!ret && GetLastError() == STATUS_ACCESS_VIOLATION,
     "Expected STATUS_ACCESS_VIOLATION, got %lx\n", GetLastError());
    /* Changing the callback pointer after the fact yields the same error (so
     * the message must copy the stream info, not just store a pointer to it)
     */
    streamInfo.pfnStreamOutput = nop_stream_output;
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, dataEmptyContent, sizeof(dataEmptyContent), FALSE);
    todo_wine
    ok(!ret && GetLastError() == STATUS_ACCESS_VIOLATION,
     "Expected STATUS_ACCESS_VIOLATION or STATUS_ILLEGAL_INSTRUCTION, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Empty non-final updates are allowed when streaming.. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, &streamInfo);
    ret = CryptMsgUpdate(msg, NULL, 0, FALSE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    /* but final updates aren't when not enough data has been received. */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    todo_wine
    ok(!ret && GetLastError() == CRYPT_E_STREAM_INSUFFICIENT_DATA,
     "Expected CRYPT_E_STREAM_INSUFFICIENT_DATA, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Updating the message byte by byte is legal */
    streamInfo.pfnStreamOutput = accumulating_stream_output;
    streamInfo.pvArg = &accum;
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, &streamInfo);
    for (i = 0, ret = TRUE; ret && i < sizeof(dataEmptyContent); i++)
        ret = CryptMsgUpdate(msg, &dataEmptyContent[i], 1, FALSE);
    ok(ret, "CryptMsgUpdate failed on byte %ld: %lx\n", i, GetLastError());
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed on byte %ld: %lx\n", i, GetLastError());
    CryptMsgClose(msg);
    todo_wine
    check_updates("byte-by-byte empty content", &a4, &accum);
    free_updates(&accum);

    /* Decoding bogus content fails in non-streaming mode.. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n",
     GetLastError());
    CryptMsgClose(msg);
    /* and as the final update in streaming mode.. */
    streamInfo.pfnStreamOutput = nop_stream_output;
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, &streamInfo);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n",
     GetLastError());
    CryptMsgClose(msg);
    /* and even as a non-final update in streaming mode. */
    streamInfo.pfnStreamOutput = nop_stream_output;
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, &streamInfo);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), FALSE);
    todo_wine
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* An empty message can be opened with undetermined type.. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ret = CryptMsgUpdate(msg, dataEmptyContent, sizeof(dataEmptyContent),
     TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* but decoding it as an explicitly typed message fails. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, 0, NULL,
     NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, dataEmptyContent, sizeof(dataEmptyContent),
     TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* On the other hand, decoding the bare content of an empty message fails
     * with unspecified type..
     */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, dataEmptyBareContent,
     sizeof(dataEmptyBareContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* but succeeds with explicit type. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, 0, NULL,
     NULL);
    ret = CryptMsgUpdate(msg, dataEmptyBareContent,
     sizeof(dataEmptyBareContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Decoding valid content with an unsupported OID fails */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, bogusOIDContent, sizeof(bogusOIDContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Similarly, opening an empty hash with unspecified type succeeds.. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, hashEmptyContent, sizeof(hashEmptyContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
    /* while with specified type it fails. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL,
     NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, hashEmptyContent, sizeof(hashEmptyContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* On the other hand, decoding the bare content of an empty hash message
     * fails with unspecified type..
     */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, hashEmptyBareContent,
     sizeof(hashEmptyBareContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* but succeeds with explicit type. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL,
     NULL);
    ret = CryptMsgUpdate(msg, hashEmptyBareContent,
     sizeof(hashEmptyBareContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* And again, opening a (non-empty) hash message with unspecified type
     * succeeds..
     */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, hashContent, sizeof(hashContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
    /* while with specified type it fails.. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL,
     NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, hashContent, sizeof(hashContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n", GetLastError());
    CryptMsgClose(msg);
    /* and decoding the bare content of a non-empty hash message fails with
     * unspecified type..
     */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, hashBareContent, sizeof(hashBareContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %lx\n",
     GetLastError());
    CryptMsgClose(msg);
    /* but succeeds with explicit type. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL,
     NULL);
    ret = CryptMsgUpdate(msg, hashBareContent, sizeof(hashBareContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Opening a (non-empty) hash message with unspecified type and a bogus
     * hash value succeeds..
     */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, bogusHashContent, sizeof(bogusHashContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ret = CryptMsgUpdate(msg, signedContent, sizeof(signedContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, signedWithCertAndCrlBareContent,
     sizeof(signedWithCertAndCrlBareContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "Expected CRYPT_E_ASN1_BADTAG, got %08lx\n", GetLastError());
    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, 0, NULL,
     NULL);
    ret = CryptMsgUpdate(msg, signedWithCertAndCrlBareContent,
     sizeof(signedWithCertAndCrlBareContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0,
     NULL, NULL);
    /* The first update succeeds.. */
    ret = CryptMsgUpdate(msg, detachedSignedContent,
     sizeof(detachedSignedContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    /* as does a second (probably to update the detached portion).. */
    ret = CryptMsgUpdate(msg, detachedSignedContent,
     sizeof(detachedSignedContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    /* while a third fails. */
    ret = CryptMsgUpdate(msg, detachedSignedContent,
     sizeof(detachedSignedContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "expected CRYPT_E_MSG_ERROR, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0, NULL, &streamInfo);
    ret = CryptMsgUpdate(msg, detachedSignedContent, sizeof(detachedSignedContent), FALSE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, detachedSignedContent, sizeof(detachedSignedContent), FALSE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());

    ret = CryptMsgUpdate(msg, detachedSignedContent, sizeof(detachedSignedContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR,
     "expected CRYPT_E_MSG_ERROR, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, envelopedEmptyBareContent,
     sizeof(envelopedEmptyBareContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, envelopedEmptyContent,
     sizeof(envelopedEmptyContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "expected CRYPT_E_ASN1_BADTAG, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, envelopedEmptyBareContent,
     sizeof(envelopedEmptyBareContent), TRUE);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_BADTAG,
     "expected CRYPT_E_ASN1_BADTAG, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, envelopedEmptyContent,
     sizeof(envelopedEmptyContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, envelopedBareContentWithoutData,
     sizeof(envelopedBareContentWithoutData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);
}

static const BYTE hashParam[] = { 0x08,0xd6,0xc0,0x5a,0x21,0x51,0x2a,0x79,0xa1,
 0xdf,0xeb,0x9d,0x2a,0x8f,0x26,0x2f };

static void compare_signer_info(const CMSG_SIGNER_INFO *got,
 const CMSG_SIGNER_INFO *expected)
{
    ok(got->dwVersion == expected->dwVersion, "Expected version %ld, got %ld\n",
     expected->dwVersion, got->dwVersion);
    ok(got->Issuer.cbData == expected->Issuer.cbData,
     "Expected issuer size %ld, got %ld\n", expected->Issuer.cbData,
     got->Issuer.cbData);
    ok(!memcmp(got->Issuer.pbData, expected->Issuer.pbData, got->Issuer.cbData),
     "Unexpected issuer\n");
    ok(got->SerialNumber.cbData == expected->SerialNumber.cbData,
     "Expected serial number size %ld, got %ld\n", expected->SerialNumber.cbData,
     got->SerialNumber.cbData);
    ok(!memcmp(got->SerialNumber.pbData, expected->SerialNumber.pbData,
     got->SerialNumber.cbData), "Unexpected serial number\n");
    /* FIXME: check more things */
}

static void compare_cms_signer_info(const CMSG_CMS_SIGNER_INFO *got,
 const CMSG_CMS_SIGNER_INFO *expected)
{
    ok(got->dwVersion == expected->dwVersion, "Expected version %ld, got %ld\n",
     expected->dwVersion, got->dwVersion);
    ok(got->SignerId.dwIdChoice == expected->SignerId.dwIdChoice,
     "Expected id choice %ld, got %ld\n", expected->SignerId.dwIdChoice,
     got->SignerId.dwIdChoice);
    if (got->SignerId.dwIdChoice == expected->SignerId.dwIdChoice)
    {
        if (got->SignerId.dwIdChoice == CERT_ID_ISSUER_SERIAL_NUMBER)
        {
            ok(got->SignerId.IssuerSerialNumber.Issuer.cbData ==
             expected->SignerId.IssuerSerialNumber.Issuer.cbData,
             "Expected issuer size %ld, got %ld\n",
             expected->SignerId.IssuerSerialNumber.Issuer.cbData,
             got->SignerId.IssuerSerialNumber.Issuer.cbData);
            ok(!memcmp(got->SignerId.IssuerSerialNumber.Issuer.pbData,
             expected->SignerId.IssuerSerialNumber.Issuer.pbData,
             got->SignerId.IssuerSerialNumber.Issuer.cbData),
             "Unexpected issuer\n");
            ok(got->SignerId.IssuerSerialNumber.SerialNumber.cbData ==
             expected->SignerId.IssuerSerialNumber.SerialNumber.cbData,
             "Expected serial number size %ld, got %ld\n",
             expected->SignerId.IssuerSerialNumber.SerialNumber.cbData,
             got->SignerId.IssuerSerialNumber.SerialNumber.cbData);
            ok(!memcmp(got->SignerId.IssuerSerialNumber.SerialNumber.pbData,
             expected->SignerId.IssuerSerialNumber.SerialNumber.pbData,
             got->SignerId.IssuerSerialNumber.SerialNumber.cbData),
             "Unexpected serial number\n");
        }
        else
        {
            ok(got->SignerId.KeyId.cbData == expected->SignerId.KeyId.cbData,
             "expected key id size %ld, got %ld\n",
             expected->SignerId.KeyId.cbData, got->SignerId.KeyId.cbData);
            ok(!memcmp(expected->SignerId.KeyId.pbData,
             got->SignerId.KeyId.pbData, got->SignerId.KeyId.cbData),
             "unexpected key id\n");
        }
    }
    /* FIXME: check more things */
}

static const BYTE signedWithCertAndCrlComputedHash[] = {
0x08,0xd6,0xc0,0x5a,0x21,0x51,0x2a,0x79,0xa1,0xdf,0xeb,0x9d,0x2a,0x8f,0x26,
0x2f };
static BYTE keyIdIssuer[] = {
0x30,0x13,0x31,0x11,0x30,0x0f,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,
0x0a,0x07,0x01,0x04,0x01,0x01 };
static const BYTE publicPrivateKeyPair[] = {
0x07,0x02,0x00,0x00,0x00,0xa4,0x00,0x00,0x52,0x53,0x41,0x32,0x00,0x04,0x00,
0x00,0x01,0x00,0x01,0x00,0x21,0x65,0x5d,0x97,0x19,0x3f,0xd0,0xd0,0x76,0x5b,
0xb1,0x10,0x4e,0xcc,0x14,0xb5,0x92,0x0f,0x60,0xad,0xb6,0x74,0x8d,0x94,0x50,
0xfd,0x14,0x5e,0xbc,0xf1,0x93,0xbf,0x24,0x21,0x64,0x9d,0xc7,0x77,0x04,0x54,
0xd1,0xbd,0x3e,0xd8,0x3b,0x2a,0x8b,0x95,0x70,0xdf,0x19,0x20,0xed,0x76,0x39,
0xfa,0x64,0x04,0xc6,0xf7,0x33,0x7b,0xaa,0x94,0x67,0x74,0xbc,0x6b,0xd5,0xa7,
0x69,0x99,0x99,0x47,0x88,0xc0,0x7e,0x36,0xf1,0xc5,0x7d,0xa8,0xd8,0x07,0x48,
0xe6,0x05,0x4f,0xf4,0x1f,0x37,0xd7,0xc7,0xa7,0x00,0x20,0xb3,0xe5,0x40,0x17,
0x86,0x43,0x77,0xe0,0x32,0x39,0x11,0x9c,0xd9,0xd8,0x53,0x9b,0x45,0x42,0x54,
0x65,0xca,0x15,0xbe,0xb2,0x44,0xf1,0xd0,0xf3,0xb6,0x4a,0x19,0xc8,0x3d,0x33,
0x63,0x93,0x4f,0x7c,0x67,0xc6,0x58,0x6d,0xf6,0xb7,0x20,0xd8,0x30,0xcc,0x52,
0xaa,0x68,0x66,0xf6,0x86,0xf8,0xe0,0x3a,0x73,0x0e,0x9d,0xc5,0x03,0x60,0x9e,
0x08,0xe9,0x5e,0xd4,0x5e,0xcc,0xbb,0xc1,0x48,0xad,0x9d,0xbb,0xfb,0x26,0x61,
0xa8,0x0e,0x9c,0xba,0xf1,0xd0,0x0b,0x5f,0x87,0xd4,0xb5,0xd2,0xdf,0x41,0xcb,
0x7a,0xec,0xb5,0x87,0x59,0x6a,0x9d,0xb3,0x6c,0x06,0xee,0x1f,0xc5,0xae,0x02,
0xa8,0x7f,0x33,0x6e,0x30,0x50,0x6d,0x65,0xd0,0x1f,0x00,0x47,0x43,0x25,0x90,
0x4a,0xa8,0x74,0x8c,0x23,0x8b,0x15,0x8a,0x74,0xd2,0x03,0xa6,0x1c,0xc1,0x7e,
0xbb,0xb1,0xa6,0x80,0x05,0x2b,0x62,0xfb,0x89,0xe5,0xba,0xc6,0xcc,0x12,0xce,
0xa8,0xe9,0xc4,0xb5,0x9d,0xd8,0x11,0xdd,0x95,0x90,0x71,0xb0,0xfe,0xaa,0x14,
0xce,0xd5,0xd0,0x5a,0x88,0x47,0xda,0x31,0xda,0x26,0x11,0x66,0xd1,0xd5,0xc5,
0x1b,0x08,0xbe,0xc6,0xf3,0x15,0xbf,0x80,0x78,0xcf,0x55,0xe0,0x61,0xee,0xf5,
0x71,0x1e,0x2f,0x0e,0xb3,0x67,0xf7,0xa1,0x86,0x04,0xcf,0x4b,0xc1,0x2f,0x94,
0x73,0xd1,0x5d,0x0c,0xee,0x10,0x58,0xbb,0x74,0x0c,0x61,0x02,0x15,0x69,0x68,
0xe0,0x21,0x3e,0xa6,0x27,0x22,0x8c,0xc8,0x61,0xbc,0xba,0xa9,0x4b,0x2e,0x71,
0x77,0x74,0xdc,0x63,0x05,0x32,0x7a,0x93,0x4f,0xbf,0xc7,0xa5,0x3a,0xe3,0x25,
0x4d,0x67,0xcf,0x78,0x1b,0x85,0x22,0x6c,0xfe,0x5c,0x34,0x0e,0x27,0x12,0xbc,
0xd5,0x33,0x1a,0x75,0x8a,0x9c,0x40,0x39,0xe8,0xa0,0xc9,0xae,0xf8,0xaf,0x9a,
0xc6,0x62,0x47,0xf3,0x5b,0xdf,0x5e,0xcd,0xc6,0xc0,0x5c,0xd7,0x0e,0x04,0x64,
0x3d,0xdd,0x57,0xef,0xf6,0xcd,0xdf,0xd2,0x7e,0x17,0x6c,0x0a,0x47,0x5e,0x77,
0x4b,0x02,0x49,0x78,0xc0,0xf7,0x09,0x6e,0xdf,0x96,0x04,0x51,0x74,0x3d,0x68,
0x99,0x43,0x8e,0x03,0x16,0x46,0xa4,0x04,0x84,0x01,0x6e,0xd4,0xca,0x5c,0xab,
0xb0,0xd3,0x82,0xf1,0xb9,0xba,0x51,0x99,0x03,0xe9,0x7f,0xdf,0x30,0x3b,0xf9,
0x18,0xbb,0x80,0x7f,0xf0,0x89,0xbb,0x6d,0x98,0x95,0xb7,0xfd,0xd8,0xdf,0xed,
0xf3,0x16,0x6f,0x96,0x4f,0xfd,0x54,0x66,0x6d,0x90,0xba,0xf5,0xcc,0xce,0x01,
0x34,0x34,0x51,0x07,0x66,0x20,0xfb,0x4a,0x3c,0x7e,0x19,0xf8,0x8e,0x35,0x0e,
0x07,0x48,0x74,0x38,0xd2,0x18,0xaa,0x2e,0x90,0x5e,0x0e,0xcc,0x50,0x6e,0x71,
0x6f,0x54,0xdb,0xbf,0x7b,0xb4,0xf4,0x79,0x6a,0x21,0xa3,0x6d,0xdf,0x61,0xc0,
0x8f,0xb3,0xb6,0xe1,0x8a,0x65,0x21,0x6e,0xf6,0x5b,0x80,0xf0,0xfb,0x28,0x87,
0x13,0x06,0xd6,0xbc,0x28,0x5c,0xda,0xc5,0x13,0x13,0x44,0x8d,0xf4,0xa8,0x7b,
0x5c,0x2a,0x7f,0x11,0x16,0x4e,0x52,0x41,0xe9,0xe7,0x8e };
static const BYTE envelopedMessage[] = {
0x30,0x81,0xf2,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x03,0xa0,
0x81,0xe4,0x30,0x81,0xe1,0x02,0x01,0x00,0x31,0x81,0xba,0x30,0x81,0xb7,0x02,
0x01,0x00,0x30,0x20,0x30,0x0c,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,
0x13,0x01,0x4e,0x02,0x10,0x63,0x75,0x75,0x7a,0x53,0x36,0xa9,0xba,0x41,0xa5,
0xcc,0x01,0x7f,0x76,0x4c,0xd9,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,
0x0d,0x01,0x01,0x01,0x05,0x00,0x04,0x81,0x80,0xc2,0x0d,0x59,0x87,0xb3,0x65,
0xd2,0x64,0xcd,0xba,0xe3,0xaf,0x1e,0xa1,0xd3,0xdd,0xb3,0x53,0xfc,0x2f,0xae,
0xdc,0x6d,0x2a,0x81,0x84,0x38,0x6f,0xdf,0x81,0xb1,0x65,0xba,0xac,0x59,0xb1,
0x19,0x12,0x3f,0xde,0x12,0xce,0x77,0x42,0x71,0x67,0xa9,0x78,0x38,0x95,0x51,
0xbb,0x66,0x78,0xbf,0xaf,0x0a,0x98,0x4b,0xba,0xa5,0xf0,0x8b,0x9f,0xef,0xcf,
0x40,0x05,0xa1,0xd6,0x10,0xae,0xbf,0xb9,0xbd,0x4d,0x22,0x39,0x33,0x63,0x2b,
0x0b,0xd3,0x0c,0xb5,0x4b,0xe8,0xfe,0x15,0xa8,0xa5,0x2c,0x86,0x33,0x80,0x6e,
0x4c,0x7a,0x99,0x3c,0x6b,0x4b,0x60,0xfd,0x8e,0xb2,0xf3,0x82,0x2f,0x3e,0x1e,
0xba,0xb9,0x78,0x24,0x32,0xab,0xa4,0x10,0x1a,0x38,0x94,0x10,0x8d,0xf8,0x70,
0x3e,0x4e,0x30,0x1f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,
0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x04,0x05,0x00,0x80,
0x04,0x5f,0x80,0xf2,0x17 };
static const BYTE envelopedBareMessage[] = {
0x30,0x81,0xe1,0x02,0x01,0x00,0x31,0x81,0xba,0x30,0x81,0xb7,0x02,0x01,0x00,
0x30,0x20,0x30,0x0c,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x13,0x01,
0x4e,0x02,0x10,0x63,0x75,0x75,0x7a,0x53,0x36,0xa9,0xba,0x41,0xa5,0xcc,0x01,
0x7f,0x76,0x4c,0xd9,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,
0x01,0x01,0x05,0x00,0x04,0x81,0x80,0x69,0x79,0x12,0x6b,0xa1,0x2f,0xe9,0x0d,
0x34,0x79,0x77,0xe9,0x15,0xf2,0xff,0x0c,0x9a,0xf2,0x87,0xbd,0x12,0xc4,0x2d,
0x9e,0x81,0xc7,0x3c,0x74,0x05,0xdc,0x13,0xaf,0xe9,0xa2,0xba,0x72,0xe9,0xa5,
0x2b,0x81,0x39,0xd3,0x62,0xaa,0x78,0xc3,0x90,0x4f,0x06,0xf0,0xdb,0x18,0x5e,
0xe1,0x2e,0x19,0xa3,0xc2,0xac,0x1e,0xf1,0xbf,0xe6,0x03,0x00,0x96,0xfa,0xd2,
0x66,0x73,0xd0,0x45,0x55,0x57,0x71,0xff,0x3a,0x0c,0xad,0xce,0xde,0x68,0xd4,
0x45,0x20,0xc8,0x44,0x4d,0x5d,0xa2,0x98,0x79,0xb1,0x81,0x0f,0x8a,0xfc,0x70,
0xa5,0x18,0xd2,0x30,0x65,0x22,0x84,0x02,0x24,0x48,0xf7,0xa4,0xe0,0xa5,0x6c,
0xa8,0xa4,0xd0,0x86,0x4b,0x6e,0x9b,0x18,0xab,0x78,0xfa,0x76,0x12,0xce,0x55,
0x30,0x1f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01,0x30,0x0c,
0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x04,0x05,0x00,0x80,0x04,0x2c,
0x2d,0xa3,0x6e };
static const BYTE envelopedMessageWith3Recps[] = {
0x30,0x82,0x02,0x69,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x03,
0xa0,0x82,0x02,0x5a,0x30,0x82,0x02,0x56,0x02,0x01,0x00,0x31,0x82,0x02,0x2e,
0x30,0x81,0xb7,0x02,0x01,0x00,0x30,0x20,0x30,0x0c,0x31,0x0a,0x30,0x08,0x06,
0x03,0x55,0x04,0x03,0x13,0x01,0x4e,0x02,0x10,0x63,0x75,0x75,0x7a,0x53,0x36,
0xa9,0xba,0x41,0xa5,0xcc,0x01,0x7f,0x76,0x4c,0xd9,0x30,0x0d,0x06,0x09,0x2a,
0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x04,0x81,0x80,0xa4,0x2e,
0xe5,0x56,0x60,0xc5,0x64,0x07,0x29,0xaf,0x5c,0x38,0x3d,0x4b,0xec,0xbd,0xba,
0x97,0x60,0x17,0xed,0xd7,0x21,0x7b,0x19,0x94,0x95,0xf1,0xb2,0x84,0x06,0x1f,
0xc5,0x83,0xb3,0x5d,0xc8,0x2c,0x1c,0x0f,0xf7,0xfd,0x58,0x8b,0x0f,0x25,0xb5,
0x9f,0x7f,0x43,0x8f,0x5f,0x81,0x16,0x4a,0x62,0xfb,0x47,0xb5,0x36,0x72,0x21,
0x29,0xd4,0x9e,0x27,0x35,0xf4,0xd0,0xd4,0xc0,0xa3,0x7a,0x47,0xbe,0xc9,0xae,
0x08,0x17,0x6a,0xb5,0x63,0x38,0xa1,0xdc,0xf5,0xc1,0x8d,0x97,0x56,0xb4,0xc0,
0x2d,0x2b,0xec,0x3d,0xbd,0xce,0xd1,0x52,0x3e,0x29,0x34,0xe2,0x9a,0x00,0x96,
0x4c,0x85,0xaf,0x0f,0xfb,0x10,0x1d,0xf8,0x08,0x27,0x10,0x04,0x04,0xbf,0xae,
0x36,0xd0,0x6a,0x49,0xe7,0x43,0x30,0x81,0xb7,0x02,0x01,0x00,0x30,0x20,0x30,
0x0c,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x13,0x01,0x4e,0x02,0x10,
0xc2,0x8f,0xc4,0x5e,0x8d,0x3b,0x01,0x8c,0x4b,0x23,0xcb,0x93,0x77,0xab,0xb6,
0xe1,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,
0x00,0x04,0x81,0x80,0x4b,0x22,0x8a,0xfa,0xa6,0xb6,0x01,0xe9,0xb5,0x54,0xcf,
0xa7,0x81,0x54,0xf9,0x08,0x42,0x8a,0x75,0x19,0x9c,0xc9,0x27,0x68,0x08,0xf9,
0x53,0xa7,0x60,0xf8,0xdd,0xba,0xfb,0x4f,0x63,0x8a,0x15,0x6a,0x5b,0xf6,0xe3,
0x4e,0x29,0xa9,0xc8,0x1d,0x63,0x92,0x8f,0x95,0x91,0x95,0x71,0xb5,0x5d,0x02,
0xe5,0xa0,0x07,0x67,0x36,0xe5,0x2d,0x7b,0xcd,0xe1,0xf2,0xa4,0xc6,0x24,0x70,
0xac,0xd7,0xaf,0x63,0xb2,0x04,0x02,0x8d,0xae,0x2f,0xdc,0x7e,0x6c,0x84,0xd3,
0xe3,0x66,0x54,0x3b,0x05,0xd8,0x77,0x40,0xe4,0x6b,0xbd,0xa9,0x8d,0x4d,0x74,
0x15,0xfd,0x74,0xf7,0xd3,0xc0,0xc9,0xf1,0x20,0x0e,0x08,0x13,0xcc,0xb0,0x94,
0x53,0x01,0xd4,0x5f,0x95,0x32,0xeb,0xe8,0x73,0x9f,0x6a,0xd1,0x30,0x81,0xb7,
0x02,0x01,0x00,0x30,0x20,0x30,0x0c,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,
0x03,0x13,0x01,0x58,0x02,0x10,0x1c,0xf2,0x1f,0xec,0x6b,0xdc,0x36,0xbf,0x4a,
0xd7,0xe1,0x6c,0x84,0x85,0xcd,0x2e,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,
0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x04,0x81,0x80,0x47,0x21,0xf9,0xe7,0x98,
0x7f,0xe7,0x49,0x3f,0x16,0xb8,0x4c,0x8b,0x7d,0x5d,0x56,0xa7,0x31,0xfd,0xa5,
0xcd,0x43,0x70,0x58,0xf1,0x33,0xfb,0xe6,0xc8,0xbb,0x6f,0x0a,0x89,0xa4,0xb9,
0x3e,0x3a,0xc5,0x85,0x46,0x54,0x73,0x37,0xa3,0xbd,0x36,0xc3,0xce,0x40,0xf3,
0xd7,0x92,0x54,0x8e,0x60,0x1f,0xa2,0xa7,0x03,0xc2,0x49,0xa9,0x02,0x28,0xc8,
0xa5,0xa7,0x42,0xcd,0x29,0x85,0x34,0xa7,0xa9,0xe8,0x8c,0x3d,0xb3,0xd0,0xac,
0x7d,0x31,0x5d,0xb4,0xcb,0x7e,0xad,0x62,0xfd,0x04,0x7b,0xa1,0x93,0xb5,0xbc,
0x08,0x4f,0x36,0xd7,0x5a,0x95,0xbc,0xff,0x47,0x0f,0x84,0x21,0x24,0xdf,0xc5,
0xfe,0xc8,0xe5,0x0b,0xc4,0xc4,0x5c,0x1a,0x50,0x31,0x91,0xce,0xf6,0x11,0xf1,
0x0e,0x28,0xce,0x30,0x1f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,
0x01,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x03,0x04,0x05,0x00,
0x80,0x04,0x4e,0x99,0x9d,0x4c };
static const BYTE serialNumber[] = {
0x2e,0xcd,0x85,0x84,0x6c,0xe1,0xd7,0x4a,0xbf,0x36,0xdc,0x6b,0xec,0x1f,0xf2,
0x1c };
static const BYTE issuer[] = {
0x30,0x0c,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x13,0x01,0x58 };

static void test_decode_msg_get_param(void)
{
    HCRYPTMSG msg;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY key = 0;
    BOOL ret;
    DWORD size = 0, value, req_size;
    LPBYTE buf;
    CMSG_CTRL_DECRYPT_PARA decryptPara = { sizeof(decryptPara), 0 };

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, dataContent, sizeof(dataContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    check_param("data content", msg, CMSG_CONTENT_PARAM, msgData,
     sizeof(msgData));
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ret = CryptMsgUpdate(msg, hashEmptyContent, sizeof(hashEmptyContent), TRUE);

    check_param("empty hash content", msg, CMSG_CONTENT_PARAM, NULL, 0);
    check_param("empty hash hash data", msg, CMSG_HASH_DATA_PARAM, NULL, 0);
    check_param("empty hash computed hash", msg, CMSG_COMPUTED_HASH_PARAM,
    emptyHashParam, sizeof(emptyHashParam));

    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ret = CryptMsgUpdate(msg, hashContent, sizeof(hashContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    check_param("hash content", msg, CMSG_CONTENT_PARAM, msgData,
     sizeof(msgData));
    check_param("hash hash data", msg, CMSG_HASH_DATA_PARAM, hashParam,
     sizeof(hashParam));
    check_param("hash computed hash", msg, CMSG_COMPUTED_HASH_PARAM,
     hashParam, sizeof(hashParam));

    ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 1, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    buf = CryptMemAlloc(size);
    if (buf)
    {
        ret = CryptMsgGetParam(msg, CMSG_COMPUTED_HASH_PARAM, 1, buf, &size);
        ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
        ok(size == sizeof(hashParam), "Unexpected size %ld\n", size);
        ok(!memcmp(buf, hashParam, size), "Unexpected value\n");
        CryptMemFree(buf);
    }
    check_param("hash inner OID", msg, CMSG_INNER_CONTENT_TYPE_PARAM,
     (const BYTE *)szOID_RSA_data, strlen(szOID_RSA_data) + 1);
    value = CMSG_HASHED_DATA_V0;
    check_param("hash version", msg, CMSG_VERSION_PARAM, (const BYTE *)&value,
     sizeof(value));
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ret = CryptMsgUpdate(msg, signedContent, sizeof(signedContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    check_param("signed content", msg, CMSG_CONTENT_PARAM, msgData,
     sizeof(msgData));
    check_param("inner content", msg, CMSG_INNER_CONTENT_TYPE_PARAM,
     (const BYTE *)szOID_RSA_data, strlen(szOID_RSA_data) + 1);
    size = sizeof(value);
    value = 2112;
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_COUNT_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(value == 1, "Expected 1 signer, got %ld\n", value);
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    buf = CryptMemAlloc(size);
    if (buf)
    {
        CMSG_SIGNER_INFO signer = { 0 };

        signer.dwVersion = 1;
        signer.Issuer.cbData = sizeof(encodedCommonName);
        signer.Issuer.pbData = encodedCommonName;
        signer.SerialNumber.cbData = sizeof(serialNum);
        signer.SerialNumber.pbData = serialNum;
        signer.HashAlgorithm.pszObjId = oid_rsa_md5;
        req_size = size;
        size += 10;
        CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, buf, &size);
        ok(size == req_size, "size = %lu, expected %lu\n", size, req_size);
        compare_signer_info((CMSG_SIGNER_INFO *)buf, &signer);
        CryptMemFree(buf);
    }
    /* Getting the CMS signer info of a PKCS7 message is possible. */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_CMS_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    buf = CryptMemAlloc(size);
    if (buf)
    {
        CMSG_CMS_SIGNER_INFO signer = { 0 };

        signer.dwVersion = 1;
        signer.SignerId.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;
        signer.SignerId.IssuerSerialNumber.Issuer.cbData = sizeof(encodedCommonName);
        signer.SignerId.IssuerSerialNumber.Issuer.pbData = encodedCommonName;
        signer.SignerId.IssuerSerialNumber.SerialNumber.cbData = sizeof(serialNum);
        signer.SignerId.IssuerSerialNumber.SerialNumber.pbData = serialNum;
        signer.HashAlgorithm.pszObjId = oid_rsa_md5;
        CryptMsgGetParam(msg, CMSG_CMS_SIGNER_INFO_PARAM, 0, buf, &size);
        compare_cms_signer_info((CMSG_CMS_SIGNER_INFO *)buf, &signer);
        CryptMemFree(buf);
    }
    /* index is ignored when getting signer count */
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_COUNT_PARAM, 1, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(value == 1, "Expected 1 signer, got %ld\n", value);
    ret = CryptMsgGetParam(msg, CMSG_CERT_COUNT_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(value == 0, "Expected 0 certs, got %ld\n", value);
    ret = CryptMsgGetParam(msg, CMSG_CRL_COUNT_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(value == 0, "Expected 0 CRLs, got %ld\n", value);
    CryptMsgClose(msg);
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, 0, NULL,
     NULL);
    ret = CryptMsgUpdate(msg, signedWithCertAndCrlBareContent,
     sizeof(signedWithCertAndCrlBareContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    ret = CryptMsgGetParam(msg, CMSG_CERT_COUNT_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(value == 1, "Expected 1 cert, got %ld\n", value);
    check_param("cert", msg, CMSG_CERT_PARAM, cert, sizeof(cert));
    ret = CryptMsgGetParam(msg, CMSG_CRL_COUNT_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(value == 1, "Expected 1 CRL, got %ld\n", value);
    check_param("crl", msg, CMSG_CRL_PARAM, crl, sizeof(crl));
    check_param("signed with cert and CRL computed hash", msg,
     CMSG_COMPUTED_HASH_PARAM, signedWithCertAndCrlComputedHash,
     sizeof(signedWithCertAndCrlComputedHash));
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ret = CryptMsgUpdate(msg, signedKeyIdEmptyContent,
     sizeof(signedKeyIdEmptyContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    size = sizeof(value);
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_COUNT_PARAM, 0, &value, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(value == 1, "Expected 1 signer, got %ld\n", value);
    /* Getting the regular (non-CMS) signer info from a CMS message is also
     * possible..
     */
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    buf = CryptMemAlloc(size);
    if (buf)
    {
        CMSG_SIGNER_INFO signer;
        BYTE zero = 0;

        /* and here's the little oddity:  for a CMS message using the key id
         * variant of a SignerId, retrieving the CMSG_SIGNER_INFO param yields
         * a signer with a zero (not empty) serial number, and whose issuer is
         * an RDN with OID szOID_KEYID_RDN, value type CERT_RDN_OCTET_STRING,
         * and value of the key id.
         */
        signer.dwVersion = CMSG_SIGNED_DATA_V3;
        signer.Issuer.cbData = sizeof(keyIdIssuer);
        signer.Issuer.pbData = keyIdIssuer;
        signer.SerialNumber.cbData = 1;
        signer.SerialNumber.pbData = &zero;
        CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, buf, &size);
        compare_signer_info((CMSG_SIGNER_INFO *)buf, &signer);
        CryptMemFree(buf);
    }
    size = 0;
    ret = CryptMsgGetParam(msg, CMSG_CMS_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    buf = CryptMemAlloc(size);
    if (buf)
    {
        CMSG_CMS_SIGNER_INFO signer = { 0 };

        signer.dwVersion = CMSG_SIGNED_DATA_V3;
        signer.SignerId.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
        signer.SignerId.KeyId.cbData = sizeof(serialNum);
        signer.SignerId.KeyId.pbData = serialNum;
        signer.HashAlgorithm.pszObjId = oid_rsa_md5;
        CryptMsgGetParam(msg, CMSG_CMS_SIGNER_INFO_PARAM, 0, buf, &size);
        compare_cms_signer_info((CMSG_CMS_SIGNER_INFO *)buf, &signer);
        CryptMemFree(buf);
    }
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    CryptMsgUpdate(msg, envelopedEmptyBareContent,
     sizeof(envelopedEmptyBareContent), TRUE);
    check_param("enveloped empty bare content", msg, CMSG_CONTENT_PARAM, NULL,
     0);
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    CryptMsgUpdate(msg, envelopedEmptyContent, sizeof(envelopedEmptyContent),
     TRUE);
    check_param("enveloped empty content", msg, CMSG_CONTENT_PARAM, NULL, 0);
    CryptMsgClose(msg);

    CryptAcquireContextA(&hCryptProv, NULL, MS_ENHANCED_PROV_A, PROV_RSA_FULL,
     CRYPT_VERIFYCONTEXT);
    SetLastError(0xdeadbeef);
    ret = CryptImportKey(hCryptProv, publicPrivateKeyPair,
     sizeof(publicPrivateKeyPair), 0, 0, &key);
    ok(ret, "CryptImportKey failed: %08lx\n", GetLastError());

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    CryptMsgUpdate(msg, envelopedMessage, sizeof(envelopedMessage), TRUE);
    check_param("enveloped message before decrypting", msg, CMSG_CONTENT_PARAM,
     envelopedMessage + sizeof(envelopedMessage) - 4, 4);

    decryptPara.hCryptProv = hCryptProv;
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(ret, "CryptMsgControl failed: %08lx\n", GetLastError());
    decryptPara.hCryptProv = 0;
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(!ret && GetLastError() == CRYPT_E_ALREADY_DECRYPTED,
     "expected CRYPT_E_ALREADY_DECRYPTED, got %08lx\n", GetLastError());
    check_param("enveloped message", msg, CMSG_CONTENT_PARAM, msgData, sizeof(msgData));
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    CryptMsgUpdate(msg, envelopedBareMessage, sizeof(envelopedBareMessage),
     TRUE);
    check_param("enveloped bare message before decrypting", msg,
     CMSG_CONTENT_PARAM, envelopedBareMessage +
     sizeof(envelopedBareMessage) - 4, 4);

    decryptPara.hCryptProv = hCryptProv;
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(ret, "CryptMsgControl failed: %08lx\n", GetLastError());
    check_param("enveloped bare message", msg, CMSG_CONTENT_PARAM, msgData, sizeof(msgData));
    CryptMsgClose(msg);

    if (key)
        CryptDestroyKey(key);
    CryptReleaseContext(hCryptProv, 0);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    CryptMsgUpdate(msg, envelopedMessageWith3Recps,
     sizeof(envelopedMessageWith3Recps), TRUE);
    value = 3;
    check_param("recipient count", msg, CMSG_RECIPIENT_COUNT_PARAM,
     (const BYTE *)&value, sizeof(value));
    size = 0;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_RECIPIENT_INFO_PARAM, 3, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "expected CRYPT_E_INVALID_INDEX, got %08lx\n", GetLastError());
    size = 0;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_RECIPIENT_INFO_PARAM, 2, NULL, &size);
    ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
    ok(size >= 142, "unexpected size: %lu\n", size);
    if (ret)
        buf = CryptMemAlloc(size);
    else
        buf = NULL;
    if (buf)
    {
        CERT_INFO *certInfo = (CERT_INFO *)buf;

        SetLastError(0xdeadbeef);
        ret = CryptMsgGetParam(msg, CMSG_RECIPIENT_INFO_PARAM, 2, buf, &size);
        ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
        ok(certInfo->SerialNumber.cbData == sizeof(serialNumber),
         "unexpected serial number size: %lu\n", certInfo->SerialNumber.cbData);
        ok(!memcmp(certInfo->SerialNumber.pbData, serialNumber,
         sizeof(serialNumber)), "unexpected serial number\n");
        ok(certInfo->Issuer.cbData == sizeof(issuer),
         "unexpected issuer size: %lu\n", certInfo->Issuer.cbData);
        ok(!memcmp(certInfo->Issuer.pbData, issuer, sizeof(issuer)),
         "unexpected issuer\n");
        CryptMemFree(buf);
    }
    CryptMsgClose(msg);
}

static void test_decode_msg(void)
{
    test_decode_msg_update();
    test_decode_msg_get_param();
}

static BYTE aKey[] = { 0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf };
/* aKey encoded as a X509_PUBLIC_KEY_INFO */
static BYTE encodedPubKey[] = {
0x30,0x1f,0x30,0x0a,0x06,0x06,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x05,0x00,0x03,
0x11,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,
0x0d,0x0e,0x0f };
/* a weird modulus encoded as RSA_CSP_PUBLICKEYBLOB */
static BYTE mod_encoded[] = {
 0x30,0x10,0x02,0x09,0x00,0x80,0x00,0x00,0x01,0x01,0x01,0x01,0x01,0x02,0x03,
 0x01,0x00,0x01 };

static void test_msg_control(void)
{
    static char oid_rsa_rsa[] = szOID_RSA_RSA;
    BOOL ret;
    HCRYPTMSG msg;
    DWORD i;
    CERT_INFO certInfo = { 0 };
    CMSG_HASHED_ENCODE_INFO hashInfo = { 0 };
    CMSG_SIGNED_ENCODE_INFO signInfo = { sizeof(signInfo), 0 };
    CMSG_CTRL_DECRYPT_PARA decryptPara = { sizeof(decryptPara), 0 };

    /* Crashes
    ret = CryptMsgControl(NULL, 0, 0, NULL);
    */

    /* Data encode messages don't allow any sort of control.. */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_DATA, NULL, NULL,
     NULL);
    /* either with no prior update.. */
    for (i = 1; i <= CMSG_CTRL_ADD_CMS_SIGNER_INFO; i++)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, i, NULL);
        ok(!ret && GetLastError() == E_INVALIDARG,
         "Expected E_INVALIDARG, got %08lx\n", GetLastError());
    }
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    /* or after an update. */
    for (i = 1; i <= CMSG_CTRL_ADD_CMS_SIGNER_INFO; i++)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, i, NULL);
        ok(!ret && GetLastError() == E_INVALIDARG,
         "Expected E_INVALIDARG, got %08lx\n", GetLastError());
    }
    CryptMsgClose(msg);

    /* Hash encode messages don't allow any sort of control.. */
    hashInfo.cbSize = sizeof(hashInfo);
    hashInfo.HashAlgorithm.pszObjId = oid_rsa_md5;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, &hashInfo,
     NULL, NULL);
    /* either with no prior update.. */
    for (i = 1; i <= CMSG_CTRL_ADD_CMS_SIGNER_INFO; i++)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, i, NULL);
        ok(!ret && GetLastError() == E_INVALIDARG,
         "Expected E_INVALIDARG, got %08lx\n", GetLastError());
    }
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    /* or after an update. */
    for (i = 1; i <= CMSG_CTRL_ADD_CMS_SIGNER_INFO; i++)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, i, NULL);
        ok(!ret && GetLastError() == E_INVALIDARG,
         "Expected E_INVALIDARG, got %08lx\n", GetLastError());
    }
    CryptMsgClose(msg);

    /* Signed encode messages likewise don't allow any sort of control.. */
    signInfo.cbSize = sizeof(signInfo);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &signInfo,
     NULL, NULL);
    /* either before an update.. */
    for (i = 1; i <= CMSG_CTRL_ADD_CMS_SIGNER_INFO; i++)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, i, NULL);
        ok(!ret && GetLastError() == E_INVALIDARG,
         "Expected E_INVALIDARG, got %08lx\n", GetLastError());
    }
    ret = CryptMsgUpdate(msg, NULL, 0, TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    /* or after an update. */
    for (i = 1; i <= CMSG_CTRL_ADD_CMS_SIGNER_INFO; i++)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, i, NULL);
        ok(!ret && GetLastError() == E_INVALIDARG,
         "Expected E_INVALIDARG, got %08lx\n", GetLastError());
    }
    CryptMsgClose(msg);

    /* Decode messages behave a bit differently. */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    /* Bad control type */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, 0, NULL);
    ok(!ret && GetLastError() == CRYPT_E_CONTROL_TYPE,
     "Expected CRYPT_E_CONTROL_TYPE, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 1, 0, NULL);
    ok(!ret && GetLastError() == CRYPT_E_CONTROL_TYPE,
     "Expected CRYPT_E_CONTROL_TYPE, got %08lx\n", GetLastError());
    /* Can't verify the hash of an indeterminate-type message */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_HASH, NULL);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    /* Crashes
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, NULL);
     */
    /* Can't decrypt an indeterminate-type message */
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL, NULL);
    /* Can't verify the hash of an empty message */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_HASH, NULL);
    todo_wine
    ok(!ret && GetLastError() == STATUS_ACCESS_VIOLATION,
     "Expected STATUS_ACCESS_VIOLATION, got %08lx\n", GetLastError());
    /* Crashes
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, NULL);
    */
    /* Can't verify the signature of a hash message */
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    CryptMsgUpdate(msg, hashEmptyBareContent, sizeof(hashEmptyBareContent), TRUE);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_HASH, NULL);
    ok(!ret, "Expected failure\n");
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_HASHED, 0, NULL,
     NULL);
    CryptMsgUpdate(msg, hashBareContent, sizeof(hashBareContent), TRUE);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_HASH, NULL);
    ok(ret, "CryptMsgControl failed: %08lx\n", GetLastError());
    /* Can't decrypt an indeterminate-type message */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0,
     NULL, NULL);
    /* Can't verify the hash of a detached message before it's been updated. */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_HASH, NULL);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, detachedHashContent, sizeof(detachedHashContent),
     TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    /* Still can't verify the hash of a detached message with the content
     * of the detached hash given..
     */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_HASH, NULL);
    ok(!ret && GetLastError() == CRYPT_E_HASH_VALUE,
     "Expected CRYPT_E_HASH_VALUE, got %08lx\n", GetLastError());
    /* and giving the content of the message after attempting to verify the
     * hash fails.
     */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    todo_wine
    ok(!ret && (GetLastError() == NTE_BAD_HASH_STATE || GetLastError() == CRYPT_E_MSG_ERROR), /* Vista */
     "Expected NTE_BAD_HASH_STATE or NTE_BAD_ALGID or CRYPT_E_MSG_ERROR, "
     "got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Finally, verifying the hash of a detached message in the correct order:
     * 1. Update with the detached hash message
     * 2. Update with the content of the message
     * 3. Verifying the hash of the message
     * succeeds.
     */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0,
     NULL, NULL);
    ret = CryptMsgUpdate(msg, detachedHashContent, sizeof(detachedHashContent),
     TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_HASH, NULL);
    ok(ret, "CryptMsgControl failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, 0, NULL,
     NULL);
    /* Can't verify the hash of a signed message */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_HASH, NULL);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    /* Can't decrypt a signed message */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "Expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());
    /* Crash
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, NULL);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
     */
    CryptMsgUpdate(msg, signedWithCertBareContent,
     sizeof(signedWithCertBareContent), TRUE);
    /* With an empty cert info, the signer can't be found in the message (and
     * the signature can't be verified.
     */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
    ok(!ret && GetLastError() == CRYPT_E_SIGNER_NOT_FOUND,
     "Expected CRYPT_E_SIGNER_NOT_FOUND, got %08lx\n", GetLastError());
    /* The cert info is expected to have an issuer, serial number, and public
     * key info set.
     */
    certInfo.SerialNumber.cbData = sizeof(serialNum);
    certInfo.SerialNumber.pbData = serialNum;
    certInfo.Issuer.cbData = sizeof(encodedCommonName);
    certInfo.Issuer.pbData = encodedCommonName;
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
    ok(!ret && GetLastError() == CRYPT_E_ASN1_EOD,
     "Expected CRYPT_E_ASN1_EOD, got %08lx\n", GetLastError());
    CryptMsgClose(msg);
    /* This cert has a public key, but it's not in a usable form */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, 0, NULL,
     NULL);
    ret = CryptMsgUpdate(msg, signedWithCertWithPubKeyBareContent,
     sizeof(signedWithCertWithPubKeyBareContent), TRUE);
    if (ret)
    {
        /* Again, cert info needs to have a public key set */
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
        ok(!ret &&
         (GetLastError() == CRYPT_E_ASN1_EOD ||
          GetLastError() == TRUST_E_NOSIGNATURE /* Vista */),
         "Expected CRYPT_E_ASN1_EOD or TRUST_E_NOSIGNATURE, got %08lx\n", GetLastError());
        /* The public key is supposed to be in encoded form.. */
        certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId = oid_rsa_rsa;
        certInfo.SubjectPublicKeyInfo.PublicKey.cbData = sizeof(aKey);
        certInfo.SubjectPublicKeyInfo.PublicKey.pbData = aKey;
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
        ok(!ret &&
         (GetLastError() == CRYPT_E_ASN1_BADTAG ||
          GetLastError() == TRUST_E_NOSIGNATURE /* Vista */),
         "Expected CRYPT_E_ASN1_BADTAG or TRUST_E_NOSIGNATURE, got %08lx\n", GetLastError());
        /* but not as a X509_PUBLIC_KEY_INFO.. */
        certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId = NULL;
        certInfo.SubjectPublicKeyInfo.PublicKey.cbData = sizeof(encodedPubKey);
        certInfo.SubjectPublicKeyInfo.PublicKey.pbData = encodedPubKey;
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
        ok(!ret &&
         (GetLastError() == CRYPT_E_ASN1_BADTAG ||
          GetLastError() == TRUST_E_NOSIGNATURE /* Vista */),
         "Expected CRYPT_E_ASN1_BADTAG or TRUST_E_NOSIGNATURE, got %08lx\n", GetLastError());
        /* This decodes successfully, but it doesn't match any key in the message */
        certInfo.SubjectPublicKeyInfo.PublicKey.cbData = sizeof(mod_encoded);
        certInfo.SubjectPublicKeyInfo.PublicKey.pbData = mod_encoded;
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
        /* In Wine's rsaenh, this fails to decode because the key length is too
         * small.  Not sure if that's a bug in rsaenh, so leaving todo_wine for
         * now.
         */
        todo_wine
        ok(!ret &&
         (GetLastError() == NTE_BAD_SIGNATURE ||
          GetLastError() == TRUST_E_NOSIGNATURE /* Vista */),
         "Expected NTE_BAD_SIGNATURE or TRUST_E_NOSIGNATURE, got %08lx\n", GetLastError());
    }
    CryptMsgClose(msg);
    /* A message with no data doesn't have a valid signature */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ret = CryptMsgUpdate(msg, signedWithCertWithValidPubKeyEmptyContent,
     sizeof(signedWithCertWithValidPubKeyEmptyContent), TRUE);
    if (ret)
    {
        certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId = oid_rsa_rsa;
        certInfo.SubjectPublicKeyInfo.PublicKey.cbData = sizeof(pubKey);
        certInfo.SubjectPublicKeyInfo.PublicKey.pbData = pubKey;
        SetLastError(0xdeadbeef);
        ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
        ok(!ret &&
         (GetLastError() == NTE_BAD_SIGNATURE ||
          GetLastError() == TRUST_E_NOSIGNATURE /* Vista */),
         "Expected NTE_BAD_SIGNATURE or TRUST_E_NOSIGNATURE, got %08lx\n", GetLastError());
    }
    CryptMsgClose(msg);
    /* Finally, this succeeds */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    CryptMsgUpdate(msg, signedWithCertWithValidPubKeyContent,
     sizeof(signedWithCertWithValidPubKeyContent), TRUE);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
    ok(ret, "CryptMsgControl failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    /* Test verifying signature of a detached signed message */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0,
     NULL, NULL);
    ret = CryptMsgUpdate(msg, detachedSignedContent,
     sizeof(detachedSignedContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    /* Can't verify the sig without having updated the data */
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
    ok(!ret && GetLastError() == NTE_BAD_SIGNATURE,
     "expected NTE_BAD_SIGNATURE, got %08lx\n",
     GetLastError());
    /* Now that the signature's been checked, can't do the final update */
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    todo_wine
    ok(!ret && (GetLastError() == NTE_BAD_HASH_STATE || GetLastError() == CRYPT_E_MSG_ERROR), /* Vista */
     "expected NTE_BAD_HASH_STATE or CRYPT_E_MSG_ERROR, got %08lx\n", GetLastError());
    CryptMsgClose(msg);
    /* Updating with the detached portion of the message and the data of the
     * the message allows the sig to be verified.
     */
    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, CMSG_DETACHED_FLAG, 0, 0,
     NULL, NULL);
    ret = CryptMsgUpdate(msg, detachedSignedContent,
     sizeof(detachedSignedContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    ret = CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, &certInfo);
    ok(ret, "CryptMsgControl failed: %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    decryptPara.cbSize = 0;
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(!ret && GetLastError() == E_INVALIDARG,
     "expected E_INVALIDARG, got %08lx\n", GetLastError());
    decryptPara.cbSize = sizeof(decryptPara);

    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_MSG_TYPE,
     "expected CRYPT_E_INVALID_MSG_TYPE, got %08lx\n", GetLastError());

    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, envelopedEmptyBareContent,
     sizeof(envelopedEmptyBareContent), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "expected CRYPT_E_INVALID_INDEX, got %08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, 0, NULL,
     NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, envelopedBareMessage,
     sizeof(envelopedBareMessage), TRUE);
    ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &decryptPara);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER,
     "expected ERROR_INVALID_PARAMETER, got %08lx\n", GetLastError());
    CryptMsgClose(msg);
}

static void test_msg_get_and_verify_signer(void)
{
    BOOL ret;
    HCRYPTMSG msg;
    PCCERT_CONTEXT signer;
    DWORD signerIndex;
    HCERTSTORE store;

    /* Crash */
    if (0)
    {
        CryptMsgGetAndVerifySigner(NULL, 0, NULL, 0, NULL, NULL);
        CryptMsgGetAndVerifySigner(NULL, 0, NULL, 0, NULL, &signerIndex);
    }

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    /* An empty message has no signer */
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, 0, NULL, NULL);
    ok(!ret && GetLastError() == CRYPT_E_NO_TRUSTED_SIGNER,
     "expected CRYPT_E_NO_TRUSTED_SIGNER, got 0x%08lx\n", GetLastError());
    /* The signer is cleared on error */
    signer = (PCCERT_CONTEXT)0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, 0, &signer, NULL);
    ok(!ret && GetLastError() == CRYPT_E_NO_TRUSTED_SIGNER,
     "expected CRYPT_E_NO_TRUSTED_SIGNER, got 0x%08lx\n", GetLastError());
    ok(!signer, "expected signer to be NULL\n");
    /* The signer index is also cleared on error */
    signerIndex = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, 0, NULL, &signerIndex);
    ok(!ret && GetLastError() == CRYPT_E_NO_TRUSTED_SIGNER,
     "expected CRYPT_E_NO_TRUSTED_SIGNER, got 0x%08lx\n", GetLastError());
    ok(!signerIndex, "expected 0, got %ld\n", signerIndex);
    /* An unsigned message (msgData isn't a signed message at all)
     * likewise has no signer.
     */
    CryptMsgUpdate(msg, msgData, sizeof(msgData), TRUE);
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, 0, NULL, NULL);
    ok(!ret && GetLastError() == CRYPT_E_NO_TRUSTED_SIGNER,
     "expected CRYPT_E_NO_TRUSTED_SIGNER, got 0x%08lx\n", GetLastError());
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    /* A "signed" message created with no signer cert likewise has no signer */
    ret = CryptMsgUpdate(msg, signedEmptyContent, sizeof(signedEmptyContent), TRUE);
    if (ret)
    {
        ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, 0, NULL, NULL);
        ok(!ret && GetLastError() == CRYPT_E_NO_TRUSTED_SIGNER,
         "expected CRYPT_E_NO_TRUSTED_SIGNER, got 0x%08lx\n", GetLastError());
    }
    CryptMsgClose(msg);

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    /* A signed message succeeds, .. */
    CryptMsgUpdate(msg, signedWithCertWithValidPubKeyContent,
     sizeof(signedWithCertWithValidPubKeyContent), TRUE);
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, 0, NULL, NULL);
    ok(ret, "CryptMsgGetAndVerifySigner failed: 0x%08lx\n", GetLastError());
    /* the signer index can be retrieved, .. */
    signerIndex = 0xdeadbeef;
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, 0, NULL, &signerIndex);
    ok(ret, "CryptMsgGetAndVerifySigner failed: 0x%08lx\n", GetLastError());
    if (ret)
        ok(signerIndex == 0, "expected 0, got %ld\n", signerIndex);
    /* as can the signer cert. */
    signer = (PCCERT_CONTEXT)0xdeadbeef;
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, 0, &signer, NULL);
    ok(ret, "CryptMsgGetAndVerifySigner failed: 0x%08lx\n", GetLastError());
    if (ret)
        ok(signer != NULL && signer != (PCCERT_CONTEXT)0xdeadbeef,
     "expected a valid signer\n");
    if (signer && signer != (PCCERT_CONTEXT)0xdeadbeef)
        CertFreeCertificateContext(signer);
    /* Specifying CMSG_USE_SIGNER_INDEX_FLAG and an invalid signer index fails
     */
    signerIndex = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, CMSG_USE_SIGNER_INDEX_FLAG,
     NULL, &signerIndex);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX,
     "expected CRYPT_E_INVALID_INDEX, got 0x%08lx\n", GetLastError());
    /* Specifying CMSG_TRUSTED_SIGNER_FLAG and no cert stores causes the
     * message signer not to be found.
     */
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetAndVerifySigner(msg, 0, NULL, CMSG_TRUSTED_SIGNER_FLAG,
     NULL, NULL);
    ok(!ret && GetLastError() == CRYPT_E_NO_TRUSTED_SIGNER,
     "expected CRYPT_E_NO_TRUSTED_SIGNER, got 0x%08lx\n", GetLastError());
    /* Specifying CMSG_TRUSTED_SIGNER_FLAG and an empty cert store also causes
     * the message signer not to be found.
     */
    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
     CERT_STORE_CREATE_NEW_FLAG, NULL);
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetAndVerifySigner(msg, 1, &store, CMSG_TRUSTED_SIGNER_FLAG,
     NULL, NULL);
    ok(!ret && GetLastError() == CRYPT_E_NO_TRUSTED_SIGNER,
     "expected CRYPT_E_NO_TRUSTED_SIGNER, got 0x%08lx\n", GetLastError());
    ret = CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING,
     v1CertWithValidPubKey, sizeof(v1CertWithValidPubKey),
     CERT_STORE_ADD_ALWAYS, NULL);
    ok(ret, "CertAddEncodedCertificateToStore failed: 0x%08lx\n", GetLastError());
    /* Specifying CMSG_TRUSTED_SIGNER_FLAG with a cert store that contains
     * the signer succeeds.
     */
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetAndVerifySigner(msg, 1, &store, CMSG_TRUSTED_SIGNER_FLAG,
     NULL, NULL);
    ok(ret, "CryptMsgGetAndVerifySigner failed: 0x%08lx\n", GetLastError());
    CertCloseStore(store, 0);
    CryptMsgClose(msg);
}

/* Generated with:
 * openssl ecparam -name prime256v1 -genkey -out private-key.pem
 * openssl req -new -x509 -key private-key.pem -out certificate.der -outform der -days 10000 -subj "/C=US/ST=T/L=T/O=T/CN=T"
 * openssl pkcs12 -export -out certificate.pfx -inkey private-key.pem -in certificate.der
 * - import certificate.pfx on Windows
 * signtool /sign /v /fd SHA256 certificate.pfx a.exe
 * - extract signed message from a.exe
 */
static const BYTE msg_signed_ecc_prime256v1[] = {
0x30,0x82,0x03,0x85,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02,0xa0,
0x82,0x03,0x76,0x30,0x82,0x03,0x72,0x02,0x01,0x01,0x31,0x0f,0x30,0x0d,0x06,0x09,
0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x30,0x5c,0x06,0x0a,0x2b,
0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x04,0xa0,0x4e,0x30,0x4c,0x30,0x17,0x06,
0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x0f,0x30,0x09,0x03,0x01,0x00,
0xa0,0x04,0xa2,0x02,0x80,0x00,0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,
0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20,0x32,0x54,0x6a,0x85,0xd7,0xe6,0x83,
0x46,0x6c,0x94,0x58,0x3b,0x17,0xa4,0xa8,0x8b,0xea,0xea,0x11,0xe0,0x6e,0xc4,0x3c,
0xea,0xde,0xbb,0x2e,0x7d,0xa3,0xb6,0xbe,0x69,0xa0,0x82,0x01,0xd5,0x30,0x82,0x01,
0xd1,0x30,0x82,0x01,0x77,0xa0,0x03,0x02,0x01,0x02,0x02,0x14,0x13,0x09,0x38,0x76,
0x3a,0x38,0xef,0x36,0xac,0xc3,0xa5,0x7e,0xa5,0xad,0x56,0x50,0x8d,0x77,0x55,0x2c,
0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x30,0x3d,0x31,0x0b,
0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x0a,0x30,0x08,0x06,
0x03,0x55,0x04,0x08,0x0c,0x01,0x54,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x07,
0x0c,0x01,0x54,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x0a,0x0c,0x01,0x54,0x31,
0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x0c,0x01,0x54,0x30,0x20,0x17,0x0d,0x32,
0x33,0x30,0x36,0x32,0x39,0x30,0x33,0x31,0x38,0x35,0x35,0x5a,0x18,0x0f,0x32,0x30,
0x35,0x30,0x31,0x31,0x31,0x34,0x30,0x33,0x31,0x38,0x35,0x35,0x5a,0x30,0x3d,0x31,
0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x0a,0x30,0x08,
0x06,0x03,0x55,0x04,0x08,0x0c,0x01,0x54,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,
0x07,0x0c,0x01,0x54,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x0a,0x0c,0x01,0x54,
0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x0c,0x01,0x54,0x30,0x59,0x30,0x13,
0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,
0x03,0x01,0x07,0x03,0x42,0x00,0x04,0xfe,0xdb,0x26,0x60,0xf6,0x89,0x3d,0xa4,0x50,
0x1f,0x06,0x91,0x4e,0x07,0x86,0x70,0x2b,0xc0,0x7c,0x5e,0xb3,0xca,0xdc,0x1a,0x8b,
0x82,0xdd,0x41,0x8a,0x62,0x0f,0xba,0xd1,0xd7,0x80,0xc8,0x20,0x77,0xba,0xe7,0xe1,
0x36,0xf8,0x76,0x9a,0x54,0x6a,0x1b,0x67,0x45,0x3b,0xd7,0x85,0x84,0xbe,0x11,0xe6,
0x6c,0x70,0xd8,0x18,0x68,0xd8,0xa7,0xa3,0x53,0x30,0x51,0x30,0x1d,0x06,0x03,0x55,
0x1d,0x0e,0x04,0x16,0x04,0x14,0x94,0x15,0x14,0xad,0x7e,0xaf,0x63,0xa4,0x12,0x29,
0xaa,0xe4,0x26,0x54,0x7b,0x4e,0x2c,0xb9,0xdb,0xc8,0x30,0x1f,0x06,0x03,0x55,0x1d,
0x23,0x04,0x18,0x30,0x16,0x80,0x14,0x94,0x15,0x14,0xad,0x7e,0xaf,0x63,0xa4,0x12,
0x29,0xaa,0xe4,0x26,0x54,0x7b,0x4e,0x2c,0xb9,0xdb,0xc8,0x30,0x0f,0x06,0x03,0x55,
0x1d,0x13,0x01,0x01,0xff,0x04,0x05,0x30,0x03,0x01,0x01,0xff,0x30,0x0a,0x06,0x08,
0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x03,0x48,0x00,0x30,0x45,0x02,0x21,0x00,
0xe6,0xb6,0x11,0x8d,0x75,0x3a,0x62,0xf3,0x08,0x17,0xce,0xa5,0x5a,0xcb,0x61,0xc7,
0x0a,0x33,0xdb,0x30,0x29,0x6b,0x5e,0xac,0xfc,0xaa,0xed,0x14,0xd1,0xd7,0xae,0x24,
0x02,0x20,0x2e,0x4d,0x70,0xc7,0x26,0xf7,0xea,0xa3,0x07,0x8a,0x6f,0x98,0x07,0xe1,
0xbc,0x38,0x13,0x88,0x17,0xdd,0x01,0x21,0x1e,0xb0,0xbb,0x32,0xfc,0x7a,0xc0,0xd5,
0x80,0x45,0x31,0x82,0x01,0x23,0x30,0x82,0x01,0x1f,0x02,0x01,0x01,0x30,0x55,0x30,
0x3d,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x0a,
0x30,0x08,0x06,0x03,0x55,0x04,0x08,0x0c,0x01,0x54,0x31,0x0a,0x30,0x08,0x06,0x03,
0x55,0x04,0x07,0x0c,0x01,0x54,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x0a,0x0c,
0x01,0x54,0x31,0x0a,0x30,0x08,0x06,0x03,0x55,0x04,0x03,0x0c,0x01,0x54,0x02,0x14,
0x13,0x09,0x38,0x76,0x3a,0x38,0xef,0x36,0xac,0xc3,0xa5,0x7e,0xa5,0xad,0x56,0x50,
0x8d,0x77,0x55,0x2c,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,
0x01,0x05,0x00,0xa0,0x5e,0x30,0x10,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,
0x02,0x01,0x0c,0x31,0x02,0x30,0x00,0x30,0x19,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,
0x0d,0x01,0x09,0x03,0x31,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,
0x01,0x04,0x30,0x2f,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x04,0x31,
0x22,0x04,0x20,0x25,0xc1,0x32,0xc0,0x4f,0x1a,0xae,0x84,0xd2,0x6a,0xff,0x0e,0xc9,
0xe8,0x85,0xbc,0x38,0x63,0x7b,0x22,0x89,0x1c,0x97,0x29,0xc2,0x8f,0x70,0x40,0xc2,
0xdf,0x42,0x9a,0x30,0x0b,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x05,0x00,
0x04,0x47,0x30,0x45,0x02,0x20,0x07,0x66,0x32,0x9a,0x15,0x8f,0x39,0x0a,0xb0,0xe1,
0x80,0xc9,0x82,0x23,0xb8,0x99,0x54,0x4c,0xa7,0x65,0xf2,0x99,0x11,0x70,0x1e,0xdf,
0xf5,0x40,0x73,0x7a,0x8d,0xd1,0x02,0x21,0x00,0x84,0xe0,0xec,0x38,0x33,0x01,0x28,
0x2b,0x4b,0x72,0xed,0x6a,0x64,0xb7,0xaf,0x7a,0x34,0x4b,0x6b,0x69,0xf6,0x55,0x9a,
0x8e,0x0d,0xe9,0xc1,0x85,0x80,0x4d,0xef,0x6c,0x00,0x00,0x00,0x00,0x00,0x00,0x00, };

static void test_verify_ecc_signature(void)
{
    HCERTSTORE store;
    HCRYPTKEY key;
#ifndef __REACTOS__
    BCRYPT_KEY_HANDLE bkey;
#endif
    HCRYPTMSG msg;
    BOOL bret;
    CERT_INFO *cert_info;
    PCCERT_CONTEXT cert;
    DWORD size;
    CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA verify_para = { sizeof(verify_para) };
    HCRYPTOIDFUNCSET set;
    void *import_func;
    HCRYPTOIDFUNCADDR hfunc = NULL;
    CMSG_CMS_SIGNER_INFO *signer_info;

    msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    ok(!!msg, "failed, error %#lx.\n", GetLastError());
    bret = CryptMsgUpdate(msg, msg_signed_ecc_prime256v1, sizeof(msg_signed_ecc_prime256v1), TRUE);
    ok(bret, "failed, error %#lx.\n", GetLastError());
    store = CertOpenStore(CERT_STORE_PROV_MSG, X509_ASN_ENCODING, 0, 0, msg);
    ok(!!store, "failed, error %#lx.\n", GetLastError());
    size = 0;
    bret = CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &size);
    ok(bret, "failed, error %#lx.\n", GetLastError());
    cert_info = malloc(size);
    bret = CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, cert_info, &size);
    ok(bret, "failed, error %#lx.\n", GetLastError());
    cert = CertGetSubjectCertificateFromStore(store, X509_ASN_ENCODING, cert_info);
    ok(!!cert, "failed, error %#lx.\n", GetLastError());

    ok(!strcmp(cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY),
            "got OID %s.\n", cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
    size = 0;
    bret = CryptMsgGetParam(msg, CMSG_CMS_SIGNER_INFO_PARAM, 0, NULL, &size);
    ok(bret, "failed, error %#lx.\n", GetLastError());
    signer_info = malloc(size);
    bret = CryptMsgGetParam(msg, CMSG_CMS_SIGNER_INFO_PARAM, 0, signer_info, &size);
    ok(bret, "failed, error %#lx.\n", GetLastError());
    ok(!strcmp(signer_info->HashAlgorithm.pszObjId, szOID_NIST_sha256), "got %s.\n",
            signer_info->HashAlgorithm.pszObjId);
    ok(!strcmp(signer_info->HashEncryptionAlgorithm.pszObjId, szOID_ECC_PUBLIC_KEY), "got %s.\n",
            signer_info->HashEncryptionAlgorithm.pszObjId);

    set = CryptInitOIDFunctionSet(CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_FUNC, 0);
    ok(!!set, "failed, error %#lx.\n", GetLastError());
    bret = CryptGetOIDFunctionAddress(set, X509_ASN_ENCODING, cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
            0, (void **)&import_func, &hfunc);
    ok(!bret, "succeeded.\n");

    bret = CryptImportPublicKeyInfo(0, X509_ASN_ENCODING, &cert->pCertInfo->SubjectPublicKeyInfo, &key);
    ok(!bret && GetLastError() == CRYPT_E_ASN1_BADTAG, "got ret %d, error %#lx.\n", bret, GetLastError());

#ifndef __REACTOS__ // FIXME: ReactOS has no implementation for CryptImportPublicKeyInfoEx2
    bret = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &cert->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &bkey);
    ok(bret, "failed, error %#lx.\n", GetLastError());
    BCryptDestroyKey(bkey);
#endif

    bret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE, cert->pCertInfo);
    ok(bret, "failed, error %#lx.\n", GetLastError());

    verify_para.dwSignerType = CMSG_VERIFY_SIGNER_CERT;
    verify_para.pvSigner = (void *)cert;
    bret = CryptMsgControl(msg, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &verify_para);
    ok(bret, "failed, error %#lx.\n", GetLastError());

    free(signer_info);
    free(cert_info);
    CertFreeCertificateContext(cert);
    CertCloseStore(store, 0);
    CryptMsgClose(msg);
}

/* CMS EnvelopedData: AES, key transport by key identifier and RSAES-OAEP, and CNG keys.
 * The fixtures come from gen_msg_fixtures.py. */

#include "msg_fixtures.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#ifndef CRYPT_E_BAD_ENCODE
#define CRYPT_E_BAD_ENCODE ((HRESULT)0x80092002)
#endif
#ifndef CRYPT_E_ATTRIBUTES_MISSING
#define CRYPT_E_ATTRIBUTES_MISSING ((HRESULT)0x8009100F)
#endif
#ifndef NTE_INVALID_PARAMETER
#define NTE_INVALID_PARAMETER ((HRESULT)0x80090027)
#endif

typedef struct _cms_enveloped_encode_info
{
    DWORD                       cbSize;
    HCRYPTPROV_LEGACY           hCryptProv;
    CRYPT_ALGORITHM_IDENTIFIER  ContentEncryptionAlgorithm;
    void                       *pvEncryptionAuxInfo;
    DWORD                       cRecipients;
    PCERT_INFO                 *rgpRecipientCert;
    PCMSG_RECIPIENT_ENCODE_INFO rgCmsRecipients;
    DWORD                       cCertEncoded;
    PCERT_BLOB                  rgCertEncoded;
    DWORD                       cCrlEncoded;
    PCRL_BLOB                   rgCrlEncoded;
    DWORD                       cAttrCertEncoded;
    PCERT_BLOB                  rgAttrCertEncoded;
    DWORD                       cUnprotectedAttr;
    PCRYPT_ATTRIBUTE            rgUnprotectedAttr;
} cms_enveloped_encode_info;

typedef struct { DWORD cbSize; DWORD dwBitLen; } cms_rc2_aux;

#define CMS_NCRYPT_KEY_SPEC 0xffffffff
#define CMS_STATUS_INVALID_PARAMETER   0xc000000d
#define CMS_STATUS_DATA_ERROR          0xc000003e
#define CMS_STATUS_INVALID_BUFFER_SIZE 0xc0000206

static const char cms_plain[] = "hello CMS enveloped world, 0123456789abcdef!";

typedef LONG (WINAPI *cms_NCryptOpenStorageProvider)(ULONG_PTR *, const WCHAR *, DWORD);
typedef LONG (WINAPI *cms_NCryptImportKey)(ULONG_PTR, ULONG_PTR, const WCHAR *, void *, ULONG_PTR *, BYTE *, DWORD, DWORD);
typedef LONG (WINAPI *cms_NCryptFreeObject)(ULONG_PTR);
typedef LONG (WINAPI *cms_NCryptDecrypt)(ULONG_PTR, BYTE *, DWORD, void *, BYTE *, DWORD, DWORD *, DWORD);

static struct
{
    HCRYPTPROV capi_prov;
    ULONG_PTR ncrypt_prov, ncrypt_a, ncrypt_b;
    BOOL have_capi, have_ncrypt;
    cms_NCryptFreeObject free_object;
} cms_keys;

static void cms_load_keys(void)
{
    HMODULE ncrypt = LoadLibraryA("ncrypt.dll");
    cms_NCryptOpenStorageProvider open_provider = ncrypt ? (void *)GetProcAddress(ncrypt, "NCryptOpenStorageProvider") : NULL;
    cms_NCryptImportKey import_key = ncrypt ? (void *)GetProcAddress(ncrypt, "NCryptImportKey") : NULL;
    HCRYPTKEY key;
    LONG status;

    cms_keys.free_object = ncrypt ? (void *)GetProcAddress(ncrypt, "NCryptFreeObject") : NULL;
    if (CryptAcquireContextA(&cms_keys.capi_prov, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptImportKey(cms_keys.capi_prov, cms_key_a_capi, sizeof(cms_key_a_capi), 0, 0, &key))
    {
        CryptDestroyKey(key);
        cms_keys.have_capi = TRUE;
    }
    if (open_provider && import_key && !open_provider(&cms_keys.ncrypt_prov, L"Microsoft Software Key Storage Provider", 0))
    {
        status = import_key(cms_keys.ncrypt_prov, 0, L"RSAPRIVATEBLOB", NULL, &cms_keys.ncrypt_a,
                            (BYTE *)cms_key_a_cng, sizeof(cms_key_a_cng), 0);
        if (!status)
            status = import_key(cms_keys.ncrypt_prov, 0, L"RSAPRIVATEBLOB", NULL, &cms_keys.ncrypt_b,
                                (BYTE *)cms_key_b_cng, sizeof(cms_key_b_cng), 0);
        cms_keys.have_ncrypt = !status;
        if (cms_keys.have_ncrypt)
        {
            /* NCryptDecrypt has to work: the garbage fails, but not as "not supported" */
            cms_NCryptDecrypt decrypt = (void *)GetProcAddress(ncrypt, "NCryptDecrypt");
            BYTE input[256] = { 0 }, output[256];
            DWORD size;

            if (!decrypt || decrypt(cms_keys.ncrypt_a, input, sizeof(input), NULL, output, sizeof(output), &size, 2) == (LONG)0x80090029)
                cms_keys.have_ncrypt = FALSE;
        }
    }
}

static void cms_free_keys(void)
{
    if (cms_keys.free_object)
    {
        if (cms_keys.ncrypt_a) cms_keys.free_object(cms_keys.ncrypt_a);
        if (cms_keys.ncrypt_b) cms_keys.free_object(cms_keys.ncrypt_b);
        if (cms_keys.ncrypt_prov) cms_keys.free_object(cms_keys.ncrypt_prov);
    }
    if (cms_keys.capi_prov) CryptReleaseContext(cms_keys.capi_prov, 0);
    memset(&cms_keys, 0, sizeof(cms_keys));
}

static HCRYPTMSG cms_open(const BYTE *data, DWORD len)
{
    HCRYPTMSG msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    BOOL ret;

    ok(!!msg, "CryptMsgOpenToDecode failed: %08lx\n", GetLastError());
    if (!msg) return NULL;
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, data, len, TRUE);
    if (!ret) { CryptMsgClose(msg); return NULL; }
    return msg;
}

static void *cms_param(HCRYPTMSG msg, DWORD param, DWORD index, DWORD *len)
{
    BYTE *buf;
    DWORD size = 0;

    if (!CryptMsgGetParam(msg, param, index, NULL, &size)) return NULL;
    buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1);
    if (!CryptMsgGetParam(msg, param, index, buf, &size)) { HeapFree(GetProcessHeap(), 0, buf); return NULL; }
    if (len) *len = size;
    return buf;
}

static DWORD cms_dword_param(HCRYPTMSG msg, DWORD param, DWORD index)
{
    DWORD value = 0xdeadbeef, size = sizeof(value), ret;

    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, param, index, &value, &size);
    ok(ret, "param %lu failed: %08lx\n", param, GetLastError());
    return value;
}

/* decrypts with the recipient at index, with a CryptoAPI or an NCrypt key; returns the error or 0 */
static DWORD cms_decrypt(HCRYPTMSG msg, DWORD index, int key_kind /* 0: CAPI, 1: NCrypt A, 2: NCrypt B */)
{
    CMSG_CTRL_KEY_TRANS_DECRYPT_PARA para;
    CMSG_CMS_RECIPIENT_INFO *recipient;
    BOOL ret;

    recipient = cms_param(msg, CMSG_CMS_RECIPIENT_INFO_PARAM, index, NULL);
    ok(!!recipient, "CMSG_CMS_RECIPIENT_INFO_PARAM(%lu) failed: %08lx\n", index, GetLastError());
    if (!recipient) return 0xdeadbeef;
    ok(recipient->dwRecipientChoice == CMSG_KEY_TRANS_RECIPIENT, "got choice %lu\n", recipient->dwRecipientChoice);
    memset(&para, 0, sizeof(para));
    para.cbSize = sizeof(para);
    para.pKeyTrans = recipient->pKeyTrans;
    para.dwRecipientIndex = index;
    if (key_kind)
    {
        para.hCryptProv = key_kind == 1 ? cms_keys.ncrypt_a : cms_keys.ncrypt_b;
        para.dwKeySpec = CMS_NCRYPT_KEY_SPEC;
    }
    else
    {
        para.hCryptProv = cms_keys.capi_prov;
        para.dwKeySpec = AT_KEYEXCHANGE;
    }
    SetLastError(0xdeadbeef);
    ret = CryptMsgControl(msg, 0, CMSG_CTRL_KEY_TRANS_DECRYPT, &para);
    HeapFree(GetProcessHeap(), 0, recipient);
    return ret ? 0 : GetLastError();
}

static void cms_check_content(HCRYPTMSG msg, const char *name)
{
    DWORD len = 0;
    BYTE *content = cms_param(msg, CMSG_CONTENT_PARAM, 0, &len);

    ok(!!content, "%s: CMSG_CONTENT_PARAM failed: %08lx\n", name, GetLastError());
    if (!content) return;
    ok(len == sizeof(cms_plain) - 1 && !memcmp(content, cms_plain, len), "%s: wrong content, %lu bytes\n", name, len);
    HeapFree(GetProcessHeap(), 0, content);
}

/* the error of decrypting message data with key_kind, 0 if it worked and the content is right */
static DWORD cms_try(const BYTE *data, DWORD len, DWORD index, int key_kind, const char *name)
{
    HCRYPTMSG msg = cms_open(data, len);
    DWORD err;

    ok(!!msg, "%s: CryptMsgUpdate failed: %08lx\n", name, GetLastError());
    if (!msg) return 0xdeadbeef;
    err = cms_decrypt(msg, index, key_kind);
    if (!err) cms_check_content(msg, name);
    CryptMsgClose(msg);
    return err;
}

static const struct cms_message
{
    const char *name;
    const BYTE *data;
    DWORD len;
    DWORD version;
    const char *alg;
    DWORD params_len;       /* encoded parameters of the content encryption algorithm */
    DWORD key_id;           /* recipient identified by subject key identifier */
    const char *key_alg;
    int capi, ncrypt;       /* the key kinds Windows decrypts it with */
} cms_messages[] =
{
#define M(n, ver, alg, plen, kid, kalg, capi, ncrypt) { #n, cms_msg_##n, sizeof(cms_msg_##n), ver, alg, plen, kid, kalg, capi, ncrypt }
    M(aes128, 0, "2.16.840.1.101.3.4.1.2", 18, 0, "1.2.840.113549.1.1.1", 0, 1),
    M(aes192, 0, "2.16.840.1.101.3.4.1.22", 18, 0, "1.2.840.113549.1.1.1", 0, 1),
    M(aes256, 0, "2.16.840.1.101.3.4.1.42", 18, 0, "1.2.840.113549.1.1.1", 0, 1),
    M(3des, 0, "1.2.840.113549.3.7", 10, 0, "1.2.840.113549.1.1.1", 1, 1),
    M(des, 0, "1.3.14.3.2.7", 10, 0, "1.2.840.113549.1.1.1", 1, 1),
    M(rc2_40, 0, "1.2.840.113549.3.2", 16, 0, "1.2.840.113549.1.1.1", 1, 1),
    M(rc2_56, 0, "1.2.840.113549.3.2", 15, 0, "1.2.840.113549.1.1.1", 1, 1),
    M(rc2_64, 0, "1.2.840.113549.3.2", 15, 0, "1.2.840.113549.1.1.1", 1, 1),
    M(rc2_128, 0, "1.2.840.113549.3.2", 15, 0, "1.2.840.113549.1.1.1", 1, 1),
    M(rc4, 0, "1.2.840.113549.3.4", 0, 0, "1.2.840.113549.1.1.1", 1, 0),
    M(rc4_40, 0, "1.2.840.113549.3.4", 13, 0, "1.2.840.113549.1.1.1", 1, 0),
    M(ski, 2, "2.16.840.1.101.3.4.1.42", 18, 1, "1.2.840.113549.1.1.1", 0, 1),
    M(oaep_sha1, 0, "2.16.840.1.101.3.4.1.42", 18, 0, "1.2.840.113549.1.1.7", 0, 1),
    M(oaep_sha256, 0, "2.16.840.1.101.3.4.1.42", 18, 0, "1.2.840.113549.1.1.7", 0, 1),
    M(ber_segments, 0, "2.16.840.1.101.3.4.1.42", 18, 0, "1.2.840.113549.1.1.1", 0, 1),
    M(ber_indefinite, 0, "2.16.840.1.101.3.4.1.42", 18, 0, "1.2.840.113549.1.1.1", 0, 1),
    M(originator, 2, "2.16.840.1.101.3.4.1.42", 18, 0, "1.2.840.113549.1.1.1", 0, 1),
    M(version5, 5, "2.16.840.1.101.3.4.1.42", 18, 0, "1.2.840.113549.1.1.1", 0, 1),
#undef M
};

static void test_cms_decode_messages(void)
{
    static const BYTE keyid_issuer_head[] = { 0x30, 0x26, 0x31, 0x24, 0x30, 0x22, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x07, 0x01, 0x04, 0x14 };
    DWORD i;

    for (i = 0; i < ARRAY_SIZE(cms_messages); i++)
    {
        const struct cms_message *m = &cms_messages[i];
        CRYPT_ALGORITHM_IDENTIFIER *alg;
        CMSG_CMS_RECIPIENT_INFO *recipient;
        HCRYPTMSG msg;
        DWORD size, err;
        char *inner;

        msg = cms_open(m->data, m->len);
        ok(!!msg, "%s: CryptMsgUpdate failed: %08lx\n", m->name, GetLastError());
        if (!msg) continue;
        ok(cms_dword_param(msg, CMSG_TYPE_PARAM, 0) == CMSG_ENVELOPED, "%s: wrong type\n", m->name);
        ok(cms_dword_param(msg, CMSG_VERSION_PARAM, 0) == m->version, "%s: wrong version %lu\n", m->name,
           cms_dword_param(msg, CMSG_VERSION_PARAM, 0));
        ok(cms_dword_param(msg, CMSG_RECIPIENT_COUNT_PARAM, 0) == 1, "%s: wrong recipient count\n", m->name);
        ok(cms_dword_param(msg, CMSG_CMS_RECIPIENT_COUNT_PARAM, 0) == 1, "%s: wrong CMS recipient count\n", m->name);
        inner = cms_param(msg, CMSG_INNER_CONTENT_TYPE_PARAM, 0, NULL);
        ok(inner && !strcmp(inner, "1.2.840.113549.1.7.1"), "%s: wrong inner content type %s\n", m->name, inner);
        HeapFree(GetProcessHeap(), 0, inner);
        alg = cms_param(msg, CMSG_ENVELOPE_ALGORITHM_PARAM, 0, NULL);
        ok(!!alg, "%s: CMSG_ENVELOPE_ALGORITHM_PARAM failed: %08lx\n", m->name, GetLastError());
        if (alg)
        {
            ok(!strcmp(alg->pszObjId, m->alg), "%s: wrong algorithm %s\n", m->name, alg->pszObjId);
            ok(alg->Parameters.cbData == m->params_len, "%s: wrong parameters size %lu\n", m->name,
               alg->Parameters.cbData);
            HeapFree(GetProcessHeap(), 0, alg);
        }
        recipient = cms_param(msg, CMSG_CMS_RECIPIENT_INFO_PARAM, 0, &size);
        ok(!!recipient, "%s: CMSG_CMS_RECIPIENT_INFO_PARAM failed: %08lx\n", m->name, GetLastError());
        if (recipient)
        {
            CMSG_KEY_TRANS_RECIPIENT_INFO *kt = recipient->pKeyTrans;

            ok(recipient->dwRecipientChoice == CMSG_KEY_TRANS_RECIPIENT, "%s: wrong choice\n", m->name);
            ok(kt->dwVersion == (m->key_id ? 2 : 0), "%s: wrong recipient version %lu\n", m->name, kt->dwVersion);
            ok(!strcmp(kt->KeyEncryptionAlgorithm.pszObjId, m->key_alg), "%s: wrong key algorithm %s\n", m->name,
               kt->KeyEncryptionAlgorithm.pszObjId);
            ok(kt->EncryptedKey.cbData == 256, "%s: wrong encrypted key size %lu\n", m->name, kt->EncryptedKey.cbData);
            if (m->key_id)
            {
                ok(kt->RecipientId.dwIdChoice == CERT_ID_KEY_IDENTIFIER, "%s: wrong id choice %lu\n", m->name,
                   kt->RecipientId.dwIdChoice);
                ok(kt->RecipientId.KeyId.cbData == 20, "%s: wrong key id size\n", m->name);
            }
            else
            {
                ok(kt->RecipientId.dwIdChoice == CERT_ID_ISSUER_SERIAL_NUMBER, "%s: wrong id choice %lu\n", m->name,
                   kt->RecipientId.dwIdChoice);
                /* the serial number of certificate A has its high bit set: the zero byte of the DER integer stays */
                ok(kt->RecipientId.IssuerSerialNumber.SerialNumber.cbData == 17 &&
                   kt->RecipientId.IssuerSerialNumber.SerialNumber.pbData[16] == 0 &&
                   kt->RecipientId.IssuerSerialNumber.SerialNumber.pbData[15] == 0x8f,
                   "%s: wrong serial number, %lu bytes\n", m->name, kt->RecipientId.IssuerSerialNumber.SerialNumber.cbData);
            }
            HeapFree(GetProcessHeap(), 0, recipient);
        }
        /* the legacy view of the recipient */
        {
            CERT_INFO *info = cms_param(msg, CMSG_RECIPIENT_INFO_PARAM, 0, NULL);

            ok(!!info, "%s: CMSG_RECIPIENT_INFO_PARAM failed: %08lx\n", m->name, GetLastError());
            if (info && m->key_id)
            {
                ok(info->SerialNumber.cbData == 1 && !info->SerialNumber.pbData[0], "%s: wrong legacy serial number\n", m->name);
                ok(info->Issuer.cbData == sizeof(keyid_issuer_head) + 20 &&
                   !memcmp(info->Issuer.pbData, keyid_issuer_head, sizeof(keyid_issuer_head)),
                   "%s: wrong legacy issuer\n", m->name);
            }
            HeapFree(GetProcessHeap(), 0, info);
        }
        CryptMsgClose(msg);

        if (m->capi && cms_keys.have_capi)
        {
            err = cms_try(m->data, m->len, 0, 0, m->name);
            ok(!err, "%s: CryptoAPI key: %08lx\n", m->name, err);
        }
        if (m->ncrypt && cms_keys.have_ncrypt)
        {
            err = cms_try(m->data, m->len, 0, 1, m->name);
            ok(!err, "%s: NCrypt key: %08lx\n", m->name, err);
        }
    }
}

static void test_cms_get_params(void)
{
    CRYPT_ATTRIBUTES *attrs;
    HCRYPTMSG msg;
    DWORD size, ret;
    BYTE *cert;

    msg = cms_open(cms_msg_aes256, sizeof(cms_msg_aes256));
    ok(!!msg, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    if (!msg) return;
    ok(cms_dword_param(msg, CMSG_RECIPIENT_INDEX_PARAM, 0) == 0, "wrong recipient index\n");
    ok(cms_dword_param(msg, CMSG_CMS_RECIPIENT_INDEX_PARAM, 3) == 0, "wrong CMS recipient index\n");
    size = 0;
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_CMS_RECIPIENT_INFO_PARAM, 1, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX, "expected CRYPT_E_INVALID_INDEX, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_INVALID_INDEX, "expected CRYPT_E_INVALID_INDEX, got %08lx\n", GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_UNPROTECTED_ATTR_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == CRYPT_E_ATTRIBUTES_MISSING, "expected CRYPT_E_ATTRIBUTES_MISSING, got %08lx\n", GetLastError());
    ok(cms_dword_param(msg, CMSG_CERT_COUNT_PARAM, 0) == 0, "wrong certificate count\n");
    CryptMsgClose(msg);

    msg = cms_open(cms_msg_originator, sizeof(cms_msg_originator));
    ok(!!msg, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    if (!msg) return;
    ok(cms_dword_param(msg, CMSG_CERT_COUNT_PARAM, 0) == 1, "wrong certificate count\n");
    cert = cms_param(msg, CMSG_CERT_PARAM, 0, &size);
    ok(cert && size == sizeof(cms_cert_a) && !memcmp(cert, cms_cert_a, size), "wrong certificate\n");
    HeapFree(GetProcessHeap(), 0, cert);
    attrs = cms_param(msg, CMSG_UNPROTECTED_ATTR_PARAM, 0, NULL);
    ok(!!attrs, "CMSG_UNPROTECTED_ATTR_PARAM failed: %08lx\n", GetLastError());
    if (attrs)
    {
        ok(attrs->cAttr == 1 && !strcmp(attrs->rgAttr[0].pszObjId, "1.2.3.4.5") && attrs->rgAttr[0].cValue == 1 &&
           attrs->rgAttr[0].rgValue[0].cbData == 4, "wrong attribute\n");
        HeapFree(GetProcessHeap(), 0, attrs);
    }
    CryptMsgClose(msg);
}

static void test_cms_decrypt_errors(void)
{
    static const struct
    {
        const char *name;
        const BYTE *data;
        DWORD len;
        DWORD error;
    } tests[] =
    {
        { "unknown_alg", cms_msg_unknown_alg, sizeof(cms_msg_unknown_alg), CRYPT_E_UNKNOWN_ALGO },
        { "iv_short", cms_msg_iv_short, sizeof(cms_msg_iv_short), CRYPT_E_BAD_ENCODE },
        { "null_params", cms_msg_null_params, sizeof(cms_msg_null_params), CRYPT_E_BAD_ENCODE },
        { "bad_padding", cms_msg_bad_padding, sizeof(cms_msg_bad_padding), CMS_STATUS_DATA_ERROR },
        { "short_content", cms_msg_short_content, sizeof(cms_msg_short_content), CMS_STATUS_INVALID_BUFFER_SIZE },
        { "cek17", cms_msg_cek17, sizeof(cms_msg_cek17), CMS_STATUS_INVALID_PARAMETER },
    };
    HCRYPTMSG msg;
    DWORD i, err;

    if (!cms_keys.have_ncrypt)
    {
        skip("no NCrypt keys\n");
        return;
    }
    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        err = cms_try(tests[i].data, tests[i].len, 0, 1, tests[i].name);
        ok(err == tests[i].error, "%s: expected %08lx, got %08lx\n", tests[i].name, tests[i].error, err);
    }

    /* no content at all, and empty content, decrypt to nothing */
    msg = cms_open(cms_msg_empty_content, sizeof(cms_msg_empty_content));
    ok(!!msg, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    if (msg)
    {
        DWORD size = 1;

        err = cms_decrypt(msg, 0, 1);
        ok(!err, "expected success, got %08lx\n", err);
        ok(CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size) && !size, "expected empty content\n");
        err = cms_decrypt(msg, 0, 1);
        ok(err == CRYPT_E_ALREADY_DECRYPTED, "expected CRYPT_E_ALREADY_DECRYPTED, got %08lx\n", err);
        CryptMsgClose(msg);
    }

    /* the wrong key, and a recipient that does not exist */
    msg = cms_open(cms_msg_aes256, sizeof(cms_msg_aes256));
    ok(!!msg, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    if (msg)
    {
        err = cms_decrypt(msg, 0, 2);
        ok(err == NTE_INVALID_PARAMETER, "expected NTE_INVALID_PARAMETER, got %08lx\n", err);
        err = cms_decrypt(msg, 0, 1);
        ok(!err, "expected success after a failed attempt, got %08lx\n", err);
        cms_check_content(msg, "after a failed attempt");
        CryptMsgClose(msg);
    }
}

static void test_cms_two_recipients(void)
{
    DWORD err, index, found_a = 0, found_b = 0;

    if (!cms_keys.have_ncrypt)
    {
        skip("no NCrypt keys\n");
        return;
    }
    for (index = 0; index < 2; index++)
    {
        err = cms_try(cms_msg_two, sizeof(cms_msg_two), index, 1, "two A");
        if (!err) found_a++;
        err = cms_try(cms_msg_two, sizeof(cms_msg_two), index, 2, "two B");
        if (!err) found_b++;
    }
    ok(found_a == 1, "key A worked for %lu recipients\n", found_a);
    ok(found_b == 1, "key B worked for %lu recipients\n", found_b);
}

/* messages made by CryptMsgOpenToEncode, read back and decrypted */
static void cms_encode_and_check(const char *name, const char *alg_oid, void *aux, int kind /* 0 issuer, 1 key id, 2 OAEP, 3 legacy */,
                                 DWORD version, const char *key_alg, int capi, int ncrypt)
{
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, cms_cert_a, sizeof(cms_cert_a));
    cms_enveloped_encode_info info;
    CMSG_RECIPIENT_ENCODE_INFO recipient;
    CMSG_KEY_TRANS_RECIPIENT_ENCODE_INFO trans;
    PCERT_INFO cert_info;
    BYTE key_id[20];
    DWORD key_id_size = sizeof(key_id), size, err;
    char rsa[] = "1.2.840.113549.1.1.1", oaep[] = "1.2.840.113549.1.1.7";
    HCRYPTMSG msg;
    BYTE *encoded;
    BOOL ret;

    ok(!!cert, "CertCreateCertificateContext failed: %08lx\n", GetLastError());
    if (!cert) return;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.ContentEncryptionAlgorithm.pszObjId = (char *)alg_oid;
    info.pvEncryptionAuxInfo = aux;
    info.cRecipients = 1;
    memset(&trans, 0, sizeof(trans));
    trans.cbSize = sizeof(trans);
    trans.KeyEncryptionAlgorithm.pszObjId = kind == 2 ? oaep : rsa;
    trans.RecipientPublicKey = cert->pCertInfo->SubjectPublicKeyInfo.PublicKey;
    if (kind == 1)
    {
        ret = CertGetCertificateContextProperty(cert, CERT_KEY_IDENTIFIER_PROP_ID, key_id, &key_id_size);
        ok(ret, "CertGetCertificateContextProperty failed: %08lx\n", GetLastError());
        trans.RecipientId.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
        trans.RecipientId.KeyId.cbData = key_id_size;
        trans.RecipientId.KeyId.pbData = key_id;
    }
    else
    {
        trans.RecipientId.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;
        trans.RecipientId.IssuerSerialNumber.Issuer = cert->pCertInfo->Issuer;
        trans.RecipientId.IssuerSerialNumber.SerialNumber = cert->pCertInfo->SerialNumber;
    }
    recipient.dwRecipientChoice = CMSG_KEY_TRANS_RECIPIENT;
    recipient.pKeyTrans = &trans;
    cert_info = cert->pCertInfo;
    if (kind == 3) info.rgpRecipientCert = &cert_info;
    else info.rgCmsRecipients = &recipient;

    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, NULL, NULL);
    ok(!!msg, "%s: CryptMsgOpenToEncode failed: %08lx\n", name, GetLastError());
    if (msg)
    {
        ret = CryptMsgUpdate(msg, (const BYTE *)cms_plain, sizeof(cms_plain) - 1, TRUE);
        ok(ret, "%s: CryptMsgUpdate failed: %08lx\n", name, GetLastError());
        size = 0;
        ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
        ok(ret, "%s: CryptMsgGetParam failed: %08lx\n", name, GetLastError());
        encoded = HeapAlloc(GetProcessHeap(), 0, size);
        ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, encoded, &size);
        ok(ret, "%s: CryptMsgGetParam failed: %08lx\n", name, GetLastError());
        CryptMsgClose(msg);
        if (ret)
        {
            CRYPT_ALGORITHM_IDENTIFIER *alg;
            CMSG_CMS_RECIPIENT_INFO *r;
            char *inner_type;

            msg = cms_open(encoded, size);
            ok(!!msg, "%s: CryptMsgUpdate failed: %08lx\n", name, GetLastError());
            if (msg)
            {
                ok(cms_dword_param(msg, CMSG_VERSION_PARAM, 0) == version, "%s: wrong version %lu\n", name,
                   cms_dword_param(msg, CMSG_VERSION_PARAM, 0));
                alg = cms_param(msg, CMSG_ENVELOPE_ALGORITHM_PARAM, 0, NULL);
                ok(alg && !strcmp(alg->pszObjId, alg_oid), "%s: wrong algorithm\n", name);
                if (alg && !strcmp(alg_oid, "2.16.840.1.101.3.4.1.2"))
                    ok(alg->Parameters.cbData == 18 && alg->Parameters.pbData[0] == 4 && alg->Parameters.pbData[1] == 16,
                       "%s: AES parameters are not an IV\n", name);
                if (alg && !strcmp(alg_oid, "1.2.840.113549.3.7"))
                    ok(alg->Parameters.cbData == 10 && alg->Parameters.pbData[0] == 4 && alg->Parameters.pbData[1] == 8,
                       "%s: 3DES parameters are not an IV\n", name);
                if (alg && !strcmp(alg_oid, "1.2.840.113549.3.2"))
                {
                    cms_rc2_aux *rc2 = aux;
                    BYTE version_byte = rc2->dwBitLen == 40 ? 0xa0 : rc2->dwBitLen == 56 ? 52 : rc2->dwBitLen == 64 ? 120 : 58;

                    ok(alg->Parameters.cbData >= 13 && alg->Parameters.pbData[0] == 0x30 && alg->Parameters.pbData[alg->Parameters.cbData - 10] == 4 &&
                       alg->Parameters.pbData[alg->Parameters.cbData - 9] == 8 && alg->Parameters.pbData[alg->Parameters.cbData - 11] == version_byte,
                       "%s: RC2 parameters are wrong\n", name);
                }
                HeapFree(GetProcessHeap(), 0, alg);
                inner_type = cms_param(msg, CMSG_INNER_CONTENT_TYPE_PARAM, 0, NULL);
                ok(inner_type && !strcmp(inner_type, "1.2.840.113549.1.7.1"), "%s: wrong inner type %s\n", name, inner_type);
                HeapFree(GetProcessHeap(), 0, inner_type);
                r = cms_param(msg, CMSG_CMS_RECIPIENT_INFO_PARAM, 0, NULL);
                ok(!!r, "%s: no recipient: %08lx\n", name, GetLastError());
                if (r)
                {
                    ok(r->pKeyTrans->dwVersion == (kind == 1 ? 2 : 0), "%s: wrong recipient version\n", name);
                    if (key_alg) ok(!strcmp(r->pKeyTrans->KeyEncryptionAlgorithm.pszObjId, key_alg), "%s: wrong key algorithm %s\n", name,
                                    r->pKeyTrans->KeyEncryptionAlgorithm.pszObjId);
                    HeapFree(GetProcessHeap(), 0, r);
                }
                CryptMsgClose(msg);
            }
            if (capi && cms_keys.have_capi)
            {
                err = cms_try(encoded, size, 0, 0, name);
                ok(!err, "%s: CryptoAPI key: %08lx\n", name, err);
            }
            if (ncrypt && cms_keys.have_ncrypt)
            {
                err = cms_try(encoded, size, 0, 1, name);
                ok(!err, "%s: NCrypt key: %08lx\n", name, err);
            }
        }
        HeapFree(GetProcessHeap(), 0, encoded);
    }
    CertFreeCertificateContext(cert);
}

static void test_cms_encode(void)
{
    cms_rc2_aux rc2_40 = { sizeof(cms_rc2_aux), 40 }, rc2_56 = { sizeof(cms_rc2_aux), 56 }, rc2_64 = { sizeof(cms_rc2_aux), 64 },
                rc2_128 = { sizeof(cms_rc2_aux), 128 };
    static const char rsa[] = "1.2.840.113549.1.1.1";
    cms_rc2_aux rc4_40 = { sizeof(cms_rc2_aux), 40 };
    cms_enveloped_encode_info info;
    HCRYPTMSG msg;

    cms_encode_and_check("aes128", "2.16.840.1.101.3.4.1.2", NULL, 0, 0, rsa, 0, 1);
    cms_encode_and_check("aes192", "2.16.840.1.101.3.4.1.22", NULL, 0, 0, rsa, 0, 1);
    cms_encode_and_check("aes256", "2.16.840.1.101.3.4.1.42", NULL, 0, 0, rsa, 0, 1);
    cms_encode_and_check("aes256 key id", "2.16.840.1.101.3.4.1.42", NULL, 1, 2, rsa, 0, 1);
    cms_encode_and_check("aes256 OAEP", "2.16.840.1.101.3.4.1.42", NULL, 2, 0, "1.2.840.113549.1.1.7", 0, 1);
    cms_encode_and_check("3des", "1.2.840.113549.3.7", NULL, 0, 0, rsa, 1, 1);
    cms_encode_and_check("3des legacy", "1.2.840.113549.3.7", NULL, 3, 0, rsa, 1, 1);
    cms_encode_and_check("des", "1.3.14.3.2.7", NULL, 0, 0, rsa, 1, 1);
    cms_encode_and_check("rc2 40", "1.2.840.113549.3.2", &rc2_40, 0, 0, rsa, 1, 1);
    cms_encode_and_check("rc2 56", "1.2.840.113549.3.2", &rc2_56, 0, 0, rsa, 1, 1);
    cms_encode_and_check("rc2 64", "1.2.840.113549.3.2", &rc2_64, 0, 0, rsa, 1, 1);
    cms_encode_and_check("rc2 128", "1.2.840.113549.3.2", &rc2_128, 0, 0, rsa, 1, 1);
    cms_encode_and_check("rc2 40 legacy", "1.2.840.113549.3.2", &rc2_40, 3, 0, rsa, 1, 1);
    cms_encode_and_check("rc4 40", "1.2.840.113549.3.4", &rc4_40, 0, 0, rsa, 1, 0);
    cms_encode_and_check("aes128 legacy", "2.16.840.1.101.3.4.1.2", NULL, 3, 0, NULL, 0, 1);

    /* unknown algorithms are CRYPT_E_UNKNOWN_ALGO, with or without recipients */
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.ContentEncryptionAlgorithm.pszObjId = (char *)"1.2.3.4.5";
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, NULL, NULL);
    ok(!msg && GetLastError() == CRYPT_E_UNKNOWN_ALGO, "expected CRYPT_E_UNKNOWN_ALGO, got %08lx\n", GetLastError());
    if (msg) CryptMsgClose(msg);
    /* recipients that are announced but missing */
    info.ContentEncryptionAlgorithm.pszObjId = (char *)"2.16.840.1.101.3.4.1.42";
    info.cRecipients = 1;
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, NULL, NULL);
    ok(!msg && GetLastError() == E_INVALIDARG, "expected E_INVALIDARG, got %08lx\n", GetLastError());
    if (msg) CryptMsgClose(msg);
}

/* messages made with an inner content type: the data are an encoded value, its content is encrypted */
static void cms_encode_inner(const char *inner, const BYTE *input, DWORD input_len, DWORD update_error,
                             const BYTE *expect, DWORD expect_len, const char *name)
{
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, cms_cert_a, sizeof(cms_cert_a));
    cms_enveloped_encode_info info;
    PCERT_INFO cert_info = cert->pCertInfo;
    HCRYPTMSG msg;
    BYTE *encoded = NULL;
    DWORD size = 0;
    BOOL ret;

    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.ContentEncryptionAlgorithm.pszObjId = (char *)"2.16.840.1.101.3.4.1.42";
    info.cRecipients = 1;
    info.rgpRecipientCert = &cert_info;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, (char *)inner, NULL);
    ok(!!msg, "%s: CryptMsgOpenToEncode failed: %08lx\n", name, GetLastError());
    if (msg)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgUpdate(msg, input, input_len, TRUE);
        if (update_error)
        {
            ok(!ret && GetLastError() == update_error, "%s: expected %08lx, got %d, %08lx\n", name, update_error, ret, GetLastError());
        }
        else
        {
            ok(ret, "%s: CryptMsgUpdate failed: %08lx\n", name, GetLastError());
            CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
            encoded = HeapAlloc(GetProcessHeap(), 0, size);
            ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, encoded, &size);
            ok(ret, "%s: CryptMsgGetParam failed: %08lx\n", name, GetLastError());
        }
        CryptMsgClose(msg);
    }
    if (encoded && ret)
    {
        HCRYPTMSG dec = cms_open(encoded, size);
        char *type;
        DWORD len = 0, err;
        BYTE *content;

        ok(!!dec, "%s: CryptMsgUpdate failed: %08lx\n", name, GetLastError());
        if (dec)
        {
            type = cms_param(dec, CMSG_INNER_CONTENT_TYPE_PARAM, 0, NULL);
            ok(type && !strcmp(type, inner), "%s: wrong inner type %s\n", name, type);
            HeapFree(GetProcessHeap(), 0, type);
            err = cms_decrypt(dec, 0, cms_keys.have_ncrypt ? 1 : 0);
            ok(!err || !cms_keys.have_capi, "%s: decrypt failed: %08lx\n", name, err);
            if (!err)
            {
                content = cms_param(dec, CMSG_CONTENT_PARAM, 0, &len);
                ok(content && len == expect_len && !memcmp(content, expect, len), "%s: wrong content, %lu bytes\n", name, len);
                HeapFree(GetProcessHeap(), 0, content);
            }
            CryptMsgClose(dec);
        }
    }
    HeapFree(GetProcessHeap(), 0, encoded);
    CertFreeCertificateContext(cert);
}

static void test_cms_inner_type(void)
{
    static const BYTE octet_string[] = { 0x04, 0x2c, 'h','e','l','l','o',' ','C','M','S',' ','e','n','v','e','l','o','p','e','d',' ','w','o','r','l','d',',',' ',
                                         '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','!' };
    static const BYTE sequence_wrapped[] = { 0x30, 0x2c, 'h','e','l','l','o',' ','C','M','S',' ','e','n','v','e','l','o','p','e','d',' ','w','o','r','l','d',',',' ',
                                             '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','!' };

    if (!cms_keys.have_capi && !cms_keys.have_ncrypt) { skip("no keys\n"); return; }
    cms_encode_inner("1.2.840.113549.1.7.1", octet_string, sizeof(octet_string), 0, (const BYTE *)cms_plain, sizeof(cms_plain) - 1, "inner data");
    cms_encode_inner("1.2.3.4.5", octet_string, sizeof(octet_string), 0, sequence_wrapped, sizeof(sequence_wrapped), "inner custom");
    cms_encode_inner("1.2.840.113549.1.7.1", (const BYTE *)cms_plain, sizeof(cms_plain) - 1, CRYPT_E_UNEXPECTED_ENCODING, NULL, 0,
                     "inner data, not encoded");
}

static void test_cms_rc2_params(void)
{
    static const BYTE encoded[] = { 0x30, 0x0e, 0x02, 0x02, 0x00, 0xa0, 0x04, 0x08, 1, 2, 3, 4, 5, 6, 7, 8 };
    static const BYTE encoded56[] = { 0x30, 0x0d, 0x02, 0x01, 0x34, 0x04, 0x08, 1, 2, 3, 4, 5, 6, 7, 8 };
    static const BYTE no_iv[] = { 0x30, 0x03, 0x02, 0x01, 0x3a };
    CRYPT_RC2_CBC_PARAMETERS params, *decoded;
    DWORD size;
    BYTE *buffer;
    BOOL ret;

    size = sizeof(params);
    memset(&params, 0xcc, sizeof(params));
    SetLastError(0xdeadbeef);
    ret = CryptDecodeObject(X509_ASN_ENCODING, PKCS_RC2_CBC_PARAMETERS, encoded, sizeof(encoded), 0, &params, &size);
    ok(ret, "CryptDecodeObject failed: %08lx\n", GetLastError());
    if (ret)
    {
        ok(params.dwVersion == 160 && params.fIV && !memcmp(params.rgbIV, "\1\2\3\4\5\6\7\x8", 8), "wrong parameters\n");
        size = 0;
        ret = CryptEncodeObjectEx(X509_ASN_ENCODING, PKCS_RC2_CBC_PARAMETERS, &params, CRYPT_ENCODE_ALLOC_FLAG, NULL, &buffer, &size);
        ok(ret, "CryptEncodeObjectEx failed: %08lx\n", GetLastError());
        if (ret)
        {
            ok(size == sizeof(encoded) && !memcmp(buffer, encoded, size), "wrong encoding\n");
            LocalFree(buffer);
        }
    }
    ret = CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RC2_CBC_PARAMETERS, encoded56, sizeof(encoded56), CRYPT_DECODE_ALLOC_FLAG, NULL, &decoded, &size);
    ok(ret, "CryptDecodeObjectEx failed: %08lx\n", GetLastError());
    if (ret)
    {
        ok(decoded->dwVersion == 52 && decoded->fIV, "wrong parameters\n");
        LocalFree(decoded);
    }
    ret = CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RC2_CBC_PARAMETERS, no_iv, sizeof(no_iv), CRYPT_DECODE_ALLOC_FLAG, NULL, &decoded, &size);
    ok(ret, "CryptDecodeObjectEx failed: %08lx\n", GetLastError());
    if (ret)
    {
        ok(decoded->dwVersion == 58 && !decoded->fIV, "wrong parameters\n");
        LocalFree(decoded);
    }
    SetLastError(0xdeadbeef);
    size = sizeof(params);
    ret = CryptDecodeObject(X509_ASN_ENCODING, PKCS_RC2_CBC_PARAMETERS, encoded, sizeof(encoded) - 1, 0, &params, &size);
    ok(!ret && (GetLastError() == CRYPT_E_ASN1_EOD || GetLastError() == CRYPT_E_ASN1_CORRUPT), "got %d, %08lx\n", ret, GetLastError());
}

/* an RC2 message made with parameters of the caller: the content key has the size of the parameters (here 128
 * bits), and all of it is random */
static void test_cms_rc2_key(void)
{
    static const BYTE params[] = { 0x30, 0x0d, 0x02, 0x01, 0x3a, 0x04, 0x08, 1, 2, 3, 4, 5, 6, 7, 8 };
    PCCERT_CONTEXT cert;
    cms_enveloped_encode_info info;
    PCERT_INFO cert_info;
    HCRYPTMSG msg, dec;
    BYTE *encoded = NULL, key[256];
    CMSG_CMS_RECIPIENT_INFO *recipient;
    cms_NCryptDecrypt decrypt;
    HMODULE ncrypt;
    DWORD size = 0, key_len = 0, i;
    BOOL ret, tail_random = FALSE;
    LONG status;

    if (!cms_keys.have_ncrypt)
    {
        skip("no NCrypt keys\n");
        return;
    }
    ncrypt = GetModuleHandleW(L"ncrypt.dll");
    decrypt = ncrypt ? (void *)GetProcAddress(ncrypt, "NCryptDecrypt") : NULL;
    if (!decrypt) { skip("no NCryptDecrypt\n"); return; }
    cert = CertCreateCertificateContext(X509_ASN_ENCODING, cms_cert_a, sizeof(cms_cert_a));
    cert_info = cert->pCertInfo;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.ContentEncryptionAlgorithm.pszObjId = (char *)"1.2.840.113549.3.2";
    info.ContentEncryptionAlgorithm.Parameters.cbData = sizeof(params);
    info.ContentEncryptionAlgorithm.Parameters.pbData = (BYTE *)params;
    info.cRecipients = 1;
    info.rgpRecipientCert = &cert_info;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, NULL, NULL);
    ok(!!msg, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());
    if (msg)
    {
        ret = CryptMsgUpdate(msg, (const BYTE *)"rc2 key", 7, TRUE);
        ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
        CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
        encoded = HeapAlloc(GetProcessHeap(), 0, size);
        ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, encoded, &size);
        ok(ret, "CryptMsgGetParam failed: %08lx\n", GetLastError());
        CryptMsgClose(msg);
    }
    dec = encoded ? cms_open(encoded, size) : NULL;
    ok(!encoded || !!dec, "CryptMsgUpdate failed: %08lx\n", GetLastError());
    if (dec)
    {
        recipient = cms_param(dec, CMSG_CMS_RECIPIENT_INFO_PARAM, 0, NULL);
        ok(!!recipient, "CMSG_CMS_RECIPIENT_INFO_PARAM failed: %08lx\n", GetLastError());
        if (recipient)
        {
            status = decrypt(cms_keys.ncrypt_a, recipient->pKeyTrans->EncryptedKey.pbData, recipient->pKeyTrans->EncryptedKey.cbData,
                             NULL, key, sizeof(key), &key_len, 2);
            ok(!status, "NCryptDecrypt failed: %08lx\n", status);
            ok(!status && key_len == 16, "expected a 128 bit key, got %lu bytes\n", key_len);
            for (i = 5; !status && i < key_len; i++) if (key[i]) tail_random = TRUE;
            ok(status || tail_random, "the key bytes behind the first 40 bits are all zero\n");
            HeapFree(GetProcessHeap(), 0, recipient);
        }
        CryptMsgClose(dec);
    }
    HeapFree(GetProcessHeap(), 0, encoded);
    CertFreeCertificateContext(cert);
}

static void test_cms_oid_info(void)
{
    static const struct { const char *oid; const WCHAR *name; ALG_ID alg; } tests[] =
    {
        { "2.16.840.1.101.3.4.1.2", L"aes128", (ALG_ID)-1 },
        { "2.16.840.1.101.3.4.1.22", L"aes192", (ALG_ID)-1 },
        { "2.16.840.1.101.3.4.1.42", L"aes256", (ALG_ID)-1 },
        { "1.2.840.113549.3.7", L"3des", CALG_3DES },
    };
    DWORD i;

    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void *)tests[i].oid, CRYPT_ENCRYPT_ALG_OID_GROUP_ID);

        ok(!!info, "%s: CryptFindOIDInfo failed: %08lx\n", tests[i].oid, GetLastError());
        if (!info) continue;
        ok(!lstrcmpW(info->pwszName, tests[i].name), "%s: wrong name %ls\n", tests[i].oid, info->pwszName);
        ok(info->Algid == tests[i].alg, "%s: wrong algid %08x\n", tests[i].oid, info->Algid);
    }
}

/* malformed messages must be refused cleanly: the lengths inside the originatorInfo, the recipient set and the
 * encrypted content are checked against the bytes that are there */
static void test_cms_malformed(void)
{
    static const BYTE ci_head[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03 };
    static const struct { const char *name; BYTE data[24]; DWORD len; } tests[] =
    {
        { "originator_length_past_end", { 0x30, 0x05, 0x02, 0x01, 0xff, 0xa0, 0x2f }, 7 },
        { "originator_long_length", { 0x30, 0x09, 0x02, 0x01, 0x00, 0xa0, 0x84, 0xff, 0xff, 0xff, 0xff }, 11 },
        { "originator_indefinite_open", { 0x30, 0x06, 0x02, 0x01, 0x00, 0xa0, 0x80, 0x00 }, 8 },
        { "originator_one_byte", { 0x30, 0x04, 0x02, 0x01, 0x00, 0xa0 }, 6 },
        { "recipient_set_length_past_end", { 0x30, 0x07, 0x02, 0x01, 0x00, 0x31, 0x7f, 0x30, 0x00 }, 9 },
        { "recipient_set_missing", { 0x30, 0x03, 0x02, 0x01, 0x00 }, 5 },
    };
    DWORD i;

    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        BYTE msg_data[64], *p = msg_data;
        HCRYPTMSG msg;
        DWORD inner = tests[i].len;

        *p++ = 0x30;
        *p++ = sizeof(ci_head) + 2 + inner;
        memcpy(p, ci_head, sizeof(ci_head));
        p += sizeof(ci_head);
        *p++ = 0xa0;
        *p++ = inner;
        memcpy(p, tests[i].data, inner);
        p += inner;
        msg = cms_open(msg_data, p - msg_data);
        ok(!msg, "%s: expected failure\n", tests[i].name);
        if (msg) CryptMsgClose(msg);
    }
}

/* ---- CryptoAPI keys, streamed messages and the size guards ---- */

#include "msg_fixtures2.h"

#ifndef NTE_BAD_TYPE
#define NTE_BAD_TYPE ((HRESULT)0x8009000A)
#endif
#ifndef NTE_BAD_ALGID
#define NTE_BAD_ALGID ((HRESULT)0x80090008)
#endif
#ifndef NTE_BAD_DATA
#define NTE_BAD_DATA ((HRESULT)0x80090005)
#endif

/* Decrypts messages with a CryptoAPI exchange key that is not exportable (imported with flags 0) and with one
 * that is, in a PROV_RSA_FULL and a PROV_RSA_AES provider. Windows (22H2, measured) decrypts messages with a
 * 3DES, RC2 or RC4 content cipher and a PKCS #1 v1.5 wrapped key with all four keys, and fails everything else
 * with NTE_BAD_TYPE: the AES ones, and the OAEP wrapped ones whatever the content cipher. We decrypt them
 * all but OAEP with a hash other than SHA-1 (NTE_BAD_ALGID): the key is unwrapped with CryptDecrypt (PKCS #1
 * v1.5 or CRYPT_OAEP) and never exported, so no provider has to know the content cipher. */
static void test_cms_capi_keys(void)
{
    static const struct { const char *name; const char *provider; DWORD type; } provs[] =
    {
        { "RSA_FULL", MS_ENHANCED_PROV_A, PROV_RSA_FULL },
        { "RSA_AES", MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES },
    };
    static const struct { const char *name; const BYTE *data; DWORD len; int windows; } msgs[] =
    {
        /* windows: 1 works, 0 fails with NTE_BAD_TYPE; 2: fails with NTE_BAD_TYPE there, with NTE_BAD_ALGID here */
#define M(n, w) { #n, cms_msg_##n, sizeof(cms_msg_##n), w }
        M(3des, 1), M(rc2_40, 1), M(rc4, 1), M(aes128, 0), M(aes256, 0), M(ski, 0),
        M(oaep_sha1, 0), M(oaep_3des, 0), M(oaep_rc2_40, 0), M(oaep_3des_sha256, 2),
#undef M
    };
    DWORD p, e, m, c;

    for (p = 0; p < ARRAY_SIZE(provs); p++)
        for (e = 0; e < 2; e++)
        {
            HCRYPTPROV prov;
            HCRYPTKEY key;

            if (!CryptAcquireContextA(&prov, NULL, provs[p].provider, provs[p].type, CRYPT_VERIFYCONTEXT))
            {
                skip("%s: no provider: %08lx\n", provs[p].name, GetLastError());
                continue;
            }
            if (!CryptImportKey(prov, cms_key_a_capi, sizeof(cms_key_a_capi), 0, e ? CRYPT_EXPORTABLE : 0, &key))
            {
                skip("%s: cannot import the key: %08lx\n", provs[p].name, GetLastError());
                CryptReleaseContext(prov, 0);
                continue;
            }
            for (m = 0; m < ARRAY_SIZE(msgs); m++)
                for (c = 0; c < 2; c++)
                {
                    HCRYPTMSG msg = cms_open(msgs[m].data, msgs[m].len);
                    DWORD err, len = 0;
                    BYTE *content;
                    BOOL ret;

                    ok(!!msg, "%s: CryptMsgUpdate failed: %08lx\n", msgs[m].name, GetLastError());
                    if (!msg) continue;
                    if (c)
                    {
                        CMSG_CTRL_DECRYPT_PARA para = { sizeof(para), prov, AT_KEYEXCHANGE, 0 };

                        SetLastError(0xdeadbeef);
                        ret = CryptMsgControl(msg, 0, CMSG_CTRL_DECRYPT, &para);
                    }
                    else
                    {
                        CMSG_CTRL_KEY_TRANS_DECRYPT_PARA para = { sizeof(para) };
                        CMSG_CMS_RECIPIENT_INFO *recipient = cms_param(msg, CMSG_CMS_RECIPIENT_INFO_PARAM, 0, NULL);

                        ok(!!recipient, "%s: no recipient: %08lx\n", msgs[m].name, GetLastError());
                        if (!recipient) { CryptMsgClose(msg); continue; }
                        para.hCryptProv = prov;
                        para.dwKeySpec = AT_KEYEXCHANGE;
                        para.pKeyTrans = recipient->pKeyTrans;
                        SetLastError(0xdeadbeef);
                        ret = CryptMsgControl(msg, 0, CMSG_CTRL_KEY_TRANS_DECRYPT, &para);
                        HeapFree(GetProcessHeap(), 0, recipient);
                    }
                    err = ret ? 0 : GetLastError();
                    if (!err)
                    {
                        content = cms_param(msg, CMSG_CONTENT_PARAM, 0, &len);
                        ok(content && len == sizeof(cms_plain) - 1 && !memcmp(content, cms_plain, len),
                           "%s %s exportable %lu: wrong content\n", provs[p].name, msgs[m].name, e);
                        HeapFree(GetProcessHeap(), 0, content);
                    }
                    if (msgs[m].windows == 1)
                        ok(!err, "%s %s exportable %lu control %lu: got %08lx\n", provs[p].name, msgs[m].name, e, c, err);
                    else if (!msgs[m].windows)
                        ok(!err || err == NTE_BAD_TYPE, "%s %s exportable %lu control %lu: got %08lx\n",
                           provs[p].name, msgs[m].name, e, c, err);
                    else
                        ok(err == NTE_BAD_TYPE || err == NTE_BAD_ALGID, "%s %s exportable %lu control %lu: got %08lx\n",
                           provs[p].name, msgs[m].name, e, c, err);
#ifdef __REACTOS__
                    /* what we do beyond Windows: AES and SHA-1 OAEP decrypt with a CryptoAPI key */
                    if (!msgs[m].windows)
                        ok(!err, "%s %s exportable %lu control %lu: got %08lx\n", provs[p].name, msgs[m].name, e, c, err);
                    else if (msgs[m].windows == 2)
                        ok(err == NTE_BAD_ALGID, "%s %s: expected NTE_BAD_ALGID, got %08lx\n", provs[p].name, msgs[m].name, err);
#endif
                    CryptMsgClose(msg);
                }
            CryptDestroyKey(key);
            CryptReleaseContext(prov, 0);
        }
}

/* what a streamed message sends to the callback */
struct cms_stream
{
    DWORD count;
    struct { DWORD len; BOOL final; DWORD first; } cb[16];     /* first: the first byte of the piece */
    BYTE *all;
    DWORD all_len;
};

static BOOL WINAPI cms_stream_output(const void *arg, BYTE *pb, DWORD cb, BOOL final)
{
    struct cms_stream *s = (struct cms_stream *)arg;

    if (s->count < ARRAY_SIZE(s->cb))
    {
        s->cb[s->count].len = cb;
        s->cb[s->count].final = final;
        s->cb[s->count].first = cb ? pb[0] : 0xffff;
    }
    s->count++;
    s->all = s->all ? HeapReAlloc(GetProcessHeap(), 0, s->all, s->all_len + cb + 1) : HeapAlloc(GetProcessHeap(), 0, cb + 1);
    memcpy(s->all + s->all_len, pb, cb);
    s->all_len += cb;
    return TRUE;
}

/* a DER (or BER, "indefinite") header at p: returns its size, the content length, or -1 for indefinite */
static DWORD cms_tlv(const BYTE *p, DWORD avail, BYTE *tag, LONGLONG *len)
{
    DWORD i, n;

    if (avail < 2) return 0;
    *tag = p[0];
    if (p[1] == 0x80) { *len = -1; return 2; }
    if (p[1] < 0x80) { *len = p[1]; return 2; }
    n = p[1] & 0x7f;
    if (n > 4 || avail < 2 + n) return 0;
    *len = 0;
    for (i = 0; i < n; i++) *len = (*len << 8) | p[2 + i];
    return 2 + n;
}

static const BYTE cms_stream_plain[] =
    "0123456789abcdefghij0123456789abcdefghij0123456789abcdefghij0123456789abcdefghij0123456789abcdefghij";

static void cms_check_bytes(HCRYPTMSG msg, const BYTE *expected, DWORD expected_len, const char *name)
{
    DWORD len = 0;
    BYTE *content = cms_param(msg, CMSG_CONTENT_PARAM, 0, &len);

    ok(!!content, "%s: CMSG_CONTENT_PARAM failed: %08lx\n", name, GetLastError());
    if (!content) return;
    ok(len == expected_len && !memcmp(content, expected, len), "%s: wrong content, %lu bytes\n", name, len);
    HeapFree(GetProcessHeap(), 0, content);
}

/* Windows 10 22H2, measured: a streamed message sends its header (up to the opening of the encrypted content) with
 * the first update, final = FALSE. The encrypted content comes with the final update. Definite length (cbContent
 * set): the ciphertext in one piece, final = TRUE. Indefinite length (cbContent -1): the OCTET STRING header
 * (none if the content is empty), the ciphertext, two end-of-contents, three end-of-contents with final = TRUE. */
static void cms_stream_encode(const char *name, const char *alg, DWORD cb_content, const DWORD *chunks, DWORD n_chunks,
                              DWORD block /* the cipher's block size */, BOOL use_ncrypt)
{
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, cms_cert_a, sizeof(cms_cert_a));
    cms_enveloped_encode_info info;
    PCERT_INFO cert_info = cert->pCertInfo;
    struct cms_stream s = { 0 };
    CMSG_STREAM_INFO stream = { cb_content, cms_stream_output, &s };
    DWORD i, off = 0, total = 0, ct_len, hdr, expected_cbs, err, size;
    BOOL indefinite = cb_content == 0xffffffff, ret;
    HCRYPTMSG msg;
    LONGLONG len;
    BYTE tag;

    for (i = 0; i < n_chunks; i++) total += chunks[i];
    ct_len = block == 1 ? total : total ? (total / block + 1) * block : 0;
    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.ContentEncryptionAlgorithm.pszObjId = (char *)alg;
    info.cRecipients = 1;
    info.rgpRecipientCert = &cert_info;
    SetLastError(0xdeadbeef);
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, NULL, &stream);
    ok(!!msg, "%s: CryptMsgOpenToEncode failed: %08lx\n", name, GetLastError());
    if (!msg) goto done;
    ok(!s.count, "%s: %lu pieces before the first update\n", name, s.count);
    for (i = 0; i < n_chunks; i++)
    {
        BOOL final = i == n_chunks - 1;

        SetLastError(0xdeadbeef);
        ret = CryptMsgUpdate(msg, cms_stream_plain + off, chunks[i], final);
        ok(ret, "%s: CryptMsgUpdate failed: %08lx\n", name, GetLastError());
        if (!final) ok(s.count == 1 && !s.cb[0].final, "%s: update %lu: %lu pieces\n", name, i, s.count);
        off += chunks[i];
    }
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_BARE_CONTENT_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == E_INVALIDARG, "%s: expected E_INVALIDARG, got %08lx\n", name, GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgGetParam(msg, CMSG_CONTENT_PARAM, 0, NULL, &size);
    ok(!ret && GetLastError() == E_INVALIDARG, "%s: expected E_INVALIDARG, got %08lx\n", name, GetLastError());
    SetLastError(0xdeadbeef);
    ret = CryptMsgUpdate(msg, cms_stream_plain, 1, TRUE);
    ok(!ret && GetLastError() == CRYPT_E_MSG_ERROR, "%s: expected CRYPT_E_MSG_ERROR, got %08lx\n", name, GetLastError());
    CryptMsgClose(msg);

    /* the pieces */
    expected_cbs = indefinite ? (ct_len ? 5 : 3) : 2;
    ok(s.count == expected_cbs, "%s: expected %lu pieces, got %lu\n", name, expected_cbs, s.count);
    if (s.count != expected_cbs) goto done;
    for (i = 0; i < s.count; i++)
        ok(s.cb[i].final == (i == s.count - 1), "%s: piece %lu: final %d\n", name, i, s.cb[i].final);
    ok(s.cb[0].first == 0x30, "%s: the message does not start with a SEQUENCE\n", name);
    if (indefinite)
    {
        DWORD k = ct_len ? 3 : 1;

        ok(s.all[1] == 0x80, "%s: outer length is not indefinite\n", name);
        if (ct_len)
        {
            hdr = cms_tlv(s.all + s.cb[0].len, s.cb[1].len, &tag, &len);
            ok(hdr == s.cb[1].len && tag == 4 && len == ct_len, "%s: wrong OCTET STRING header\n", name);
            ok(s.cb[2].len == ct_len, "%s: ciphertext piece is %lu bytes, expected %lu\n", name, s.cb[2].len, ct_len);
        }
        ok(s.cb[k].len == 4 && s.cb[k + 1].len == 6, "%s: wrong end pieces %lu, %lu\n", name, s.cb[k].len, s.cb[k + 1].len);
        for (i = s.all_len - 10; i < s.all_len; i++)
            ok(!s.all[i], "%s: end-of-contents byte %lu is %02x\n", name, i, s.all[i]);
    }
    else
    {
        /* one definite SEQUENCE around everything, and the ciphertext piece */
        hdr = cms_tlv(s.all, s.all_len, &tag, &len);
        ok(hdr && len == s.all_len - hdr, "%s: outer length %I64d for %lu bytes\n", name, len, s.all_len - hdr);
        ok(s.cb[1].len == ct_len, "%s: ciphertext piece is %lu bytes, expected %lu\n", name, s.cb[1].len, ct_len);
    }

    /* the non-streamed reader takes it and decrypts the plaintext */
    msg = cms_open(s.all, s.all_len);
    ok(!!msg, "%s: CryptMsgUpdate of the streamed message failed: %08lx\n", name, GetLastError());
    if (msg)
    {
        if (!use_ncrypt && !cms_keys.have_capi) skip("%s: no CryptoAPI key\n", name);
        else if (use_ncrypt && !cms_keys.have_ncrypt) skip("%s: no NCrypt key\n", name);
        else
        {
            err = cms_decrypt(msg, 0, use_ncrypt);
            ok(!err, "%s: decrypt failed: %08lx\n", name, err);
            if (!err) cms_check_bytes(msg, cms_stream_plain, total, name);
        }
        CryptMsgClose(msg);
    }
done:
    HeapFree(GetProcessHeap(), 0, s.all);
    CertFreeCertificateContext(cert);
}

static void test_cms_stream_encode(void)
{
    static const DWORD three[] = { 30, 30, 40 }, one[] = { 100 }, none[] = { 0 }, odd[] = { 1, 7, 8, 16, 3 };
    static const char des3[] = "1.2.840.113549.3.7", aes256[] = "2.16.840.1.101.3.4.1.42", rc4[] = "1.2.840.113549.3.4";

    cms_stream_encode("3des definite", des3, 100, three, 3, 8, FALSE);
    cms_stream_encode("3des definite, one update", des3, 100, one, 1, 8, FALSE);
    cms_stream_encode("3des indefinite", des3, 0xffffffff, three, 3, 8, FALSE);
    cms_stream_encode("3des indefinite, odd chunks", des3, 0xffffffff, odd, 5, 8, FALSE);
    cms_stream_encode("aes256 definite", aes256, 100, three, 3, 16, TRUE);
    cms_stream_encode("aes256 indefinite", aes256, 0xffffffff, three, 3, 16, TRUE);
    cms_stream_encode("aes256 indefinite, empty", aes256, 0xffffffff, none, 1, 16, TRUE);
    cms_stream_encode("aes256 definite, empty", aes256, 0, none, 1, 16, TRUE);
    cms_stream_encode("rc4 indefinite", rc4, 0xffffffff, three, 3, 1, FALSE);
}

/* the callback of a streamed decode: nothing while the message is read, the plaintext when it is decrypted */
static void test_cms_stream_decode(void)
{
    static const struct { const char *name; const BYTE *data; DWORD len; int key; } tests[] =
    {
        { "3des", cms_msg_3des, sizeof(cms_msg_3des), 0 },
        { "aes256", cms_msg_aes256, sizeof(cms_msg_aes256), 1 },
        { "ber_indefinite", cms_msg_ber_indefinite, sizeof(cms_msg_ber_indefinite), 1 },
    };
    DWORD i, pos;

    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        struct cms_stream s = { 0 };
        CMSG_STREAM_INFO stream = { 0xffffffff, cms_stream_output, &s };
        HCRYPTMSG msg;
        DWORD err, count;
        BOOL ret;

        if ((tests[i].key && !cms_keys.have_ncrypt) || (!tests[i].key && !cms_keys.have_capi))
        {
            skip("%s: no key\n", tests[i].name);
            continue;
        }
        msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, 0, 0, NULL, &stream);
        ok(!!msg, "%s: CryptMsgOpenToDecode failed: %08lx\n", tests[i].name, GetLastError());
        if (!msg) continue;
        for (pos = 0; pos < tests[i].len; pos += 50)
        {
            DWORD n = min(50, tests[i].len - pos);

            SetLastError(0xdeadbeef);
            ret = CryptMsgUpdate(msg, tests[i].data + pos, n, pos + n == tests[i].len);
            ok(ret, "%s: CryptMsgUpdate failed: %08lx\n", tests[i].name, GetLastError());
        }
        ok(!s.count, "%s: %lu pieces before the decryption\n", tests[i].name, s.count);
        ok(cms_dword_param(msg, CMSG_TYPE_PARAM, 0) == CMSG_ENVELOPED, "%s: wrong type\n", tests[i].name);
        err = cms_decrypt(msg, 0, tests[i].key);
        ok(!err, "%s: decrypt failed: %08lx\n", tests[i].name, err);
        count = s.count;
        ok(count == 1, "%s: expected one piece after the decryption, got %lu\n", tests[i].name, count);
        if (count == 1)
        {
            ok(s.cb[0].final, "%s: the piece is not final\n", tests[i].name);
            ok(s.all_len == sizeof(cms_plain) - 1 && !memcmp(s.all, cms_plain, s.all_len), "%s: wrong plaintext, %lu bytes\n",
               tests[i].name, s.all_len);
        }
        CryptMsgClose(msg);
        HeapFree(GetProcessHeap(), 0, s.all);
    }
}

#ifdef __REACTOS__
/* Sizes that cannot be buffered or padded inside a DWORD are refused before the data is read: the pointer
 * in these calls is good for a few bytes only. Not run against Windows, whose answer to this was not measured
 * and might well be to read the memory. */
static void test_cms_size_guards(void)
{
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, cms_cert_a, sizeof(cms_cert_a));
    cms_enveloped_encode_info info;
    PCERT_INFO cert_info = cert->pCertInfo;
    struct cms_stream s = { 0 };
    CMSG_STREAM_INFO stream = { 0xffffffff, cms_stream_output, &s };
    HCRYPTMSG msg;
    BOOL ret;

    memset(&info, 0, sizeof(info));
    info.cbSize = sizeof(info);
    info.ContentEncryptionAlgorithm.pszObjId = (char *)"1.2.840.113549.3.7";
    info.cRecipients = 1;
    info.rgpRecipientCert = &cert_info;

    /* not streamed: the final update of too much data */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, NULL, NULL);
    ok(!!msg, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());
    if (msg)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgUpdate(msg, cms_stream_plain, 0xfffffff0, TRUE);
        ok(!ret && GetLastError() == ERROR_OUTOFMEMORY, "expected ERROR_OUTOFMEMORY, got %d, %08lx\n", ret, GetLastError());
        CryptMsgClose(msg);
    }

    /* streamed, indefinite: the sum of the updates would not fit */
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, NULL, &stream);
    ok(!!msg, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());
    if (msg)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgUpdate(msg, cms_stream_plain, 10, FALSE);
        ok(ret, "CryptMsgUpdate failed: %08lx\n", GetLastError());
        SetLastError(0xdeadbeef);
        ret = CryptMsgUpdate(msg, cms_stream_plain, 0xfffffff0, FALSE);
        ok(!ret && GetLastError() == ERROR_OUTOFMEMORY, "expected ERROR_OUTOFMEMORY, got %d, %08lx\n", ret, GetLastError());
        CryptMsgClose(msg);
    }

    /* streamed, definite: the declared size and its padding would not fit the lengths of the header */
    stream.cbContent = 0xfffffff0;
    s.count = 0;
    msg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CMSG_ENVELOPED, &info, NULL, &stream);
    ok(!!msg, "CryptMsgOpenToEncode failed: %08lx\n", GetLastError());
    if (msg)
    {
        SetLastError(0xdeadbeef);
        ret = CryptMsgUpdate(msg, cms_stream_plain, 10, FALSE);
        ok(!ret && GetLastError() == ERROR_OUTOFMEMORY, "expected ERROR_OUTOFMEMORY, got %d, %08lx\n", ret, GetLastError());
        ok(!s.count, "%lu pieces sent\n", s.count);
        CryptMsgClose(msg);
    }
    HeapFree(GetProcessHeap(), 0, s.all);
    CertFreeCertificateContext(cert);
}
#endif

static void test_enveloped_cms(void)
{
    cms_load_keys();
    if (!cms_keys.have_capi) skip("no CryptoAPI key\n");
    if (!cms_keys.have_ncrypt) skip("no NCrypt keys\n");
    test_cms_decode_messages();
    test_cms_get_params();
    test_cms_decrypt_errors();
    test_cms_two_recipients();
    test_cms_encode();
    test_cms_inner_type();
    test_cms_rc2_key();
    test_cms_capi_keys();
    test_cms_stream_encode();
    test_cms_stream_decode();
#ifdef __REACTOS__
    test_cms_size_guards();
#endif
    cms_free_keys();
    test_cms_rc2_params();
    test_cms_oid_info();
    test_cms_malformed();
}

START_TEST(msg)
{
    /* Basic parameter checking tests */
    test_msg_open_to_encode();
    test_msg_open_to_decode();
    test_msg_get_param();
    test_msg_close();
    test_msg_control();

    /* Message-type specific tests */
    test_data_msg();
    test_hash_msg();
    test_signed_msg();
    test_enveloped_msg();
    test_enveloped_cms();
    test_decode_msg();

    test_msg_get_and_verify_signer();
    test_verify_ecc_signature();
}
