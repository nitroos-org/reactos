/*
 * PROJECT:     ReactOS host tools
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Post-link fix-up of the PDB files that "ld --pdb" writes (NITRO_PDB_PUBLICS)
 *
 * The program reads a PDB (the MSF 7.00 container described in the public "The PDB File Format"
 * documentation of the LLVM project), changes two things and writes the container again:
 *
 *  1. Stream 0, the "old MSF directory", is made empty. GNU ld leaves 4 bytes in it. Microsoft's
 *     debugger libraries (dbghelp, msdia) refuse such a file ("file system or network error reading
 *     pdb"); every other producer of PDB files writes the stream empty.
 *
 *  2. Absolute paths of the build host are replaced. ld records the object files (module names in the
 *     DBI stream) and, in the "* Linker *" module, the working directory, the linker and the PDB itself
 *     (S_ENVBLOCK, S_OBJNAME) by their absolute, symbolic-link resolved paths. A path below a directory
 *     named with --map becomes the given prefix plus the rest of the path with backslashes; any other
 *     absolute path is reduced to its file name. The PDB is then free of the build host's directory
 *     names and the same for every build directory.
 *
 * Streams are copied as they are, except the DBI module records and the symbol records named above. The
 * layout of the output depends on the content only (nothing random, no time), so the same input gives
 * the same output.
 *
 *  3. With --signature SECONDS the time stamp that GNU ld writes into the PDB information stream (the
 *     link time, also when the linker was told to write no time into the image) is replaced, so that the
 *     file does not depend on when it was made. The GUID and age, by which a debugger matches a PDB to its
 *     image, are not touched.
 *
 * Usage: pdbfix [--map DIR=PREFIX]... [--forbid TEXT]... [--signature SECONDS] file.pdb
 *   The file is rewritten in place. After the rewrite no stream may contain the name of any --map
 *   directory (as given and with links resolved) or any --forbid text; if one does, the file is not
 *   changed and the exit code is 1: a leak must stop the build, not be published.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <limits.h>
#endif

#define MSF_MAGIC "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS\0\0\0"
#define MSF_MAGIC_SIZE 32
#define MAX_MAPS 8
#define MAX_PREFIX 64
#define MAX_FORBID 16

static const char *g_Prog = "pdbfix";
static const char *g_File;

typedef struct
{
    uint8_t *Data;
    uint32_t Size;
    int Present;     /* 0: the stream does not exist (size 0xFFFFFFFF in the directory) */
} STREAM;

typedef struct
{
    char *From;      /* directory, no trailing slash */
    size_t FromLen;
    char *To;        /* replacement prefix, no trailing backslash */
} MAPPING;

static MAPPING g_Maps[MAX_MAPS * 2];
static unsigned g_MapCount;
static char *g_Forbid[MAX_FORBID + MAX_MAPS * 2];
static unsigned g_ForbidCount;
static int g_SetSignature;
static uint32_t g_Signature;

static void fail(const char *fmt, ...)
{
    va_list args;

    fprintf(stderr, "%s ERROR: '%s': ", g_Prog, g_File);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    exit(1);
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static void wr16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        fail("out of memory (%lu bytes)", (unsigned long)n);
    return p;
}

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

static size_t my_strnlen(const char *s, size_t max)
{
    size_t n = 0;
    while (n < max && s[n])
        n++;
    return n;
}

/* ---- paths ---------------------------------------------------------------------------------------------------- */

static int is_abs_path(const char *s)
{
    if (s[0] == '/')
        return 1;
    if (((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && (s[2] == '\\' || s[2] == '/'))
        return 1;
    return 0;
}

static const char *base_name(const char *s)
{
    const char *b = s, *p;
    for (p = s; *p; p++)
        if (*p == '/' || *p == '\\')
            b = p + 1;
    return b;
}

static void add_map_entry(const char *dir, const char *to)
{
    size_t n = strlen(dir);
    MAPPING *m;

    while (n > 1 && (dir[n - 1] == '/' || dir[n - 1] == '\\'))
        n--;
    if (n == 0 || g_MapCount >= sizeof(g_Maps) / sizeof(g_Maps[0]))
        return;
    m = &g_Maps[g_MapCount++];
    m->From = xmalloc(n + 1);
    memcpy(m->From, dir, n);
    m->From[n] = '\0';
    m->FromLen = n;
    m->To = xstrdup(to);
    g_Forbid[g_ForbidCount++] = xstrdup(m->From);
}

static void add_map(const char *spec)
{
    const char *eq = strchr(spec, '=');
    char *dir, *to;
    size_t n;

    if (!eq || eq == spec || !eq[1])
        fail("--map needs DIR=PREFIX, got '%s'", spec);
    dir = xmalloc((size_t)(eq - spec) + 1);
    memcpy(dir, spec, (size_t)(eq - spec));
    dir[eq - spec] = '\0';
    to = xstrdup(eq + 1);
    n = strlen(to);
    if (n > MAX_PREFIX)
        fail("--map prefix longer than %d characters", MAX_PREFIX);
    while (n > 1 && to[n - 1] == '\\')
        to[--n] = '\0';

    add_map_entry(dir, to);
#ifndef _WIN32
    {
        /* ld records the path with symbolic links resolved */
        char resolved[PATH_MAX];
        if (realpath(dir, resolved) && strcmp(resolved, dir) != 0)
            add_map_entry(resolved, to);
    }
#endif
    free(dir);
    free(to);
}

/* Longest matching directory wins. A match is the directory itself or the directory followed by a separator. */
static const MAPPING *find_map(const char *path)
{
    const MAPPING *best = NULL;
    unsigned i;

    for (i = 0; i < g_MapCount; i++)
    {
        const MAPPING *m = &g_Maps[i];
        if (strncmp(path, m->From, m->FromLen) == 0 &&
            (path[m->FromLen] == '\0' || path[m->FromLen] == '/' || path[m->FromLen] == '\\') &&
            (!best || m->FromLen > best->FromLen))
            best = m;
    }
    return best;
}

/* Returns a newly allocated normalised copy of a path found in the PDB; text that is not an absolute path is copied. */
static char *map_path(const char *path)
{
    const MAPPING *m;
    char *out, *q;
    const char *rest;

    if (!is_abs_path(path))
        return xstrdup(path);

    m = find_map(path);
    if (!m)
    {
        unsigned i;

        /* a path that was normalised before (running the tool twice changes nothing) */
        for (i = 0; i < g_MapCount; i++)
        {
            size_t n = strlen(g_Maps[i].To);
            if (strncmp(path, g_Maps[i].To, n) == 0 && (path[n] == '\0' || path[n] == '\\'))
                return xstrdup(path);
        }
        return xstrdup(base_name(path));
    }

    rest = path + m->FromLen;
    out = xmalloc(strlen(m->To) + strlen(rest) + 1);
    strcpy(out, m->To);
    q = out + strlen(out);
    for (; *rest; rest++, q++)
        *q = (*rest == '/') ? '\\' : *rest;
    *q = '\0';
    return out;
}

/* ---- MSF container -------------------------------------------------------------------------------------------- */

static uint8_t *read_file(const char *name, size_t *size)
{
    FILE *f = fopen(name, "rb");
    long n;
    uint8_t *buf;

    if (!f)
        fail("cannot open: %s", strerror(errno));
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0)
        fail("cannot determine the size");
    buf = xmalloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n)
        fail("read error");
    fclose(f);
    *size = (size_t)n;
    return buf;
}

static STREAM *parse_msf(const uint8_t *d, size_t size, uint32_t *block_size, uint32_t *num_streams)
{
    uint32_t B, nblocks, ndir, bma, nmapblk, ndirblk, i, s, off;
    uint8_t *dir;
    STREAM *st;

    if (size < 0x38 || memcmp(d, MSF_MAGIC, MSF_MAGIC_SIZE) != 0)
        fail("not an MSF 7.00 file");
    B = rd32(d + 0x20);
    nblocks = rd32(d + 0x28);
    ndir = rd32(d + 0x2c);
    bma = rd32(d + 0x34);
    if (B != 512 && B != 1024 && B != 2048 && B != 4096)
        fail("unsupported block size %lu", (unsigned long)B);
    if ((uint64_t)nblocks * B != size)
        fail("file size %lu is not %lu blocks of %lu", (unsigned long)size, (unsigned long)nblocks, (unsigned long)B);
    ndirblk = (ndir + B - 1) / B;
    nmapblk = (ndirblk * 4 + B - 1) / B;
    if (bma >= nblocks || nblocks - bma < nmapblk)
        fail("block map address out of range");

    dir = xmalloc((size_t)ndirblk * B);
    for (i = 0; i < ndirblk; i++)
    {
        uint32_t blk = rd32(d + (size_t)bma * B + (size_t)i * 4);
        if (blk >= nblocks)
            fail("directory block %lu out of range", (unsigned long)blk);
        memcpy(dir + (size_t)i * B, d + (size_t)blk * B, B);
    }
    if (ndir < 4)
        fail("directory too small");
    *num_streams = rd32(dir);
    if ((uint64_t)*num_streams * 4 + 4 > ndir)
        fail("directory too small for %lu streams", (unsigned long)*num_streams);
    st = xmalloc(sizeof(STREAM) * (*num_streams ? *num_streams : 1));
    off = 4 + 4 * *num_streams;
    for (s = 0; s < *num_streams; s++)
    {
        uint32_t sz = rd32(dir + 4 + 4 * s), nb, j;

        st[s].Present = (sz != 0xFFFFFFFFu);
        if (!st[s].Present)
            sz = 0;
        st[s].Size = sz;
        nb = (sz + B - 1) / B;
        if ((uint64_t)off + (uint64_t)nb * 4 > ndir)
            fail("directory ends inside stream %lu", (unsigned long)s);
        st[s].Data = xmalloc((size_t)nb * B + 1);
        for (j = 0; j < nb; j++)
        {
            uint32_t blk = rd32(dir + off + 4 * j);
            if (blk >= nblocks)
                fail("stream %lu: block %lu out of range", (unsigned long)s, (unsigned long)blk);
            memcpy(st[s].Data + (size_t)j * B, d + (size_t)blk * B, B);
        }
        off += nb * 4;
    }
    free(dir);
    *block_size = B;
    return st;
}

typedef struct
{
    uint8_t *Buf;
    uint8_t *Used;       /* one flag per block: handed out (or reserved) */
    uint32_t Blocks;     /* blocks in use so far */
    uint32_t Cap;
    uint32_t B;
} OUTFILE;

/* The free block map lives in blocks 1 and 2 and again in every B-th block after them. */
static int is_fpm_block(uint32_t id, uint32_t B)
{
    uint32_t r = id % B;
    return r == 1 || r == 2;
}

static void out_ensure(OUTFILE *o, uint32_t blocks)
{
    if (blocks > o->Cap)
    {
        uint32_t cap = o->Cap ? o->Cap : 64;
        while (cap < blocks)
            cap *= 2;
        o->Buf = realloc(o->Buf, (size_t)cap * o->B);
        o->Used = realloc(o->Used, cap);
        if (!o->Buf || !o->Used)
            fail("out of memory");
        memset(o->Buf + (size_t)o->Cap * o->B, 0, (size_t)(cap - o->Cap) * o->B);
        memset(o->Used + o->Cap, 0, cap - o->Cap);
        o->Cap = cap;
    }
}

/* Next block above all that were handed out and not reserved for the free block map */
static uint32_t out_alloc(OUTFILE *o)
{
    uint32_t id = o->Blocks;
    while (is_fpm_block(id, o->B))
        id++;
    out_ensure(o, id + 1);
    o->Used[id] = 1;
    o->Blocks = id + 1;
    return id;
}

/* Copies `data` into new blocks (the reserved blocks are skipped, so they need not be adjacent) */
static uint32_t *out_put(OUTFILE *o, const uint8_t *data, uint32_t size, uint32_t *count)
{
    uint32_t n = (size + o->B - 1) / o->B, i;
    uint32_t *ids = xmalloc((size_t)(n ? n : 1) * 4);

    for (i = 0; i < n; i++)
    {
        uint32_t blk = out_alloc(o);
        uint32_t len = size - i * o->B;
        if (len > o->B)
            len = o->B;
        memcpy(o->Buf + (size_t)blk * o->B, data + (size_t)i * o->B, len);
        ids[i] = blk;
    }
    *count = n;
    return ids;
}

static void write_msf(const char *name, const STREAM *st, uint32_t ns, uint32_t B, const uint8_t *super)
{
    OUTFILE o;
    uint32_t **sblocks, *sbn, s, i, k, ndirbytes, dirblocks_n, mapblocks_n, nblocks, nint, start;
    uint32_t *dirids;
    uint8_t *dir, *p, *fpm;
    FILE *f;
    char *tmp;

    memset(&o, 0, sizeof(o));
    o.B = B;
    out_ensure(&o, 3);
    o.Blocks = 3;
    o.Used[0] = o.Used[1] = o.Used[2] = 1;

    /* the streams, in order */
    sblocks = xmalloc(sizeof(*sblocks) * (ns ? ns : 1));
    sbn = xmalloc(sizeof(*sbn) * (ns ? ns : 1));
    for (s = 0; s < ns; s++)
        sblocks[s] = out_put(&o, st[s].Data, st[s].Size, &sbn[s]);

    /* the directory: number of streams, their sizes, the block list of every stream */
    ndirbytes = 4 + 4 * ns;
    for (s = 0; s < ns; s++)
        ndirbytes += 4 * sbn[s];
    dir = xmalloc(ndirbytes);
    wr32(dir, ns);
    for (s = 0; s < ns; s++)
        wr32(dir + 4 + 4 * s, st[s].Present ? st[s].Size : 0xFFFFFFFFu);
    p = dir + 4 + 4 * ns;
    for (s = 0; s < ns; s++)
        for (i = 0; i < sbn[s]; i++, p += 4)
            wr32(p, sblocks[s][i]);
    dirids = out_put(&o, dir, ndirbytes, &dirblocks_n);

    /* the block map (the directory's block list) must lie in consecutive blocks */
    mapblocks_n = (dirblocks_n * 4 + B - 1) / B;
    start = o.Blocks;
    for (;;)
    {
        int clash = 0;
        for (k = 0; k < mapblocks_n; k++)
            if (is_fpm_block(start + k, B))
                clash = 1;
        if (!clash)
            break;
        start++;
    }
    out_ensure(&o, start + mapblocks_n);
    for (k = 0; k < mapblocks_n; k++)
        o.Used[start + k] = 1;
    o.Blocks = start + mapblocks_n;
    for (i = 0; i < dirblocks_n; i++)
        wr32(o.Buf + (size_t)start * B + 4 * i, dirids[i]);

    /* every interval of B blocks ends with its two free block map blocks inside the file */
    nblocks = o.Blocks;
    if (((nblocks - 1) / B) * B + 3 > nblocks)
        nblocks = ((nblocks - 1) / B) * B + 3;
    out_ensure(&o, nblocks);
    nint = (nblocks + B - 1) / B;

    /* the map: bit set = block free; bytes [k*B, (k+1)*B) of it are stored in blocks k*B+1 and k*B+2 */
    fpm = xmalloc((size_t)nint * B);
    memset(fpm, 0xff, (size_t)nint * B);
    for (i = 0; i < nblocks; i++)
        if (o.Used[i] || is_fpm_block(i, B))
            fpm[i / 8] &= (uint8_t)~(1u << (i % 8));
    for (k = 0; k < nint; k++)
    {
        memcpy(o.Buf + (size_t)(k * B + 1) * B, fpm + (size_t)k * B, B);
        memcpy(o.Buf + (size_t)(k * B + 2) * B, fpm + (size_t)k * B, B);
    }

    /* the super block: the 32 bytes of magic, block size, free map block (1), size in blocks, directory size, 0, block map */
    memcpy(o.Buf, super, MSF_MAGIC_SIZE);
    wr32(o.Buf + 0x20, B);
    wr32(o.Buf + 0x24, 1);
    wr32(o.Buf + 0x28, nblocks);
    wr32(o.Buf + 0x2c, ndirbytes);
    wr32(o.Buf + 0x30, 0);
    wr32(o.Buf + 0x34, start);

    tmp = xmalloc(strlen(name) + 8);
    strcpy(tmp, name);
    strcat(tmp, ".tmp");
    f = fopen(tmp, "wb");
    if (!f)
        fail("cannot write '%s': %s", tmp, strerror(errno));
    if (fwrite(o.Buf, B, nblocks, f) != nblocks || fclose(f) != 0)
    {
        remove(tmp);
        fail("write error");
    }
#ifdef _WIN32
    remove(name);
#endif
    if (rename(tmp, name) != 0)
    {
        remove(tmp);
        fail("cannot replace the file: %s", strerror(errno));
    }
    free(tmp);
}

/* ---- DBI stream and module symbol streams ----------------------------------------------------------------------- */

#define DBI_HEADER_SIZE 64
#define MODI_FIXED 64

#define S_COMPILE      0x0001
#define S_COMPILE2     0x1116
#define S_OBJNAME      0x1101
#define S_COMPILE3     0x113c
#define S_ENVBLOCK     0x113d
#define S_BUILDINFO    0x114c

/* Rewrites the S_OBJNAME and S_ENVBLOCK records of a module symbol stream. Returns 1 when the stream changed. */
static int rewrite_module_symbols(STREAM *ms, uint32_t *symbytes)
{
    uint32_t sb = *symbytes, o, newsize = 4;
    uint8_t *out, *p;
    int changed = 0, resized = 0, other = 0;

    if (sb <= 4 || sb > ms->Size)
        return 0;
    if (rd32(ms->Data) != 4)
        return 0;                     /* CV_SIGNATURE_C13 */

    out = xmalloc((size_t)sb * 8 + 4096);
    memcpy(out, ms->Data, 4);
    p = out + 4;
    for (o = 4; o + 4 <= sb;)
    {
        uint32_t len = rd16(ms->Data + o), kind = rd16(ms->Data + o + 2), total = len + 2;
        const uint8_t *body = ms->Data + o + 4;
        uint32_t blen;

        if (len < 2 || o + total > sb)
            fail("damaged symbol record at offset %lu", (unsigned long)o);
        blen = len - 2;

        if (kind == S_OBJNAME && blen >= 5)
        {
            const char *name = (const char *)body + 4;
            size_t nl = my_strnlen(name, blen - 4);
            char *src, *dst;
            size_t dl, padded;

            if (nl == blen - 4)
                fail("unterminated object name in a symbol record");
            src = xmalloc(nl + 1);
            memcpy(src, name, nl);
            src[nl] = '\0';
            dst = map_path(src);
            dl = strlen(dst);
            padded = (2 + 2 + 4 + dl + 1 + 3) & ~(size_t)3;
            wr16(p, (uint32_t)(padded - 2));
            wr16(p + 2, S_OBJNAME);
            memcpy(p + 4, body, 4);
            memcpy(p + 8, dst, dl + 1);
            memset(p + 8 + dl + 1, 0, padded - (8 + dl + 1));
            if (padded != total || strcmp(src, dst) != 0)
                changed = 1;
            if (padded != total)
                resized = 1;
            p += padded;
            newsize += (uint32_t)padded;
            free(src);
            free(dst);
        }
        else if (kind == S_ENVBLOCK && blen >= 1)
        {
            /* flags byte, then (key, value) pairs of NUL-terminated strings, then an empty key */
            uint8_t *tmp = xmalloc((size_t)blen * 16 + 4096);
            size_t tl = 1, pos = 1;
            size_t padded;
            int differs = 0;

            tmp[0] = body[0];
            while (pos < blen && body[pos] != 0)
            {
                const char *key = (const char *)body + pos;
                size_t kl = my_strnlen(key, blen - pos);
                const char *val;
                size_t vl;
                char *dst;

                if (pos + kl + 1 >= blen)
                    fail("damaged environment block");
                val = key + kl + 1;
                vl = my_strnlen(val, blen - (pos + kl + 1));
                if (pos + kl + 1 + vl >= blen)
                    fail("damaged environment block");
                dst = xmalloc(vl + 1);
                memcpy(dst, val, vl);
                dst[vl] = '\0';
                {
                    char *mapped = map_path(dst);
                    if (strcmp(mapped, dst) != 0)
                        differs = 1;
                    memcpy(tmp + tl, key, kl + 1);
                    tl += kl + 1;
                    memcpy(tmp + tl, mapped, strlen(mapped) + 1);
                    tl += strlen(mapped) + 1;
                    free(mapped);
                }
                free(dst);
                pos += kl + 1 + vl + 1;
            }
            tmp[tl++] = 0;                /* the empty key that ends the block */
            padded = (2 + 2 + tl + 3) & ~(size_t)3;
            wr16(p, (uint32_t)(padded - 2));
            wr16(p + 2, S_ENVBLOCK);
            memcpy(p + 4, tmp, tl);
            memset(p + 4 + tl, 0, padded - 4 - tl);
            if (padded != total || differs)
                changed = 1;
            if (padded != total)
                resized = 1;
            p += padded;
            newsize += (uint32_t)padded;
            free(tmp);
        }
        else
        {
            if (kind != S_COMPILE && kind != S_COMPILE2 && kind != S_COMPILE3 && kind != S_BUILDINFO)
                other = 1;
            memcpy(p, ms->Data + o, total);
            p += total;
            newsize += total;
        }
        o += total;
    }
    if (o != sb)
        fail("symbol records do not end at the symbol byte count");

    if (!changed)
    {
        free(out);
        return 0;
    }
    if (resized && other)
        fail("a module stream has records that hold offsets and a path that changes size: not handled");

    /* new stream: records + whatever follows the symbols (global references, C13 data ...) */
    {
        uint32_t tail = ms->Size - sb;
        uint8_t *ns = xmalloc((size_t)newsize + tail + 1);
        memcpy(ns, out, newsize);
        memcpy(ns + newsize, ms->Data + sb, tail);
        free(ms->Data);
        ms->Data = ns;
        ms->Size = newsize + tail;
        *symbytes = newsize;
    }
    free(out);
    return 1;
}

static void rewrite_dbi(STREAM *st, uint32_t ns)
{
    STREAM *dbi;
    uint32_t modsz, o, end, newmodsz = 0, restsz;
    uint8_t *mods, *q, *nd;

    if (ns <= 3 || !st[3].Present || st[3].Size < DBI_HEADER_SIZE)
        return;
    dbi = &st[3];
    if (rd32(dbi->Data) != 0xFFFFFFFFu)
        fail("unknown DBI stream version");
    modsz = rd32(dbi->Data + 24);
    if ((uint64_t)DBI_HEADER_SIZE + modsz > dbi->Size)
        fail("DBI module information is larger than the stream");

    mods = xmalloc((size_t)modsz * 4 + 4096 + 1);
    q = mods;
    o = DBI_HEADER_SIZE;
    end = DBI_HEADER_SIZE + modsz;
    while (o < end)
    {
        const char *name, *obj;
        size_t nl, ol;
        char *mname, *mobj;
        uint32_t reclen, newlen, stream;
        uint32_t symbytes;
        uint8_t *rec;

        if (end - o < MODI_FIXED + 2)
            fail("damaged module record");
        name = (const char *)dbi->Data + o + MODI_FIXED;
        nl = my_strnlen(name, end - o - MODI_FIXED);
        if (o + MODI_FIXED + nl + 1 >= end)
            fail("damaged module name");
        obj = name + nl + 1;
        ol = my_strnlen(obj, end - (o + MODI_FIXED + nl + 1));
        if (o + MODI_FIXED + nl + 1 + ol + 1 > end)
            fail("damaged object name");
        reclen = (uint32_t)((MODI_FIXED + nl + 1 + ol + 1 + 3) & ~(size_t)3);

        mname = map_path(name);
        mobj = map_path(obj);
        newlen = (uint32_t)((MODI_FIXED + strlen(mname) + 1 + strlen(mobj) + 1 + 3) & ~(size_t)3);

        rec = q;
        memcpy(rec, dbi->Data + o, MODI_FIXED);
        memcpy(rec + MODI_FIXED, mname, strlen(mname) + 1);
        memcpy(rec + MODI_FIXED + strlen(mname) + 1, mobj, strlen(mobj) + 1);
        memset(rec + MODI_FIXED + strlen(mname) + 1 + strlen(mobj) + 1, 0, newlen - (MODI_FIXED + strlen(mname) + 1 + strlen(mobj) + 1));

        /* the module's own symbol stream (the linker's carries the environment) */
        stream = rd16(dbi->Data + o + 34);
        symbytes = rd32(dbi->Data + o + 36);
        if (stream != 0xFFFF && stream < ns && st[stream].Present)
        {
            if (rewrite_module_symbols(&st[stream], &symbytes))
                wr32(rec + 36, symbytes);
        }

        q += newlen;
        newmodsz += newlen;
        o += reclen;
        free(mname);
        free(mobj);
    }
    if (o != end)
        fail("module records do not end at the module information size");

    restsz = dbi->Size - end;
    nd = xmalloc((size_t)DBI_HEADER_SIZE + newmodsz + restsz + 1);
    memcpy(nd, dbi->Data, DBI_HEADER_SIZE);
    wr32(nd + 24, newmodsz);
    memcpy(nd + DBI_HEADER_SIZE, mods, newmodsz);
    memcpy(nd + DBI_HEADER_SIZE + newmodsz, dbi->Data + end, restsz);
    free(dbi->Data);
    free(mods);
    dbi->Data = nd;
    dbi->Size = DBI_HEADER_SIZE + newmodsz + restsz;
}

/* ---- check ------------------------------------------------------------------------------------------------------- */

static const uint8_t *find_bytes(const uint8_t *h, size_t hl, const char *n, size_t nl)
{
    size_t i;
    if (nl == 0 || hl < nl)
        return NULL;
    for (i = 0; i + nl <= hl; i++)
        if (h[i] == (uint8_t)n[0] && memcmp(h + i, n, nl) == 0)
            return h + i;
    return NULL;
}

int main(int argc, char **argv)
{
    int i;
    size_t size;
    uint8_t *file;
    uint32_t B, ns, s;
    STREAM *st;
    unsigned f;

    g_Prog = argv[0];
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--map") == 0 && i + 1 < argc)
            add_map(argv[++i]);
        else if (strcmp(argv[i], "--signature") == 0 && i + 1 < argc)
        {
            char *end;
            unsigned long v = strtoul(argv[++i], &end, 10);
            if (end == argv[i] || *end != '\0' || v > 0xFFFFFFFFUL)
                fail("--signature needs a number of seconds");
            g_Signature = (uint32_t)v;
            g_SetSignature = 1;
        }
        else if (strcmp(argv[i], "--forbid") == 0 && i + 1 < argc)
        {
            if (g_ForbidCount < sizeof(g_Forbid) / sizeof(g_Forbid[0]))
                g_Forbid[g_ForbidCount++] = xstrdup(argv[++i]);
            else
                fail("too many --forbid");
        }
        else if (argv[i][0] == '-' && argv[i][1] == '-')
        {
            fprintf(stderr, "Usage: %s [--map DIR=PREFIX]... [--forbid TEXT]... [--signature SECONDS] file.pdb\n", argv[0]);
            return 1;
        }
        else
            break;
    }
    if (i != argc - 1)
    {
        fprintf(stderr, "Usage: %s [--map DIR=PREFIX]... [--forbid TEXT]... [--signature SECONDS] file.pdb\n", argv[0]);
        return 1;
    }
    g_File = argv[i];

    file = read_file(g_File, &size);
    st = parse_msf(file, size, &B, &ns);

    /* 1. the old MSF directory stream is empty */
    if (ns > 0)
    {
        st[0].Size = 0;
        st[0].Present = 1;
    }

    /* the PDB information stream: version, signature (a time), age, GUID */
    if (g_SetSignature && ns > 1 && st[1].Present && st[1].Size >= 28)
        wr32(st[1].Data + 4, g_Signature);

    /* 2. host paths */
    rewrite_dbi(st, ns);

    /* nothing of the host may remain */
    for (s = 0; s < ns; s++)
        for (f = 0; f < g_ForbidCount; f++)
            if (find_bytes(st[s].Data, st[s].Size, g_Forbid[f], strlen(g_Forbid[f])))
                fail("stream %lu still contains '%s'", (unsigned long)s, g_Forbid[f]);

    write_msf(g_File, st, ns, B, file);
    return 0;
}
