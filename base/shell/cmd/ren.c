/*
 *  REN.C - rename internal command.
 *
 *
 *  History:
 *
 *
 *    27-Jul-1998 (John P Price <linux-guru@gcfl.net>)
 *        added config.h include
 *
 *    18-Dec-1998 (Eric Kohl)
 *        Added support for quoted long file names with spaces.
 *
 *    20-Jan-1999 (Eric Kohl)
 *        Unicode and redirection safe!
 *
 *    17-Oct-2001 (Eric Kohl)
 *        Implemented basic rename code.
 *
 *    30-Apr-2005 (Magnus Olsen <magnus@greatlord.com>)
 *        Remove all hardcoded strings in En.rc
 *
 *    25-Nov-2008 (Victor Martinez <vicmarcal@hotmail.com>)
 *        Patch dedicated to Myrjala because her comprehension and love :D
 *        Fixing following Bugs:
 *             -Wrong behavior with wildcards when Source and Destiny are Paths(FIXED).
 *             -Wrong general behavior (MSDN:"Rename cant move files between subdirectories")(FIXED)
 *             -Wrong behavior when renaming without path in destiny:(i.e) "ren C:\text\as.txt list.txt" it moves as.txt and then rename it(FIXED)
 *              (MSDN: If there is a Path in Source and no Path in Destiny, then Destiny Path is Source Path,because never Ren has to be used to move.)
 *             -Implemented checkings if SourcePath and DestinyPath are differents.
 *
 */

#include "precomp.h"

#ifdef INCLUDE_CMD_RENAME

enum
{
    REN_ATTRIBUTES = 0x001,   /* /A : not implemented */
    REN_ERROR      = 0x002,   /* /E */
    REN_NOTHING    = 0x004,   /* /N */
    REN_PROMPT     = 0x008,   /* /P : not implemented */
    REN_QUIET      = 0x010,   /* /Q */
    REN_SUBDIR     = 0x020,   /* /S */
    REN_TOTAL      = 0x040,   /* /T */
};


/*
 * Expands the destination mask against a source file name the way cmd.exe on Windows does and stores the
 * result in pszOut. Returns FALSE when it does not fit.
 *
 *   '?'  copies the next source character, or nothing at a '.' or at the end of the source name;
 *   '*'  copies the source up to the last occurrence of the mask character that follows it (the whole rest
 *        of the name when there is none), so "*.bak" keeps "a.b" of "a.b.txt";
 *   '.'  is copied and the source position moves behind the next '.' of the source;
 *   any other character is copied and consumes one source character, but never a '.'.
 */
static BOOL
RenExpandMask(
    IN PCWSTR pszSrc,
    IN PCWSTR pszMask,
    OUT PWSTR pszOut,
    IN SIZE_T cchOut)
{
    SIZE_T cch = 0;
    PCWSTR p = pszSrc, q = pszMask, pEnd;

#define REN_PUT(c) \
    do { if (cch + 1 >= cchOut) return FALSE; pszOut[cch++] = (c); } while (0)

    while (*q)
    {
        if (*q == L'*')
        {
            q++;
            pEnd = p + wcslen(p);
            if (*q && *q != L'*' && *q != L'?')
            {
                PCWSTR pFound = NULL, s;

                for (s = p; *s; s++)
                {
                    if (towupper(*s) == towupper(*q))
                        pFound = s;
                }
                if (pFound)
                    pEnd = pFound;
            }
            while (p < pEnd)
                REN_PUT(*p++);
        }
        else if (*q == L'?')
        {
            q++;
            if (*p && *p != L'.')
                REN_PUT(*p++);
        }
        else if (*q == L'.')
        {
            q++;
            REN_PUT(L'.');
            p = wcschr(p, L'.');
            p = p ? p + 1 : pszSrc + wcslen(pszSrc);
        }
        else
        {
            REN_PUT(*q++);
            if (*p && *p != L'.')
                p++;
        }
    }
    pszOut[cch] = 0;
#undef REN_PUT
    return TRUE;
}

/* "The syntax of the command is incorrect." */
static INT
RenSyntaxError(DWORD dwFlags)
{
    if (!(dwFlags & REN_ERROR))
        ConErrResPuts(STRING_SYNTAX_COMMAND_INCORRECT);
    nErrorLevel = 1;
    return 1;
}

/*
 *  file rename internal command.
 */
INT cmd_rename (LPTSTR param)
{
    LPTSTR *arg = NULL;
    INT args = 0;
    INT nEvalArgs = 0; /* number of evaluated arguments */
    DWORD dwFlags = 0;
    DWORD dwFiles = 0; /* number of renamed files */
    INT i;

    LPTSTR srcPattern = NULL; /* Source Argument*/
    LPTSTR dstPattern = NULL; /* Destination Argument: a bare name or mask */
    TCHAR srcSpec[MAX_PATH];  /* Source Argument without a trailing backslash */
    TCHAR srcDir[MAX_PATH];   /* Directory part of the source, with its trailing backslash, or empty */
    LPTSTR srcFILE;           /* File name part of the source (may have wildcards) */
    TCHAR srcFinal[MAX_PATH];
    TCHAR dstLast[MAX_PATH];  /* The new name, with the mask applied */
    TCHAR dstFinal[MAX_PATH]; /* The new name behind the directory of the source */
    SIZE_T cchSpec;

    BOOL bDstWildcard = FALSE;

    HANDLE hFile;
    WIN32_FIND_DATA f;
    /*If the PARAM=/? then show the help*/
    if (!_tcsncmp(param, _T("/?"), 2))
    {
        ConOutResPaging(TRUE,STRING_REN_HELP1);
        return 0;
    }

    nErrorLevel = 0;

    /* Split the argument list.Args will be saved in arg vector*/
    arg = split(param, &args, FALSE, FALSE);

    if (args < 2)
    {
        RenSyntaxError(dwFlags);
        freep(arg);
        return 1;
    }

    /* Read options */
    for (i = 0; i < args; i++)
    {
        /* Lets check if we have a special option chosen and set the flag(s)*/
        if (*arg[i] == _T('/'))
        {
            if (_tcslen(arg[i]) >= 2)
            {
                switch (_totupper(arg[i][1]))
                {
                    case _T('E'):
                    dwFlags |= REN_ERROR;
                    break;

                    case _T('N'):
                    dwFlags |= REN_NOTHING;
                    break;

                    case _T('P'):
                    dwFlags |= REN_PROMPT;
                    break;

                    case _T('Q'):
                    dwFlags |= REN_QUIET;
                    break;

                    case _T('S'):
                    dwFlags |= REN_SUBDIR;
                    break;

                    case _T('T'):
                    dwFlags |= REN_TOTAL;
                    break;
                }
            }
            nEvalArgs++;//Save the number of the options.
        }
    }

    /* keep quiet within batch files */
    if (bc != NULL)
        dwFlags |= REN_QUIET;

    /* there are only options on the command line --> error!!! */
    if (args < nEvalArgs + 2)
    {
        RenSyntaxError(dwFlags);
        freep(arg);
        return 1;
    }

    /* The last two arguments that are not options are the source and the destination */
    for (i = 0; i < args; i++)
    {
        if (*arg[i] == _T('/'))//We have find an Option.Jump it.
            continue;
        srcPattern = dstPattern;
        dstPattern = arg[i];
    }

    /* As on Windows the destination is only a new name, never a path: the file stays in its directory */
    if (_tcspbrk(dstPattern, _T("\\:")))
    {
        RenSyntaxError(dwFlags);
        freep(arg);
        return 1;
    }

    /* "ren dir\ new" renames the directory */
    cchSpec = _tcslen(srcPattern);
    if (cchSpec >= ARRAYSIZE(srcSpec))
    {
        if (!(dwFlags & REN_ERROR))
            ErrorMessage(ERROR_FILENAME_EXCED_RANGE, NULL);
        nErrorLevel = 1;
        freep(arg);
        return 1;
    }
    StringCchCopy(srcSpec, ARRAYSIZE(srcSpec), srcPattern);
    while (cchSpec > 1 && srcSpec[cchSpec - 1] == _T('\\') && srcSpec[cchSpec - 2] != _T(':'))
        srcSpec[--cchSpec] = 0;

    /* Split the source in its directory part ("C:\dir\", "dir\", "C:" or nothing) and its file name (mask) */
    srcFILE = _tcsrchr(srcSpec, _T('\\'));
    if (srcFILE)
        srcFILE++;
    else if (srcSpec[0] && srcSpec[1] == _T(':'))
        srcFILE = srcSpec + 2;
    else
        srcFILE = srcSpec;
    /* the directory part is always NUL-terminated */
    StringCchCopyN(srcDir, ARRAYSIZE(srcDir), srcSpec, srcFILE - srcSpec);

    /* Checking Wildcards. */
    if (_tcspbrk(dstPattern, _T("*?")))
        bDstWildcard = TRUE;

    TRACE("\n\nSourcePattern: %s SourcePath: %s SourceFile: %s", debugstr_aw(srcPattern),debugstr_aw(srcDir),debugstr_aw(srcFILE));
    TRACE("\n\nDestinationPattern: %s\n", debugstr_aw(dstPattern));

    hFile = FindFirstFile(srcSpec, &f);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (!(dwFlags & REN_ERROR))
            ErrorMessage(GetLastError(), NULL);
        nErrorLevel = 1;
        freep(arg);
        return 1;
    }
    do
    {
        /* ignore "." and ".." */
        if (!_tcscmp (f.cFileName, _T(".")) || !_tcscmp (f.cFileName, _T("..")))
            continue;

        /* do not rename hidden or system files */
        if (f.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
            continue;

        /* do not rename directories when the destination pattern contains
         * wildcards, unless option /S is used */
        if ((f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            bDstWildcard && !(dwFlags & REN_SUBDIR))
        {
            continue;
        }

        TRACE("Found source name: %s\n", debugstr_aw(f.cFileName));
        /* Apply the mask (dstPattern, which can have wildcards) to the found name to get the new name */
        if (!RenExpandMask(f.cFileName, dstPattern, dstLast, ARRAYSIZE(dstLast)) ||
            FAILED(StringCchPrintf(srcFinal, ARRAYSIZE(srcFinal), _T("%s%s"), srcDir, f.cFileName)) ||
            FAILED(StringCchPrintf(dstFinal, ARRAYSIZE(dstFinal), _T("%s%s"), srcDir, dstLast)))
        {
            if (!(dwFlags & REN_ERROR))
                ErrorMessage(ERROR_FILENAME_EXCED_RANGE, NULL);
            nErrorLevel = 1;
            continue;
        }

        TRACE("DestinationPath: %s\n", debugstr_aw(dstFinal));

        if (!(dwFlags & REN_QUIET) && !(dwFlags & REN_TOTAL))
            ConOutPrintf(_T("%s -> %s\n"),srcFinal , dstFinal);

        /* Rename the file */
        if (!(dwFlags & REN_NOTHING))
        {
            if (MoveFile(srcFinal, dstFinal))
            {
                dwFiles++;
            }
            else
            {
                if (!(dwFlags & REN_ERROR))
                    ErrorMessage(GetLastError(), NULL);
                nErrorLevel = 1;
            }
        }
    }
    while (FindNextFile(hFile, &f));

    //Closing and Printing errors.
    FindClose(hFile);

    if (!(dwFlags & REN_QUIET))
    {
        if (dwFiles == 1)
            ConOutResPrintf(STRING_REN_HELP2, dwFiles);
        else
            ConOutResPrintf(STRING_REN_HELP3, dwFiles);
    }

    freep(arg);
    return nErrorLevel;
}

#endif

/* EOF */
