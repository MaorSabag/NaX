#include "Nax.h"
#include "Common.h"

/* ========= [ CMD_CD (0x14) ] ========= */

FUNC INT CmdCd( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 1 || args == NULL ) return NAX_ERR_INVAL;

    CHAR path[MAX_PATH_SIZE];
    UINT32 path_len = ( args_len < MAX_PATH_SIZE ) ? args_len : (MAX_PATH_SIZE - 1);
    MmCopy( path, args, path_len );
    path[path_len] = '\0';
    NaxDbg( Nax, "CMD_CD '%s'", path );

    if ( Nax->Kernel32.SetCurrentDirectoryA( path ) ) {
        *out_len = 0;
        return NAX_OK;
    }
    NaxWriteWin32Err( out, out_len );
    return NAX_ERR_FAIL;
}

/* ========= [ CMD_PWD (0x15) ] ========= */

FUNC INT CmdPwd( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    (void)args; (void)args_len;
    if ( *out_len < MAX_PATH_SIZE ) return NAX_ERR_NOMEM;

    DWORD rc = Nax->Kernel32.GetCurrentDirectoryA( MAX_PATH_SIZE, (PCHAR)out );
    NaxDbg( Nax, "CMD_PWD: GetCurrentDirectoryA rc=%lu out_len=%u", (ULONG)rc, *out_len );
    if ( rc == 0 || rc > MAX_PATH_SIZE ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }
    *out_len = rc;
    return NAX_OK;
}

/* ========= [ CMD_MKDIR (0x16) ] ========= */

FUNC INT CmdMkdir( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 1 || args == NULL ) return NAX_ERR_INVAL;

    CHAR path[MAX_PATH_SIZE];
    UINT32 path_len = ( args_len < MAX_PATH_SIZE ) ? args_len : (MAX_PATH_SIZE - 1);
    MmCopy( path, args, path_len );
    path[path_len] = '\0';

    if ( Nax->Kernel32.CreateDirectoryA( path, NULL ) ) {
        *out_len = 0;
        return NAX_OK;
    }
    NaxWriteWin32Err( out, out_len );
    return NAX_ERR_FAIL;
}

/* ========= [ CMD_RMDIR (0x17) ] ========= */

FUNC BOOL NaxDeleteTree( PNAX_INSTANCE Nax, PCHAR dir ) {
    UINT32 dir_len = 0;
    while ( dir[dir_len] ) dir_len++;
    if ( dir_len + 3 > MAX_PATH_SIZE ) return FALSE;

    CHAR pattern[MAX_PATH_SIZE + 3];
    UINT32 plen = dir_len;
    MmCopy( pattern, dir, plen );
    if ( plen > 0 && dir[plen - 1] != '\\' ) pattern[plen++] = '\\';
    pattern[plen]     = '*';
    pattern[plen + 1] = '\0';

    WIN32_FIND_DATAA fd;
    HANDLE h = Nax->Kernel32.FindFirstFileA( pattern, &fd );
    if ( h == INVALID_HANDLE_VALUE ) return FALSE;

    BOOL ok = TRUE;
    do {
        if ( fd.cFileName[0] == '.' &&
             ( fd.cFileName[1] == '\0' ||
               ( fd.cFileName[1] == '.' && fd.cFileName[2] == '\0' ) ) )
            continue;

        CHAR child[MAX_PATH_SIZE];
        UINT32 ci = 0;
        while ( ci < dir_len ) { child[ci] = dir[ci]; ci++; }
        if ( ci > 0 && child[ci - 1] != '\\' ) child[ci++] = '\\';
        UINT32 ni = 0;
        while ( fd.cFileName[ni] && ci < MAX_PATH_SIZE - 1 ) child[ci++] = fd.cFileName[ni++];
        child[ci] = '\0';

        if ( fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) {
            if ( ! NaxDeleteTree( Nax, child ) ) ok = FALSE;
        } else {
            if ( fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY )
                Nax->Kernel32.SetFileAttributesA( child, FILE_ATTRIBUTE_NORMAL );
            if ( ! Nax->Kernel32.DeleteFileA( child ) ) ok = FALSE;
        }
    } while ( Nax->Kernel32.FindNextFileA( h, &fd ) );

    Nax->Kernel32.FindClose( h );

    if ( ok ) ok = Nax->Kernel32.RemoveDirectoryA( dir );
    return ok;
}

FUNC INT CmdRmdir( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 1 || args == NULL ) return NAX_ERR_INVAL;

    BYTE flags = args[0];
    const PBYTE path_raw = args + 1;
    UINT32 path_raw_len  = args_len - 1;

    CHAR path[MAX_PATH_SIZE];
    UINT32 path_len = ( path_raw_len < MAX_PATH_SIZE ) ? path_raw_len : (MAX_PATH_SIZE - 1);
    MmCopy( path, path_raw, path_len );
    path[path_len] = '\0';

    BOOL ok;
    if ( flags & 0x01 ) {
        ok = NaxDeleteTree( Nax, path );
    } else {
        ok = Nax->Kernel32.RemoveDirectoryA( path );
    }

    if ( ok ) {
        *out_len = 0;
        return NAX_OK;
    }
    NaxWriteWin32Err( out, out_len );
    return NAX_ERR_FAIL;
}

/* ========= [ CMD_CAT (0x18) ] ========= */

FUNC INT CmdCat( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 1 || args == NULL ) return NAX_ERR_INVAL;

    CHAR path[MAX_PATH_SIZE];
    UINT32 path_len = ( args_len < MAX_PATH_SIZE ) ? args_len : (MAX_PATH_SIZE - 1);
    MmCopy( path, args, path_len );
    path[path_len] = '\0';

    HANDLE f = Nax->Kernel32.CreateFileA( path, GENERIC_READ, FILE_SHARE_READ,
                                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( f == INVALID_HANDLE_VALUE ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    DWORD read    = 0;
    DWORD to_read = ( *out_len < MAX_FILE_SIZE ) ? *out_len : MAX_FILE_SIZE;
    if ( ! Nax->Kernel32.ReadFile( f, out, to_read, &read, NULL ) ) {
        /* Save error BEFORE CloseHandle which may overwrite LastErrorValue */
        NaxWriteWin32Err( out, out_len );
        Nax->Kernel32.CloseHandle( f );
        return NAX_ERR_FAIL;
    }
    Nax->Kernel32.CloseHandle( f );
    *out_len = read;
    return NAX_OK;
}

/* ========= [ CMD_LS (0x19) ] ========= */

#define LS_TREE_MAX_DEPTH 16

FUNC UINT32 NaxLsTreeCount( PNAX_INSTANCE Nax, PCHAR pattern ) {
    WIN32_FIND_DATAA fd;
    HANDLE h = Nax->Kernel32.FindFirstFileA( pattern, &fd );
    if ( h == INVALID_HANDLE_VALUE ) return 0;
    UINT32 count = 0;
    do {
        if ( fd.cFileName[0] == '.' &&
             ( fd.cFileName[1] == '\0' ||
               ( fd.cFileName[1] == '.' && fd.cFileName[2] == '\0' ) ) )
            continue;
        count++;
    } while ( Nax->Kernel32.FindNextFileA( h, &fd ) );
    Nax->Kernel32.FindClose( h );
    return count;
}

FUNC void NaxLsTreeWrite( PNAX_INSTANCE Nax, PCHAR dir, PBYTE* wp, UINT32* cap,
                           PBYTE prefix, UINT32 prefix_len, UINT32 depth ) {
    if ( depth > LS_TREE_MAX_DEPTH || *cap < 64 ) return;

    UINT32 dir_len = 0;
    while ( dir[dir_len] ) dir_len++;

    CHAR pattern[MAX_PATH_SIZE + 3];
    UINT32 plen = dir_len;
    MmCopy( pattern, dir, plen );
    if ( plen > 0 && dir[plen - 1] != '\\' ) pattern[plen++] = '\\';
    pattern[plen]     = '*';
    pattern[plen + 1] = '\0';

    UINT32 total = NaxLsTreeCount( Nax, pattern );
    if ( total == 0 ) return;

    WIN32_FIND_DATAA fd;
    HANDLE h = Nax->Kernel32.FindFirstFileA( pattern, &fd );
    if ( h == INVALID_HANDLE_VALUE ) return;

    BYTE tee[] = { 0xE2, 0x94, 0x9C, 0xE2, 0x94, 0x80, 0x20 };
    BYTE ell[] = { 0xE2, 0x94, 0x94, 0xE2, 0x94, 0x80, 0x20 };
    BYTE bar[] = { 0xE2, 0x94, 0x82, 0x20, 0x20, 0x20 };
    BYTE spc[] = { 0x20, 0x20, 0x20, 0x20 };

    UINT32 idx = 0;
    do {
        if ( fd.cFileName[0] == '.' &&
             ( fd.cFileName[1] == '\0' ||
               ( fd.cFileName[1] == '.' && fd.cFileName[2] == '\0' ) ) )
            continue;

        idx++;
        BOOL isLast = ( idx == total );
        BOOL isDir  = ( fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) ? TRUE : FALSE;

        UINT32 nlen = 0;
        while ( fd.cFileName[nlen] ) nlen++;

        UINT32 need = prefix_len + 7 + nlen + 2;
        if ( need > *cap ) break;

        if ( prefix_len > 0 ) {
            MmCopy( *wp, prefix, prefix_len );
            *wp += prefix_len; *cap -= prefix_len;
        }

        PBYTE conn = isLast ? ell : tee;
        MmCopy( *wp, conn, 7 ); *wp += 7; *cap -= 7;

        MmCopy( *wp, fd.cFileName, nlen ); *wp += nlen; *cap -= nlen;

        if ( isDir && *cap >= 1 ) { *(*wp)++ = '/'; (*cap)--; }

        if ( *cap >= 1 ) { *(*wp)++ = '\n'; (*cap)--; }

        if ( isDir ) {
            CHAR child[MAX_PATH_SIZE];
            UINT32 ci = 0;
            while ( ci < dir_len ) { child[ci] = dir[ci]; ci++; }
            if ( ci > 0 && child[ci - 1] != '\\' ) child[ci++] = '\\';
            UINT32 ni = 0;
            while ( fd.cFileName[ni] && ci < MAX_PATH_SIZE - 1 ) child[ci++] = fd.cFileName[ni++];
            child[ci] = '\0';

            UINT32 new_plen;
            if ( isLast ) {
                MmCopy( prefix + prefix_len, spc, 4 );
                new_plen = prefix_len + 4;
            } else {
                MmCopy( prefix + prefix_len, bar, 6 );
                new_plen = prefix_len + 6;
            }
            NaxLsTreeWrite( Nax, child, wp, cap, prefix, new_plen, depth + 1 );
        }
    } while ( Nax->Kernel32.FindNextFileA( h, &fd ) );

    Nax->Kernel32.FindClose( h );
}

FUNC INT CmdLs( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    CHAR path[ MAX_PATH_SIZE ];
    BYTE flags = 0;

    if ( args_len >= 1 && args != NULL ) {
        flags = args[0];
        if ( args_len > 1 ) {
            UINT32 path_len = ( args_len - 1 < MAX_PATH_SIZE ) ? (args_len - 1) : (MAX_PATH_SIZE - 1);
            MmCopy( path, args + 1, path_len );
            path[path_len] = '\0';
        } else {
            DWORD rc = Nax->Kernel32.GetCurrentDirectoryA( MAX_PATH_SIZE, path );
            if ( rc == 0 || rc > MAX_PATH_SIZE ) { NaxWriteWin32Err( out, out_len ); return NAX_ERR_FAIL; }
        }
    } else {
        DWORD rc = Nax->Kernel32.GetCurrentDirectoryA( MAX_PATH_SIZE, path );
        if ( rc == 0 || rc > MAX_PATH_SIZE ) { NaxWriteWin32Err( out, out_len ); return NAX_ERR_FAIL; }
    }

    if ( flags & 0x01 ) {
        PBYTE  wp  = out;
        UINT32 cap = *out_len;

        if ( cap < 2 ) return NAX_ERR_NOMEM;
        *wp++ = 0xFF; cap--;

        UINT32 plen = 0;
        while ( path[plen] ) plen++;
        if ( plen + 1 > cap ) return NAX_ERR_NOMEM;
        MmCopy( wp, path, plen ); wp += plen; cap -= plen;
        *wp++ = '\n'; cap--;

        BYTE prefix_buf[256];
        NaxLsTreeWrite( Nax, path, &wp, &cap, prefix_buf, 0, 0 );

        *out_len = (UINT32)( wp - out );
        return NAX_OK;
    }

    UINT32 plen = 0;
    while ( path[ plen ] ) plen++;
    UINT32 path_wire_len = plen;

    CHAR pattern[ MAX_PATH_SIZE + 3 ];
    MmCopy( pattern, path, plen );
    if ( plen > 0 && path[ plen - 1 ] != '\\' ) pattern[ plen++ ] = '\\';
    pattern[ plen++ ] = '*';
    pattern[ plen ]   = '\0';

    WIN32_FIND_DATAA fd;
    HANDLE h = Nax->Kernel32.FindFirstFileA( pattern, &fd );
    if ( h == INVALID_HANDLE_VALUE ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    PBYTE  wp  = out;
    UINT32 cap = *out_len;

    if ( cap < 2 + path_wire_len + 2 ) { Nax->Kernel32.FindClose( h ); return NAX_ERR_NOMEM; }
    NaxW16( wp, (UINT16)path_wire_len ); wp += 2; cap -= 2;
    MmCopy( wp, path, path_wire_len );   wp += path_wire_len; cap -= path_wire_len;

    PBYTE  count_ptr = wp;
    wp += 2; cap -= 2;
    UINT16 count = 0;

    do {
        if ( fd.cFileName[0] == '.' &&
             ( fd.cFileName[1] == '\0' ||
               ( fd.cFileName[1] == '.' && fd.cFileName[2] == '\0' ) ) )
            continue;

        UINT32 nlen = 0;
        while ( fd.cFileName[ nlen ] ) nlen++;
        if ( nlen > 255 ) nlen = 255;

        if ( cap < 11 + nlen ) break;

        BYTE   isDir = ( fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) ? 1 : 0;
        BYTE   attrs = (BYTE)( fd.dwFileAttributes & 0xFFu );
        UINT32 size  = fd.nFileSizeLow;

        UINT64 ft = ( (UINT64)fd.ftLastWriteTime.dwHighDateTime << 32 )
                  | (UINT64)fd.ftLastWriteTime.dwLowDateTime;
        UINT32 ts = ( ft > 116444736000000000ULL )
                  ? (UINT32)( ( ft - 116444736000000000ULL ) / 10000000ULL )
                  : 0;

        *wp++ = isDir; cap--;
        *wp++ = attrs; cap--;
        NaxW32( wp, size ); wp += 4; cap -= 4;
        NaxW32( wp, ts );   wp += 4; cap -= 4;
        *wp++ = (BYTE)nlen; cap--;
        MmCopy( wp, fd.cFileName, nlen ); wp += nlen; cap -= nlen;

        count++;

    } while ( Nax->Kernel32.FindNextFileA( h, &fd ) );

    Nax->Kernel32.FindClose( h );

    NaxW16( count_ptr, count );
    *out_len = (UINT32)( wp - out );
    return NAX_OK;
}

/* ========= [ CMD_RM (0x27) ] ========= */

FUNC INT CmdRm( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 1 || args == NULL ) return NAX_ERR_INVAL;

    BYTE flags = args[0];
    const PBYTE path_raw = args + 1;
    UINT32 path_raw_len  = args_len - 1;

    CHAR path[MAX_PATH_SIZE];
    UINT32 path_len = ( path_raw_len < MAX_PATH_SIZE ) ? path_raw_len : (MAX_PATH_SIZE - 1);
    MmCopy( path, path_raw, path_len );
    path[path_len] = '\0';

    BOOL ok;
    if ( flags & 0x01 ) {
        WIN32_FIND_DATAA fd;
        HANDLE h = Nax->Kernel32.FindFirstFileA( path, &fd );
        DWORD attr = 0;
        if ( h != INVALID_HANDLE_VALUE ) {
            attr = fd.dwFileAttributes;
            Nax->Kernel32.FindClose( h );
        }
        if ( attr & FILE_ATTRIBUTE_DIRECTORY ) {
            ok = NaxDeleteTree( Nax, path );
        } else {
            if ( attr & FILE_ATTRIBUTE_READONLY )
                Nax->Kernel32.SetFileAttributesA( path, FILE_ATTRIBUTE_NORMAL );
            ok = Nax->Kernel32.DeleteFileA( path );
        }
    } else {
        ok = Nax->Kernel32.DeleteFileA( path );
    }

    if ( ok ) {
        *out_len = 0;
        return NAX_OK;
    }
    NaxWriteWin32Err( out, out_len );
    return NAX_ERR_FAIL;
}
