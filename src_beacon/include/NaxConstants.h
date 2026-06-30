/* beacon/include/NaxConstants.h
 * Shared named constants for magic values used across the beacon.
 * Replaces inline hex/decimal literals with descriptive macros. */

#pragma once

/* ========= [ memory alignment ] ========= */

#define NAX_PAGE_SIZE           0x1000u
#define NAX_PAGE_MASK           0x0FFFu
#define ALIGN_UP( size, align ) ( ( (size) + ((align) - 1) ) & ~( (SIZE_T)(align) - 1 ) )

/* ========= [ transport buffer sizes ] ========= */

#define NAX_IO_CAP              ( 8 * 1024 * 1024 )    /* 8 MB - Http.c + Smb.c result/IO cap */
#define NAX_REG_BODY_BUF        1200                    /* registration body stack buffer       */
#define NAX_PIPE_CHUNK_SIZE     0x2000u                 /* 8 KB - pipe write chunk (Smb + Pivot) */
#define NAX_PIPE_BUF_SIZE       0x10000u                /* 64 KB - CreateNamedPipeA buffer size */
#define NAX_PIPE_IO_TIMEOUT_MS  5000u                   /* 5 s - pipe read/write timeout         */

/* ========= [ Winsock SDK constants (PIC: not from headers) ] ========= */

#define NAX_AF_INET             2
#define NAX_SOCK_STREAM         1
#define NAX_IPPROTO_TCP         6

#define NAX_SOL_SOCKET          0xFFFF
#define NAX_SO_RCVTIMEO         0x1006
#define NAX_SO_SNDTIMEO         0x1005
#define NAX_SO_REUSEADDR        0x0004

#define NAX_FIONBIO             0x8004667Eu
#define NAX_INADDR_NONE         0xFFFFFFFFu
#define NAX_INADDR_LOOPBACK_NBO 0x0100007Fu  /* 127.0.0.1 in network byte order */
#define NAX_WSAEWOULDBLOCK      10035

#define NAX_SD_SEND             1            /* shutdown(sock, SD_SEND) */
#define NAX_SD_BOTH             2            /* shutdown(sock, SD_BOTH) */

/* FD_* event masks for WSAEventSelect */
#define NAX_FD_READ             0x01
#define NAX_FD_WRITE            0x02
#define NAX_FD_ACCEPT           0x08
#define NAX_FD_CONNECT          0x10
#define NAX_FD_CLOSE            0x20

/* ========= [ tunnel operational constants ] ========= */

#define NAX_TUNNEL_RECV_MAX_ITER      16
#define NAX_TUNNEL_RECV_BUDGET_MS     2500
#define NAX_TUNNEL_RECV_HDR_RESERVE   16       /* entry header + payload header */
#define NAX_TUNNEL_RECV_CHUNK_MAX     131072u  /* 128 KB max single recv */
#define NAX_TUNNEL_DRAIN_TIMEOUT_MS   5000
#define NAX_TUNNEL_CLOSE_GRACE_MS     1000

/* ========= [ Win32 SDK constants (PIC: not from headers) ] ========= */

#define NAX_TOKEN_QUERY                0x0008u
#define NAX_TOKEN_ELEVATION_TYPE       20
#define NAX_MIB_IF_TYPE_LOOPBACK       24

/* PEB offset accessors for OS version (x64) */
#define NAX_PEB_OSMAJOR_OFFSET         0x118u
#define NAX_PEB_OSMINOR_OFFSET         0x11Cu
#define NAX_PEB_OSBUILD_OFFSET         0x120u

/* Process info class for CFG policy */
#define NAX_PROCESS_CFG_GUARD_POLICY   7
#define NAX_CFG_CALL_TARGET_VALID      1

/* ========= [ BOF constants ] ========= */

#define NAX_BOF_MAPFN_MAX              512

/* ========= [ stomp context tag ] ========= */

#define NAX_STOMP_CTX_MAGIC            0x4E415854u  /* 'NAXT' - loader writes at (code start + code size) */

/* ========= [ miscellaneous ] ========= */

#define NAX_PS_OUTPUT_WAIT_MS          10000
#define NAX_ERROR_INVALID_PARAMETER    87
#define NAX_SYSINFO_EXTRA_BUF          0x1000
#define NAX_ARCH_UNKNOWN               10
