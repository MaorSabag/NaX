/* beacon/src/Core/PackerProfile.c
 * PROFILE v1/v2 wire format decoder.  Splits from Packer.c for readability.
 * Uses NaxR16 / NaxR32 from Packer.c via forward declarations. */

#include "Nax.h"

/* ========= [ PROFILE body decode helpers ] ========= */

/* Reads a length-prefixed string (len:uint16LE + bytes) from `data` at `*off`.
 * Copies up to `cap-1` bytes into `dst`, NUL-terminates. Advances `*off`. */
FUNC INT NaxReadLpStr( const PBYTE data, UINT32 data_len, UINT32* off, PCHAR dst, UINT32 cap ) {
    if ( *off + 2 > data_len ) return NAX_ERR_WIRE;
    UINT16 slen = NaxR16( data + *off );
    *off += 2;
    if ( *off + slen > data_len ) return NAX_ERR_WIRE;
    UINT32 cpy = slen < cap - 1 ? slen : cap - 1;
    MmCopy( dst, data + *off, cpy );
    dst[ cpy ] = '\0';
    *off += slen;
    return NAX_OK;
}

/* Skips a length-prefixed string without copying content. */
FUNC INT NaxSkipLpStr( const PBYTE data, UINT32 data_len, UINT32* off ) {
    if ( *off + 2 > data_len ) return NAX_ERR_WIRE;
    UINT16 slen = NaxR16( data + *off );
    *off += 2 + slen;
    if ( *off > data_len ) return NAX_ERR_WIRE;
    return NAX_OK;
}

/* Reads one OutputConfig block from the wire binary.
 * Wire layout: format(1) + mask(1) + placement(1) + name(lpstr)
 *            + prepend(lpstr) + append(lpstr) + empty_resp(lpstr) */
FUNC INT NaxReadOutputCfg( const PBYTE data, UINT32 data_len, UINT32* off, NAX_OUTPUT_CFG* cfg ) {
    if ( *off + 3 > data_len ) return NAX_ERR_WIRE;
    cfg->Format    = data[ *off ]; *off += 1;
    cfg->Mask      = data[ *off ]; *off += 1;
    cfg->Placement = data[ *off ]; *off += 1;

    INT rc;
    rc = NaxReadLpStr( data, data_len, off, cfg->Name, 128 );
    if ( rc != NAX_OK ) return rc;

    UINT32 before;
    UINT16 slen;

    before = *off;
    rc = NaxReadLpStr( data, data_len, off, cfg->Prepend, 512 );
    if ( rc != NAX_OK ) return rc;
    slen = ( before + 2 <= data_len ) ? NaxR16( data + before ) : 0;
    cfg->PrependLen = slen < 511 ? slen : 511;

    before = *off;
    rc = NaxReadLpStr( data, data_len, off, cfg->Append, 512 );
    if ( rc != NAX_OK ) return rc;
    slen = ( before + 2 <= data_len ) ? NaxR16( data + before ) : 0;
    cfg->AppendLen = slen < 511 ? slen : 511;

    before = *off;
    rc = NaxReadLpStr( data, data_len, off, cfg->EmptyResp, 512 );
    if ( rc != NAX_OK ) return rc;
    slen = ( before + 2 <= data_len ) ? NaxR16( data + before ) : 0;
    cfg->EmptyRespLen = slen < 511 ? slen : 511;

    return NAX_OK;
}

/* --------- [ v2 profile parser ] --------- */

/* Decode PROFILE v2 frame body into NAX_CONFIG fields.
 * V2 wire format (all LE):
 *   version(1) + rotation(1)
 *   user_agent: lpstr
 *   beacon_id_hdr: lpstr
 *   host_count(2) [lpstr]...
 *   server_error: err_status(2) + err_body(lpstr) + err_hdr_count(2) + [lpstr]...
 *   GET block:
 *     uri_count(2) [lpstr]...
 *     client_meta: OutputConfig
 *     client_hdr_count(2) [lpstr]...
 *     client_param_count(2) [lpstr]...
 *     server_output: OutputConfig
 *     server_hdr_count(2) [lpstr]...  (skipped)
 *   POST block:
 *     uri_count(2) [lpstr]...
 *     client_meta: OutputConfig
 *     client_output: OutputConfig
 *     client_hdr_count(2) [lpstr]...
 *     server_output: OutputConfig
 *     server_hdr_count(2) [lpstr]...  (skipped)
 *
 * Falls back to v1 flat format when version != 0x02. */
FUNC INT NaxDecodeProfile( const PBYTE data, UINT32 data_len, PNAX_INSTANCE Nax ) {
    UINT32 off = 0;
    INT    rc;
    UINT16 itemCount;
    UINT16 i;

    if ( data_len < 2 ) return NAX_ERR_WIRE;

    BYTE first = data[ off ]; off += 1;

    if ( first == 0x02 ) {
        /* ========= v2 format ========= */
        Nax->Config.ProfileVersion = 2;
        Nax->Config.Rotation       = data[ off ]; off += 1;

        /* User-Agent */
        rc = NaxReadLpStr( data, data_len, &off, Nax->Config.UserAgent, 256 );
        if ( rc != NAX_OK ) return rc;

        /* Beacon ID header name */
        rc = NaxReadLpStr( data, data_len, &off, Nax->Config.BeaconIdHdr, 128 );
        if ( rc != NAX_OK ) return rc;

        /* Callback hosts */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 4 ) itemCount = 4;
        Nax->Config.HostCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.Hosts[ i ], 128 );
            if ( rc != NAX_OK ) return rc;
        }

        /* Server error block - beacon doesn't use, skip entirely */
        /* err_status(2) */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        off += 2;
        /* err_body(lpstr) */
        rc = NaxSkipLpStr( data, data_len, &off );
        if ( rc != NAX_OK ) return rc;
        /* err_hdr_count(2) + [lpstr]... */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxSkipLpStr( data, data_len, &off );
            if ( rc != NAX_OK ) return rc;
        }

        /* --------- GET block --------- */

        /* GET URIs */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 8 ) itemCount = 8;
        Nax->Config.GetUriCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.GetUris[ i ], 128 );
            if ( rc != NAX_OK ) return rc;
        }

        /* GET client metadata OutputConfig */
        rc = NaxReadOutputCfg( data, data_len, &off, &Nax->Config.GetClientMeta );
        if ( rc != NAX_OK ) return rc;

        /* GET client headers */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 8 ) itemCount = 8;
        Nax->Config.GetClientHdrCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.GetClientHdrs[ i ], 256 );
            if ( rc != NAX_OK ) return rc;
        }

        /* GET client parameters */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 8 ) itemCount = 8;
        Nax->Config.GetClientParamCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.GetClientParams[ i ], 128 );
            if ( rc != NAX_OK ) return rc;
        }

        /* GET server output OutputConfig */
        rc = NaxReadOutputCfg( data, data_len, &off, &Nax->Config.GetServerOutput );
        if ( rc != NAX_OK ) return rc;

        /* GET server headers - beacon doesn't need, skip */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxSkipLpStr( data, data_len, &off );
            if ( rc != NAX_OK ) return rc;
        }

        /* --------- POST block --------- */

        /* POST URIs */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 8 ) itemCount = 8;
        Nax->Config.PostUriCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.PostUris[ i ], 128 );
            if ( rc != NAX_OK ) return rc;
        }

        /* POST client metadata OutputConfig */
        rc = NaxReadOutputCfg( data, data_len, &off, &Nax->Config.PostClientMeta );
        if ( rc != NAX_OK ) return rc;

        /* POST client output OutputConfig */
        rc = NaxReadOutputCfg( data, data_len, &off, &Nax->Config.PostClientOutput );
        if ( rc != NAX_OK ) return rc;

        /* POST client headers */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 8 ) itemCount = 8;
        Nax->Config.PostClientHdrCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.PostClientHdrs[ i ], 256 );
            if ( rc != NAX_OK ) return rc;
        }

        /* POST server output OutputConfig */
        rc = NaxReadOutputCfg( data, data_len, &off, &Nax->Config.PostServerOutput );
        if ( rc != NAX_OK ) return rc;

        /* POST server headers - beacon doesn't need, skip */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxSkipLpStr( data, data_len, &off );
            if ( rc != NAX_OK ) return rc;
        }

    } else {
        /* ========= v1 fallback ========= */
        /* In v1 there is no version byte - first byte was rotation */
        Nax->Config.ProfileVersion = 1;
        Nax->Config.Rotation       = first;

        /* GET URIs */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 8 ) itemCount = 8;
        Nax->Config.GetUriCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.GetUris[ i ], 128 );
            if ( rc != NAX_OK ) return rc;
        }

        /* POST URIs */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 8 ) itemCount = 8;
        Nax->Config.PostUriCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.PostUris[ i ], 128 );
            if ( rc != NAX_OK ) return rc;
        }

        /* User-Agents - v1 had a list, take the first one */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        UINT16 ua_count = NaxR16( data + off ); off += 2;
        for ( i = 0; i < ua_count; i++ ) {
            if ( i == 0 ) {
                rc = NaxReadLpStr( data, data_len, &off, Nax->Config.UserAgent, 256 );
            } else {
                rc = NaxSkipLpStr( data, data_len, &off );
            }
            if ( rc != NAX_OK ) return rc;
        }

        /* Extra headers - map to GetClientHdrs */
        if ( off + 2 > data_len ) return NAX_ERR_WIRE;
        itemCount = NaxR16( data + off ); off += 2;
        if ( itemCount > 8 ) itemCount = 8;
        Nax->Config.GetClientHdrCount = (BYTE)itemCount;
        for ( i = 0; i < itemCount; i++ ) {
            rc = NaxReadLpStr( data, data_len, &off, Nax->Config.GetClientHdrs[ i ], 256 );
            if ( rc != NAX_OK ) return rc;
        }

        /* Cookie name - map to GetClientMeta with COOKIE placement, BASE64 format */
        CHAR cookie_name[ 64 ];
        MmZero( cookie_name, 64 );
        rc = NaxReadLpStr( data, data_len, &off, cookie_name, 64 );
        if ( rc != NAX_OK ) return rc;

        Nax->Config.GetClientMeta.Format    = NAX_FMT_BASE64;
        Nax->Config.GetClientMeta.Mask      = 0;
        Nax->Config.GetClientMeta.Placement = NAX_PLACE_COOKIE;
        MmCopy( Nax->Config.GetClientMeta.Name, cookie_name, 64 );
        Nax->Config.GetClientMeta.Prepend[ 0 ]   = '\0';
        Nax->Config.GetClientMeta.PrependLen      = 0;
        Nax->Config.GetClientMeta.Append[ 0 ]     = '\0';
        Nax->Config.GetClientMeta.AppendLen        = 0;
        Nax->Config.GetClientMeta.EmptyResp[ 0 ]  = '\0';
        Nax->Config.GetClientMeta.EmptyRespLen     = 0;

        /* v1 rotation byte was already consumed as `first` */

        /* Default POST client meta to HEADER placement */
        Nax->Config.PostClientMeta.Format    = NAX_FMT_BASE64;
        Nax->Config.PostClientMeta.Mask      = 0;
        Nax->Config.PostClientMeta.Placement = NAX_PLACE_HEADER;
        Nax->Config.PostClientMeta.Name[ 0 ] = '\0';
        Nax->Config.PostClientMeta.Prepend[ 0 ]   = '\0';
        Nax->Config.PostClientMeta.PrependLen      = 0;
        Nax->Config.PostClientMeta.Append[ 0 ]     = '\0';
        Nax->Config.PostClientMeta.AppendLen        = 0;
        Nax->Config.PostClientMeta.EmptyResp[ 0 ]  = '\0';
        Nax->Config.PostClientMeta.EmptyRespLen     = 0;

        /* Default POST client output to BODY placement */
        Nax->Config.PostClientOutput.Format    = NAX_FMT_RAW;
        Nax->Config.PostClientOutput.Mask      = 0;
        Nax->Config.PostClientOutput.Placement = NAX_PLACE_BODY;
        Nax->Config.PostClientOutput.Name[ 0 ] = '\0';
        Nax->Config.PostClientOutput.Prepend[ 0 ]   = '\0';
        Nax->Config.PostClientOutput.PrependLen      = 0;
        Nax->Config.PostClientOutput.Append[ 0 ]     = '\0';
        Nax->Config.PostClientOutput.AppendLen        = 0;
        Nax->Config.PostClientOutput.EmptyResp[ 0 ]  = '\0';
        Nax->Config.PostClientOutput.EmptyRespLen     = 0;
    }

    Nax->Config.GetUriIdx     = 0;
    Nax->Config.PostUriIdx    = 0;
    Nax->Config.ProfileLoaded = 1;

    return NAX_OK;
}
