/* beacon/include/Cfg.h
 * Control Flow Guard types and constants. */

#pragma once
#include <windows.h>

/* ProcessControlFlowGuardPolicy = 7 (PROCESS_MITIGATION_POLICY enum) */
#define NAX_POLICY_CFG 7

typedef struct {
    union {
        DWORD Flags;
        struct {
            DWORD EnableControlFlowGuard : 1;
            DWORD EnableExportSuppression : 1;
            DWORD StrictMode : 1;
            DWORD EnableXfg : 1;
            DWORD EnableXfgAuditMode : 1;
            DWORD ReservedFlags : 27;
        };
    };
} NAX_CFG_POLICY;

#ifndef CFG_CALL_TARGET_VALID
#define CFG_CALL_TARGET_VALID 0x00000001
#endif

#ifndef CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID
#define CFG_CALL_TARGET_CONVERT_EXPORT_SUPPRESSED_TO_VALID 0x00000004
#endif
