/* beacon/include/Bof.h
 * COFF/BOF loader types - COFF structs, Beacon API interface, output type constants.
 * Beacon API functions (BeaconOutput, BeaconDataParse, ...) are declared here and
 * implemented in src/Bof/Api.c.  The COFF loader lives in src/Bof/Loader.c. */

#pragma once
#include "Macros.h"
#include "Instance.h"

/* ========= [ COFF / BOF constants ] ========= */

#define COF_MACHINE_AMD64       0x8664
#define COF_MACHINE_I386        0x014C

/* x64 relocation types */
#define IMAGE_REL_AMD64_ADDR64  0x0001
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32   0x0004
#define IMAGE_REL_AMD64_REL32_1 0x0005
#define IMAGE_REL_AMD64_REL32_2 0x0006
#define IMAGE_REL_AMD64_REL32_3 0x0007
#define IMAGE_REL_AMD64_REL32_4 0x0008
#define IMAGE_REL_AMD64_REL32_5 0x0009

/* x86 relocation types */
#define IMAGE_REL_I386_DIR32    0x0006
#define IMAGE_REL_I386_REL32    0x0014

/* COFF symbol class */
#define IMAGE_SYM_CLASS_EXTERNAL 0x02
#define IMAGE_SYM_CLASS_STATIC   0x03

/* BeaconOutput / BeaconPrintf callback types (Cobalt Strike convention) */
#define CALLBACK_OUTPUT         0x00
#define CALLBACK_OUTPUT_OEM     0x1E
#define CALLBACK_OUTPUT_UTF8    0x20
#define CALLBACK_ERROR          0x0D

/* Adaptix-extension callback types (adaptix.h) */
#define CALLBACK_AX_SCREENSHOT   0x81
#define CALLBACK_AX_DOWNLOAD_MEM 0x82

/* BOF loader error codes written to BofCtx output on failure */
#define BOF_ERROR_PARSE         0x101   /* malformed COFF              */
#define BOF_ERROR_SYMBOL        0x102   /* unresolved external symbol  */
#define BOF_ERROR_ENTRY         0x104   /* 'go' entry not found        */
#define BOF_ERROR_ALLOC         0x105   /* section allocation failed   */

#define BOF_MAX_SECTIONS        16      /* hard cap on sections per BOF */
#define BOF_OUTPUT_CAP          8192    /* heap output buffer capacity  */

/* NtCurrentProcess() / NtCurrentThread() are provided by ntdll.h via Instance.h */

/* ========= [ COFF structures ] ========= */

#pragma pack(push, 1)

typedef struct _COF_HEADER {
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} COF_HEADER, *PCOF_HEADER;

typedef struct _COF_SECTION {
    CHAR   Name[8];
    UINT32 VirtualSize;
    UINT32 VirtualAddress;
    UINT32 SizeOfRawData;
    UINT32 PointerToRawData;
    UINT32 PointerToRelocations;
    UINT32 PointerToLineNumbers;
    UINT16 NumberOfRelocations;
    UINT16 NumberOfLinenumbers;
    UINT32 Characteristics;
} COF_SECTION, *PCOF_SECTION;

typedef struct _COF_SYMBOL {
    union {
        CHAR   cName[8];
        struct { UINT32 Short; UINT32 Long; } Name;
    };
    UINT32 Value;
    INT16  SectionNumber;
    UINT16 Type;
    BYTE   StorageClass;
    BYTE   NumberOfAuxSymbols;
} COF_SYMBOL, *PCOF_SYMBOL;

typedef struct _COF_RELOCATION {
    UINT32 VirtualAddress;
    UINT32 SymbolTableIndex;
    UINT16 Type;
} COF_RELOCATION, *PCOF_RELOCATION;

/* x64 runtime function entry (one per function in .pdata) */
typedef struct _BOF_RUNTIME_FUNCTION {
    UINT32 BeginAddress;
    UINT32 EndAddress;
    UINT32 UnwindInfoAddress;
} BOF_RUNTIME_FUNCTION;

#pragma pack(pop)

/* ========= [ Beacon API data structures ] ========= */

/* Standard BOF argument parser state - stack-allocated by the BOF's go() */
typedef struct {
    CHAR* original;
    CHAR* buffer;
    INT   length;
    INT   size;
} datap;

/* Format accumulator - heap-allocated via BeaconFormatAlloc */
typedef struct {
    CHAR* original;
    CHAR* buffer;
    INT   length;
    INT   size;
} formatp;

/* ========= [ Beacon API table ] ========= */

typedef struct {
    UINT32 Hash;   /* FNV1a-32 of function name (no __imp_ prefix) */
    PVOID  Proc;
} NAX_BOF_API;

#define NAX_BOF_API_COUNT 33   /* 15 original + 6 beacon.h + 2 adaptix.h + 4 Win32 proxy + 2 async BOF + 3 KV store + 1 heap redirect */

/* ========= [ Beacon API declarations ] ========= */
/* Full contract: beacon.h (CS 4.x compatible).
 * We implement the functions below; everything else in beacon.h is stubbed. */

/* Data parsing */
FUNC VOID  BeaconDataParse( datap* parser, CHAR* buffer, INT size );
FUNC CHAR* BeaconDataPtr( datap* parser, INT size );
FUNC INT   BeaconDataInt( datap* parser );
FUNC SHORT BeaconDataShort( datap* parser );
FUNC INT   BeaconDataLength( datap* parser );
FUNC CHAR* BeaconDataExtract( datap* parser, INT* size );

/* Output */
FUNC VOID  BeaconOutput( INT type, const CHAR* data, INT len );
FUNC VOID  BeaconPrintf( INT type, const CHAR* fmt, ... );

/* Token / utility stubs */
FUNC BOOL  BeaconUseToken( HANDLE token );
FUNC VOID  BeaconRevertToken( VOID );
FUNC BOOL  BeaconIsAdmin( VOID );
FUNC VOID  BeaconGetSpawnTo( BOOL x86, CHAR* buffer, INT length );
FUNC BOOL  BeaconInformation( PVOID info );
FUNC BOOL  toWideChar( CHAR* src, WCHAR* dst, INT max );

/* Format buffer */
FUNC VOID  BeaconFormatAlloc( formatp* format, INT maxsz );
FUNC VOID  BeaconFormatReset( formatp* format );
FUNC VOID  BeaconFormatFree( formatp* format );
FUNC VOID  BeaconFormatAppend( formatp* format, CHAR* text, INT len );
FUNC VOID  BeaconFormatPrintf( formatp* format, CHAR* fmt, ... );
FUNC CHAR* BeaconFormatToString( formatp* format, INT* size );
FUNC VOID  BeaconFormatInt( formatp* format, INT value );

/* Adaptix-extension BOF callbacks (adaptix.h compatible) */
FUNC VOID AxAddScreenshot( CHAR* note, CHAR* data, INT len );
FUNC VOID AxDownloadMemory( CHAR* filename, CHAR* data, INT len );

/* Key-value store */
FUNC BOOL   BeaconAddValue( const CHAR* key, PVOID ptr );
FUNC PVOID  BeaconGetValue( const CHAR* key );
FUNC BOOL   BeaconRemoveValue( const CHAR* key );
FUNC HANDLE BofGetProcessHeap( VOID );

/* Async BOF APIs */
FUNC VOID   BeaconWakeup( VOID );
FUNC HANDLE BeaconGetStopJobEvent( VOID );

/* ========= [ loader entry point ] ========= */

FUNC INT NaxBofExecute( PNAX_INSTANCE Nax,
                        PBYTE bof, UINT32 bof_size,
                        PBYTE user_args, UINT32 user_args_size );

FUNC PVOID NaxBofLoadResident( PNAX_INSTANCE Nax,
                               PBYTE bof, UINT32 bof_size,
                               PCHAR sym_name );

FUNC VOID NaxBofFreeResident( PNAX_INSTANCE Nax );
