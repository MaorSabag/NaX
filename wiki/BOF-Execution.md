# BOF Execution

BOF (Beacon Object File) execution lets operators run compiled C object files inside the beacon's process. No child process is created, nothing is written to disk. The beacon contains a built-in COFF loader that allocates, relocates, and executes BOFs entirely in memory.

A BOF is a standard COFF `.o` file compiled with MinGW or MSVC. It exports a single entry point named `go`, which receives packed arguments from the operator. It can call back into the beacon via the Beacon API (output, data parsing, format buffers) and can call any Win32 API using the `MODULE$FUNCTION` naming convention.

## Source Layout

The COFF loader is a unity build rooted at `src_beacon/src/Bof/Loader.c`:

| File | Role |
|------|------|
| `Loader.c` | COFF parser, section allocator, relocation engine, entry point search, `NaxBofExecute()` |
| `Api.c` | Beacon API implementations (BeaconOutput, BeaconDataParse, BeaconFormat*, etc.) |
| `Stomp.c` | Module stomping allocator - execute BOF .text from image-backed DLL memory |

`Loader.c` includes `Api.c` and `Stomp.c` via `#include` directives, producing a single translation unit. This is required because MinGW cross-unit references produce `.refptr.*` stubs that live outside `.text`. Since only `.text` is extracted for PIC shellcode, those stubs would be missing at runtime and all function addresses would resolve to stale link-time offsets.

## Loading Pipeline

`NaxBofExecute()` processes a COFF object in six steps:

### Step 1: Allocate Sections

Each COFF section gets its own allocation. The loader tries module stomping first (`NaxBofStompAlloc`); if stomping is disabled or the BOF does not fit, it falls back to `NtAllocateVirtualMemory` with `MEM_TOP_DOWN`.

`MEM_TOP_DOWN` places allocations near DLLs at high virtual addresses (around `0x7FF9...`), keeping REL32 displacements within the +/-2 GB range required by x64 RIP-relative addressing.

After all sections are allocated, a 4 KB `mapFunctions` buffer is allocated in the same region. Allocating it last (not first) is important: allocating first would place it in a separate region 6 TB away from the sections, overflowing 32-bit REL32 displacements.

`.bss` sections (zero-initialized globals) have `SizeOfRawData = 0` and `VirtualSize > 0`. The loader uses `VirtualSize` in that case and relies on `NtAllocateVirtualMemory`'s zero-fill guarantee.

`image_base` is set to the minimum address across all allocated sections and `mapFunctions`. This ensures all `ADDR32NB` RVAs are non-negative.

### Step 2: Process Relocations

The loader walks every relocation entry in every section. For each relocation:

- **Internal symbols** (SectionNumber > 0) resolve to `mapSections[secIdx] + sym->Value`
- **External symbols** go through `NaxBofResolveExternal()` (described below)

The `__imp_` prefix (6 bytes) is stripped before resolution, so both `__imp_BeaconOutput` and `BeaconOutput` resolve identically.

Supported relocation types:

| Type | Architecture | Behavior |
|------|-------------|----------|
| `IMAGE_REL_AMD64_ADDR64` (0x01) | x64 | 64-bit absolute address; adds `sym_addr` to the 8-byte value at the relocation site |
| `IMAGE_REL_AMD64_ADDR32NB` (0x03) | x64 | 32-bit RVA relative to `image_base`; reads 4-byte addend, adds `sym_addr - image_base` |
| `IMAGE_REL_AMD64_REL32` through `REL32_5` (0x04-0x09) | x64 | 32-bit RIP-relative displacement; see below |
| `IMAGE_REL_I386_DIR32` (0x06) | x86 | 32-bit absolute address |
| `IMAGE_REL_I386_REL32` (0x14) | x86 | 32-bit PC-relative displacement |

#### REL32 and mapFunctions

External `REL32` relocations cannot point directly to 64-bit function addresses (the displacement would overflow 32 bits). Instead, the loader stores the 64-bit function pointer in the next free 8-byte slot of `mapFunctions` and patches the displacement to point at that slot. This adds one level of indirection (matching the `FF 15` indirect call pattern from `__imp_*` symbols) but keeps everything within +/-2 GB.

The formula applied at the relocation site:

```
disp32 = addend + target - (loc + 4 + delta)
```

Where `delta` is `Type - IMAGE_REL_AMD64_REL32` (0 for REL32, 1 for REL32_1, etc.) and `addend` is the existing 4-byte signed value at the site.

Internal symbols (same COFF, section already allocated nearby) skip `mapFunctions` and patch the displacement directly.

### Step 3: Set Protections

**Stomped path**: `.text` is set to `PAGE_EXECUTE_READ` (RX); all other sections stay `PAGE_READWRITE` (RW). This is the clean configuration.

**Non-stomped path**: All sections get `PAGE_EXECUTE_READWRITE` (RWX). Fine-grained RX/RO protection crashes because the Windows unwind machinery writes through `.pdata` and `.xdata` sections before control reaches the first BOF instruction.

### Step 3b: Register .pdata

For stomped BOFs, the loader injects the BOF's `RUNTIME_FUNCTION` entries into the sacrificial DLL's `.pdata` section. The Inverted Function Table (IFT) already points to that `.pdata`, so the unwinder finds the BOF's entries through the normal IFT lookup path - no dynamic registration needed.

Entries are placed at the end of the DLL's `.pdata` (the leading entries were zeroed during stomp setup, so they sort before the BOF entries and the IFT binary search still works).

If `.pdata` injection fails, the loader falls back to `RtlAddFunctionTable` for dynamic registration.

### Step 4: Find Entry

The loader scans the COFF symbol table for a symbol named `go` (or `_go` on x86). This is the BOF's entry point. The function signature is:

```c
void go(char* args, unsigned long args_size);
```

### Step 5: Execute

The loader calls `go(user_args, user_args_size)` directly. The BOF runs synchronously in the calling thread (for sync BOFs) or in a thread pool worker (for async BOFs).

### Step 6: Cleanup

**Stomped**: Restore the DLL's original `.text` and `.pdata` content from backups. Free all private-memory sections (non-`.text`).

**Non-stomped**: Free all sections and `mapFunctions` via `NtFreeVirtualMemory`.

If `.pdata` was registered dynamically (fallback path), `RtlDeleteFunctionTable` removes it before freeing memory.

## External Symbol Resolution

`NaxBofResolveExternal()` resolves symbols in three stages:

1. **Beacon API table** - Hashes the symbol name (FNV1a-32) and checks against the 29-entry API table. Matches return the pointer to the beacon's implementation directly.

2. **MODULE$FUNCTION pattern** - If the symbol contains `$` (e.g., `KERNEL32$VirtualAlloc`), the loader splits at `$`. The module name is lowercased, suffixed with `.dll`, hashed with FNV1a-32, and resolved via PEB walk (`NaxGetModule`). If the module is not loaded, `LoadLibraryA` loads it. The function is then resolved via `GetProcAddress` (not `NaxGetProc`) because `GetProcAddress` handles forwarded exports (e.g., `ole32!CreateStreamOnHGlobal` forwarded to `combase`) that the beacon's hash-based resolver cannot follow.

3. **Bare symbol fallback** - Symbols with no `$` separator that did not match the Beacon API table are passed to `GetProcAddress(kernel32, sym_name)` as a last resort. This handles `__imp_*` symbols from `<windows.h>` declarations (e.g., `HeapAlloc`, `VirtualAlloc`) that are not in the Beacon API table.

Unresolved symbols cause `NaxBofExecute` to abort with `NAX_ERR_FAIL` and send the symbol name to the operator via `BeaconOutput(CALLBACK_ERROR, ...)`.

## Beacon API

The beacon exposes 29 functions to BOFs, initialized at the start of every `NaxBofExecute` call via `NaxBofInitApiTable()`. Each entry is a hash/pointer pair; the hash is FNV1a-32 of the function name.

### Data Parsing

BOF arguments arrive as a packed binary buffer with a 4-byte LE total-length header. `BeaconDataParse` skips this header and initializes the parser state.

```c
void  BeaconDataParse(datap* parser, char* buffer, int size);
int   BeaconDataInt(datap* parser);           // 4-byte LE integer
short BeaconDataShort(datap* parser);         // 2-byte LE short
char* BeaconDataExtract(datap* parser, int* size);  // length-prefixed blob
char* BeaconDataPtr(datap* parser, int size);       // fixed-size read (no prefix)
int   BeaconDataLength(datap* parser);        // remaining bytes
```

### Output

```c
void BeaconOutput(int type, const char* data, int len);
void BeaconPrintf(int type, const char* fmt, ...);
```

Output accumulates in `NAX_INSTANCE.BofCtx.Buf`, an 8 KB heap buffer. Consecutive `BeaconOutput` calls are separated by `\n` if the previous call did not end with one. `BeaconPrintf` formats into a 1 KB stack buffer via `_vsnprintf` then calls `BeaconOutput`.

Output type constants:

| Constant | Value | Meaning |
|----------|-------|---------|
| `CALLBACK_OUTPUT` | 0x00 | Normal text output |
| `CALLBACK_OUTPUT_OEM` | 0x1E | OEM-encoded text |
| `CALLBACK_OUTPUT_UTF8` | 0x20 | UTF-8 text |
| `CALLBACK_ERROR` | 0x0D | Error message |

### Format Buffer

Heap-allocated accumulation buffer for building structured output:

```c
void  BeaconFormatAlloc(formatp* fmt, int maxsz);
void  BeaconFormatReset(formatp* fmt);
void  BeaconFormatFree(formatp* fmt);
void  BeaconFormatAppend(formatp* fmt, char* text, int len);
void  BeaconFormatPrintf(formatp* fmt, char* fmt_str, ...);
char* BeaconFormatToString(formatp* fmt, int* size);
void  BeaconFormatInt(formatp* fmt, int value);  // 4-byte big-endian
```

`BeaconFormatInt` packs integers in network byte order (big-endian), matching the Cobalt Strike convention.

### Utility

```c
BOOL BeaconIsAdmin(void);                        // stub (Phase 7A)
BOOL BeaconUseToken(HANDLE token);               // stub
void BeaconRevertToken(void);                     // stub
void BeaconGetSpawnTo(BOOL x86, char* buf, int len);  // stub
BOOL BeaconInformation(void* info);               // stub
BOOL toWideChar(char* src, WCHAR* dst, int max);  // MultiByteToWideChar wrapper
```

### Adaptix Extensions

Two additional callbacks for sending media back to the Adaptix server:

```c
void AxAddScreenshot(char* note, char* data, int len);
void AxDownloadMemory(char* filename, char* data, int len);
```

Each call allocates a `NAX_BOF_MEDIA` node and prepends it to `BofCtx.MediaHead`. Multiple media entries per BOF execution are supported. Wire format:

```
Screenshot (0x81): [0x81][note_len(4LE)][note][img_len(4LE)][img]
Download   (0x82): [0x82][name_len(4LE)][name][data_len(4LE)][data]
```

### Win32 Proxies

Four functions are proxied from the beacon's resolved kernel32 pointers:

```c
LoadLibraryA(...)
GetProcAddress(...)
GetModuleHandleA(...)
FreeLibrary(...)
```

These handle BOFs that declare `DECLSPEC_IMPORT` Win32 functions (producing `__imp_LoadLibraryA` COFF symbols with no `MODULE$` prefix).

### Async BOF APIs

```c
void   BeaconWakeup(void);            // signals main thread to drain output
HANDLE BeaconGetStopJobEvent(void);   // event handle, set when operator kills the job
```

## Module Stomping

When enabled, BOF `.text` executes from image-backed (IMG) memory instead of private (PRV) allocations. This avoids the "executable private memory" detection heuristic.

### How It Works

At beacon startup, `NaxBofStompInit()` loads one or more sacrificial DLLs using `LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES)`. This gives each DLL a clean image-backed `.text` section without calling `DllMain` or resolving imports.

For each DLL, the loader:

1. Locates the `.text` section and records its base address and capacity
2. Backs up the original `.text` content (for restoration after BOF execution)
3. Locates and backs up the `.pdata` section (exception unwind data)

### Slot Pool

The stomp pool has two tiers:

- **Sync slot** (1) - Used for synchronous BOF execution. Configured via `Config.BofSyncDll`.
- **Async slots** (up to `BOF_STOMP_ASYNC_MAX`) - Used for async BOFs. Each concurrent async BOF needs its own slot. Configured via `Config.BofAsyncDlls[]`.

Slot selection: if `CurrentJob == NULL` (sync), use the sync slot. Otherwise, pick the first free async slot whose `.text` capacity fits the BOF.

### Near Allocator

Non-`.text` COFF sections and `mapFunctions` must be within +/-2 GB of the stomped DLL for REL32 relocations. `StompAllocNear()` probes 64 KB-aligned addresses forward and backward from the DLL image, within +/-16 MB, using `NtAllocateVirtualMemory` without `MEM_TOP_DOWN`.

### Stomp Lifecycle

**Allocate**: VirtualProtect the DLL's `.text` to RW, zero it, copy the BOF's `.text` in. Zero the DLL's `.pdata` so injected entries take priority. Allocate non-`.text` sections and `mapFunctions` nearby.

**Protect**: Set DLL `.text` back to RX. Private sections stay RW.

**Free**: Restore original `.text` and `.pdata` from backups. Free all private allocations. Mark the slot as not in use.

### Runtime Reconfiguration

The `bof_stomp` command (`CMD_BOF_STOMP`, 0x31) allows operators to swap sacrificial DLLs at runtime without restarting the beacon. Sub-commands:

| Sub-command | Wire byte | Effect |
|-------------|-----------|--------|
| sync | 0x00 | Replace the sync DLL with a new one |
| async | 0x01 | Replace the entire async pool |
| show | 0x02 | Dump current stomp configuration (DLL names, .text capacity, in-use status) |

## Sync vs Async Execution

### Sync BOFs

`NaxCmdBof()` allocates an 8 KB output buffer in `BofCtx`, calls `NaxBofExecute()` directly, and returns the output in the task result. The beacon's heartbeat loop is blocked for the duration.

### Async BOFs

When the operator passes the `-a` flag, `NaxCmdBof()` creates a `NAX_JOB` and submits it to the Windows thread pool via `TpAllocWork` / `TpPostWork`. The command handler returns `NAX_STATUS_ASYNC` immediately, and the heartbeat loop continues.

The job thread:

1. Sets `TEB->ArbitraryUserPointer` to the `NAX_INSTANCE` pointer (so `G_INSTANCE` works)
2. Swaps `Nax->BofCtx` to the job's private output buffer (under a critical section)
3. Calls `NaxBofExecute()`
4. Swaps `BofCtx` back and marks the job as `NAX_JOB_FINISHED`
5. Signals `JobWakeEvent` so the main thread drains output on the next heartbeat

Output drains incrementally: `NaxProcessJobs()` runs each heartbeat, tries to acquire the job's critical section, and packs any accumulated output into job result frames.

### Job Lifecycle

```
PENDING -> RUNNING -> FINISHED -> (drained + freed)
                   -> KILLED   -> (drained + freed)
                   -> KILLED [abandoned] -> (leaked)
```

**Watchdog**: Each job has a timeout (default 60 seconds, configurable per-BOF). `NaxProcessJobs()` checks elapsed time and calls `NaxJobKill()` if exceeded.

**Kill**: Sets `hStopEvent` (cooperative) then waits 500 ms for the thread to exit. If the thread does not exit, the job is marked as abandoned. `TerminateThread` is intentionally avoided because it corrupts ntdll's thread pool state and crashes the process.

**Abandoned jobs**: The thread is left running. Partial output is snapshot from `BofCtx` and the main-thread context is restored. Resources are intentionally leaked (a few KB) - a dead beacon is worse than a small leak.

### Job Result Wire Format

Each heartbeat can carry multiple job frames:

```
[type(1)][task_id(4LE)][data_len(4LE)][data...]
```

Type bytes:

| Type | Meaning |
|------|---------|
| `NAX_JOB_OUTPUT` | Incremental output from a running job |
| `NAX_JOB_COMPLETE` | Final output - job finished normally |
| `NAX_JOB_KILLED` | Final output - job was killed or timed out |

The final drain (COMPLETE or KILLED) includes a 2-byte stomp metadata prefix (`[stomped(1)][slot_idx(1)]`) before the output payload.

## Task Wire Format

The `CMD_BOF` (0x20) task arguments:

```
async_flag(1) | timeout_secs(4LE) | bof_size(4LE) | bof_bytes | user_args_size(4LE) | user_args
```

| Field | Size | Description |
|-------|------|-------------|
| `async_flag` | 1 byte | 0x00 = sync, non-zero = async |
| `timeout_secs` | 4 bytes LE | Async timeout (0 = default 60s) |
| `bof_size` | 4 bytes LE | Size of COFF object data |
| `bof_bytes` | variable | Raw COFF .o file content |
| `user_args_size` | 4 bytes LE | Size of packed BOF arguments |
| `user_args` | variable | Packed arguments (bof_pack format) |

## Result Wire Format

BOF results support text output, media entries (screenshots, downloads), or both.

**Text only** (no media):

```
[stomp_status(1)][stomp_slot(1)][text_bytes...]
```

**Media + text** (compound):

```
[stomp_status(1)][stomp_slot(1)][media_entry]...[0x00][text_len(4LE)][text]
```

**Media only**:

```
[stomp_status(1)][stomp_slot(1)][media_entry]...
```

## Operator Usage

From the Adaptix operator UI:

```
bof /path/to/file.x64.o [args]       # synchronous execution
bof -a /path/to/file.x64.o [args]    # asynchronous execution
```

Arguments are packed on the server side using `ax.bof_pack()` in AxScript:

```javascript
var packed = ax.bof_pack("iZz", [pid, wide_path, ansi_name]);
```

Pack type characters:

| Type | Character | Description |
|------|-----------|-------------|
| `bytes` | `b` | Raw byte buffer |
| `int` | `i` | 4-byte LE integer |
| `short` | `s` | 2-byte LE short |
| `cstr` | `z` | Null-terminated ANSI string (length-prefixed on wire) |
| `wstr` | `Z` | Null-terminated wide string (length-prefixed on wire) |

## Writing a BOF

A minimal BOF:

```c
#include "beacon.h"

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);
    int pid = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "target pid: %d\n", pid);
}
```

To call Win32 APIs, declare them with the `MODULE$FUNCTION` convention:

```c
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);

void go(char* args, int alen) {
    HANDLE h = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 1234);
    // ...
}
```

The loader strips the `__imp_` prefix, splits at `$`, resolves the module via PEB walk (or `LoadLibraryA` if not loaded), and resolves the function via `GetProcAddress`.

## COFF Structures

For reference, the COFF structures parsed by the loader (from `Bof.h`):

```c
typedef struct _COF_HEADER {
    UINT16 Machine;              // 0x8664 (AMD64) or 0x014C (i386)
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} COF_HEADER;

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
} COF_SECTION;

typedef struct _COF_SYMBOL {
    union {
        CHAR cName[8];                           // short name (<=8 bytes)
        struct { UINT32 Short; UINT32 Long; };   // Short==0 -> Long is strtab offset
    };
    UINT32 Value;
    INT16  SectionNumber;
    UINT16 Type;
    BYTE   StorageClass;
    BYTE   NumberOfAuxSymbols;
} COF_SYMBOL;

typedef struct _COF_RELOCATION {
    UINT32 VirtualAddress;       // offset within the section
    UINT32 SymbolTableIndex;
    UINT16 Type;                 // IMAGE_REL_AMD64_* or IMAGE_REL_I386_*
} COF_RELOCATION;
```

## Source Files

| Path | Description |
|------|-------------|
| `src_beacon/include/Bof.h` | COFF structures, Beacon API declarations, constants |
| `src_beacon/src/Bof/Loader.c` | Unity build root: COFF loader + relocation engine |
| `src_beacon/src/Bof/Api.c` | Beacon API implementations |
| `src_beacon/src/Bof/Stomp.c` | Module stomping allocator and slot management |
| `src_beacon/src/Commands/Bof.c` | `CMD_BOF` command handler (sync/async dispatch) |
| `src_beacon/src/Commands/BofStomp.c` | `CMD_BOF_STOMP` runtime reconfiguration handler |
| `src_beacon/src/Commands/Jobs.c` | Async job manager (create, start, kill, drain, list) |
