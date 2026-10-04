# Beacon Architecture

The beacon is position-independent shellcode - a single `.text` section with no CRT, no imports table, and no static data. All state lives in a heap-allocated `NAX_INSTANCE` struct, and all Windows APIs are resolved at runtime via PEB walk using FNV1a-32 hashes.

## NAX_INSTANCE

Every beacon function accesses state through a pointer to `NAX_INSTANCE`, stored in `TEB->NtTib.ArbitraryUserPointer` and recovered via the `G_INSTANCE` macro. The struct contains:

| Field | Purpose |
|-------|---------|
| `SessionId[17]` | 16 hex chars + NUL, generated at boot |
| `Config` (NAX_CONFIG) | All runtime-configurable fields: sleep, jitter, AES key, C2 URL, profile, BOF stomp settings |
| `Heap` | Private heap for all beacon allocations |
| `hSession` / `hConnect` | Persistent WinHTTP handles, reused across heartbeats |
| `Ntdll`, `Kernel32`, `Bcrypt`, `Winhttp`, ... | DLL bundles - each holds only resolved function pointers from that DLL |
| `BofCtx` | Current BOF execution context (output buffer, media list) |
| `BofStompPool` | BOF module stomping slot pool (sync + async DLLs) |
| `JobHead` / `CurrentJob` | Linked list of async BOF jobs |
| `PivotHead` | SMB pivot linked list |
| `Ws2` (NAX_WS2) | Lazy-loaded winsock2 function pointers |
| `TunnelHead` | Tunnel channel linked list |

### DLL Bundles

Each DLL has a dedicated struct (e.g., `NAX_KERNEL32`, `NAX_NTDLL`) containing only the function pointers resolved from that DLL. The `D_API(FuncName)` macro expands to `__typeof__(FuncName)* FuncName`, giving type-safe function pointers.

Resolution happens once in `NaxBootstrap()`:
```c
Nax->Kernel32.Handle = NaxGetModule( H_KERNEL32 );
Nax->Kernel32.LoadLibraryW = NaxGetProc( Nax->Kernel32.Handle, H_LOADLIBRARYW );
// ... all other APIs
```

To add a new API: add `D_API(NewFunc)` at the END of the bundle struct in `Instance.h`, then `NAX_RESOLVE(Nax->BundleName, NewFunc)` in `Bootstrap.c`.

## Execution Flow

### 1. Bootstrap

`NaxBootstrap()` runs once after the loader transfers execution:

1. **PEB walk** - Resolve base addresses of NTDLL and KERNEL32 from `PEB->Ldr->InMemoryOrderModuleList`
2. **API resolution** - Walk export tables using FNV1a-32 hashes to find each function pointer
3. **Heap creation** - `HeapCreate(0, 0, 0)` for a private beacon heap
4. **Instance allocation** - `RtlAllocateHeap` for `NAX_INSTANCE`, store pointer in `TEB->ArbitraryUserPointer`
5. **Remaining DLLs** - Load WINHTTP, BCRYPT, ADVAPI32, IPHLPAPI, USER32, GDI32 via `LoadLibraryW` and resolve their APIs
6. **Config init** - `NaxConfigInit()` populates `NAX_CONFIG` from compile-time macros
7. **BOF stomp init** - `NaxBofStompInit()` loads sacrificial DLLs for BOF module stomping
8. **System info** - Hostname, username, domain, IP, PID/TID, OS version, process name, elevation, code pages

### 2. Register (retry loop)

The beacon builds a REGISTER frame containing all system info and POSTs it to the C2. The server responds with:
- A PROFILE frame (`0x82`) containing the runtime malleable C2 profile
- A NO_TASKS frame confirming registration

Registration retries indefinitely with the configured sleep interval until the server responds.

### 3. Heartbeat Loop

```
loop:
    Sleep(SleepMs +/- Jitter%)
    Build HEARTBEAT frame -> encrypt -> HTTP GET/POST
    Decrypt response -> walk TASK frames
    For each TASK:
        NaxDispatch() -> execute command handler
        Build RESULT frame -> encrypt -> HTTP POST
```

The heartbeat loop runs forever. Each cycle:
1. Sleeps for the configured interval (with jitter)
2. Checks in with the C2 (GET for heartbeat, POST if there are pending results)
3. Processes any queued tasks synchronously (or dispatches to the async job pool for BOFs with `-a`)
4. Sends results back immediately after each command completes

### Tunnel Processing

After command dispatch and pivot/job collection, the heartbeat loop calls `NaxProcessTunnels()` if any tunnels are active. This is a four-phase pipeline:

1. **Check** -- Poll connecting sockets (`select` writefds), accept reverse listeners (`select` readfds), transition states
2. **Flush** -- Send buffered write data on READY sockets
3. **Recv** -- Read from READY sockets (max 16 reads/socket, 4MB total cap, 2.5s time budget), pack WRITE_TCP entries
4. **Cleanup** -- Graceful shutdown with 1-second close timer

Tunnel results are batched into a single RESULT frame per heartbeat with `TaskId=0` and `Status=0x20` (STATUS_TUNNEL).

For SMB beacons, tunnel results are sent through the parent's pipe instead of HTTP POST. The `WaitForMultipleObjects` timeout is capped to 100ms when tunnels are active to ensure socket polling.

### WS2 Lazy Loading

`ws2_32.dll` is NOT linked or loaded at boot. `NaxEnsureWs2()` loads it on the first tunnel command using PEB walk (`NaxGetModule`) with `LoadLibraryW` fallback, then resolves all winsock APIs into the `NAX_WS2` struct. The PE import table shows no ws2_32 dependency.

### Persistent HTTP Handles

WinHTTP session and connection handles are reused across heartbeats for performance. If the sleep interval exceeds `NAX_HTTP_STALE_MS` (60 seconds), handles are closed and recreated on the next heartbeat to avoid stale connections.

## PIC Constraints

| Rule | Rationale |
|------|-----------|
| No static/global variables | Shellcode has no `.bss` segment |
| No CRT calls | No `memcpy`, `strlen` - use `MmCopy`, `MmZero`, manual loops |
| No string literals | Use char arrays or `_WRITE` macros: per-byte MOVs |
| All Win32 via NAX_INSTANCE | Never call APIs directly - always through resolved function pointers |
| New struct fields go LAST | Mid-struct insertion silently shifts all subsequent offsets |
| `make clean && make` after header changes | Stale objects with wrong offsets cause runtime corruption |
| Heap-allocate large buffers | Stack arrays > 1KB risk overflow in PIC context |

### String Handling

Since `.rdata` doesn't exist in PIC, string constants must be written as stack-allocated char arrays:

```c
// Wrong - goes to .rdata
const char* msg = "hello";

// Correct - stays in .text as immediate MOVs
CHAR msg[] = { 'h', 'e', 'l', 'l', 'o', '\0' };
```

For build-time configuration strings, the `_WRITE(p)` macro pattern generates per-byte MOV instructions:
```c
#define NAX_C2_URL_WRITE(p) do { (p)[0]='h'; (p)[1]='t'; (p)[2]='t'; ... } while(0)
```

### API Hash Resolution

`NaxHashStr` uppercases the input before hashing with FNV1a-32. When computing hashes manually (e.g., with `tools/hash.py`), always pass the uppercase form:

```bash
python3 src_beacon/tools/hash.py LOADLIBRARYW VIRTUALPROTECT
```
