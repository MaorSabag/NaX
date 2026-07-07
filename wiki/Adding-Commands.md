# Adding Commands

This is an end-to-end walkthrough for adding a new command to the NoNameAx agent. A command touches every layer of the system: a wire protocol ID, a PIC beacon handler in C, a dispatcher entry, Go server-side packing and result parsing, and an AxScript UI registration. All nine steps are mandatory for a fully wired command.

The walkthrough uses a concrete example -- a `hostname` command that reads the machine's hostname and returns it as a UTF-8 string -- so you can see real code for every file.

---

## Architecture Overview

When an operator types a command in the Adaptix console, the data flows through these layers:

```
Operator UI (AxScript)
    |
    v
Go server: CreateCommand()     -- pack args into wire format
    |
    v
Wire protocol (TASK frame)     -- cmd_id(1) | args_len(4LE) | args
    |
    v
Beacon: NaxDispatch()          -- route to handler by cmd_id
    |
    v
Beacon: NaxCmdXxx()            -- execute, write output to buffer
    |
    v
Wire protocol (RESULT frame)   -- task_id(4LE) | status(1) | data_len(4LE) | data
    |
    v
Go server: ProcessTasksResult() -- parse output, format for operator
    |
    v
Operator console output
```

---

## Step 1: Wire.h -- Define the Command ID

**File:** `src_beacon/include/Wire.h`

Pick the next available ID. The current assignments are:

| Range | Usage |
|-------|-------|
| `0x10`-`0x19` | Core commands (whoami, sleep, exit, fs ops) |
| `0x20`-`0x27` | BOF, screenshot, download, ps, upload, rm |
| `0x28`-`0x29` | Job management |
| `0x30`-`0x31` | Profile, BOF stomp |
| `0x37`-`0x39` | Pivot operations |

Add your constant after the existing block:

```c
#define NAX_CMD_HOSTNAME     0x40u
```

**Important:** This value must match exactly on the Go side. There is no auto-sync -- you maintain both by hand.

### Go side: `src_server/agent_nonameax/pl_main.go`

Add the matching constant in the `const` block alongside the other `CMD_*` values:

```go
CMD_HOSTNAME byte = 0x40
```

The existing constants live in `pl_main.go` around line 33:

```go
// NaX wire command IDs - must match Wire.h NAX_CMD_* in the C beacon.
const (
    CMD_WHOAMI      byte = 0x10
    CMD_SLEEP       byte = 0x11
    // ...
    CMD_HOSTNAME    byte = 0x40   // <-- add here
)
```

---

## Step 2: Beacon Command Handler

**File:** `src_beacon/src/Commands/Hostname.c`

Create a new file. Every command handler follows one of two signatures:

```c
// With arguments:
FUNC INT NaxCmdXxx( PNAX_INSTANCE Nax, const PBYTE args, UINT32 args_len,
                    PBYTE out, UINT32* out_len );

// Without arguments:
FUNC INT NaxCmdXxx( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
```

**Contract:**
- `out` is a caller-provided buffer (at least 512 bytes, typically much larger).
- `*out_len` enters as the buffer capacity, exits as the actual bytes written.
- Return `NAX_OK` (0) on success, `NAX_ERR_*` on failure.

**PIC constraints apply to all beacon code:**
- No string literals. Use `CHAR` arrays on the stack.
- No CRT calls. All Win32 APIs go through `Nax->BundleName.FuncName(...)`.
- No global variables. All state lives in `NAX_INSTANCE`.
- Stack arrays must stay under ~1 KB. For larger buffers, use `Nax->Ntdll.RtlAllocateHeap(Nax->Heap, 0, size)`.

### Example: Hostname.c

```c
/* beacon/src/Commands/Hostname.c
 * CMD_HOSTNAME (0x40) - return machine hostname as UTF-8. */

#include "Macros.h"
#include "Instance.h"
#include "Wire.h"

FUNC INT NaxCmdHostname( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    WCHAR wbuf[256];
    DWORD wlen = 256;

    if ( ! Nax->Kernel32.GetComputerNameExW( ComputerNamePhysicalDnsHostname,
                                              wbuf, &wlen ) )
        return NAX_ERR_FAIL;

    INT n = Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, wbuf, -1,
                                               (PCHAR)out, (INT)*out_len,
                                               NULL, NULL );
    if ( n <= 0 ) return NAX_ERR_NOMEM;

    *out_len = (UINT32)( n - 1 );   /* exclude NUL terminator from byte count */
    return NAX_OK;
}
```

This command needs `GetComputerNameExW` (KERNEL32) and `WideCharToMultiByte` (KERNEL32), both of which are already resolved in `Bootstrap.c`. No new API resolution is needed.

For reference, the existing `Whoami.c` handler follows the same pattern:

```c
FUNC INT NaxCmdWhoami( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    WCHAR wbuf[256];
    DWORD wlen = 256;

    if ( ! Nax->Advapi32.GetUserNameW( wbuf, &wlen ) )
        return NAX_ERR_INVAL;

    INT n = Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, wbuf, -1,
                                               (PCHAR)out, (INT)*out_len,
                                               NULL, NULL );
    if ( n <= 0 ) return NAX_ERR_NOMEM;
    *out_len = (UINT32)( n - 1 );
    return NAX_OK;
}
```

---

## Step 3: Dispatch.c -- Wire the Command

**File:** `src_beacon/src/Commands/Dispatch.c`

Two edits:

### 3a. Add forward declaration in Nax.h

**File:** `src_beacon/include/Nax.h`

`Dispatch.c` includes `Nax.h`, which already contains all command handler prototypes. Add yours to the `/* ========= [ command handlers ] ========= */` section:

```c
/* ========= [ command handlers ] ========= */
// ... existing declarations ...
FUNC INT NaxCmdHostname( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
```

### 3b. Add switch case in NaxDispatch

Add a new `case` before the `default:` label. Follow the existing pattern:

```c
    /* ---- CMD_HOSTNAME (0x40) ---- */
    case NAX_CMD_HOSTNAME:
        *result_status = ( NaxCmdHostname( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        if ( *result_status != NAX_STATUS_OK ) *result_data_len = 0;
        return 1;
```

**Pattern notes:**
- For commands **with arguments**, pass `task->Args` and `(UINT32)task->ArgsLen`:
  ```c
  *result_status = ( NaxCmdFoo( Nax, task->Args, (UINT32)task->ArgsLen,
                                result_data, result_data_len ) == NAX_OK )
                       ? NAX_STATUS_OK : NAX_STATUS_ERR;
  ```
- For commands that need the `taskId` (e.g., async BOF, link): pass `task->TaskId` as an extra parameter.
- Return `1` if a RESULT frame should be sent back. Return `0` for fire-and-forget commands (exit, pivot_exec).

---

## Step 4: Makefile -- Add Source File

**File:** `src_beacon/Makefile`

Add `Hostname.c` to the `C_SRCS_CORE` list:

```makefile
C_SRCS_CORE := Main.c \
               Bootstrap.c Ldr.c Config.c Crypto.c Packer.c Cfg.c Helpers.c \
               Dispatch.c Whoami.c Sleep.c Core.c Bof.c \
               Screenshot.c Download.c Downloader.c Upload.c MemSave.c Ps.c \
               Loader.c Jobs.c BofStomp.c Sleepmask.c DllNotify.c Shell.c \
               Token.c \
               Hostname.c
```

The `VPATH` already includes `src/Commands`, so Make will find the file automatically:

```makefile
VPATH := src:src/Core:src/Transport:src/Commands:src/Bof
```

---

## Step 5: Go Server -- CreateCommand

**File:** `src_server/agent_nonameax/pl_commands.go`

In the `CreateCommand` switch, add your case. This function is called when the operator submits the command from the UI. It packs the arguments into the wire format the beacon expects.

### Wire format

Every command follows this layout:

```
cmd_id(1) | args_len(4LE) | args...
```

For a no-argument command like `hostname`:

```go
case "hostname":
    task := adaptix.TaskData{
        Type: taskTypeTask,
        Data: []byte{CMD_HOSTNAME, 0x00, 0x00, 0x00, 0x00}, // cmd_id + args_len=0
        Sync: true,
    }
    msg := adaptix.ConsoleMessageData{
        Status:  messageSeverityInfo,
        Message: "hostname task queued",
    }
    return task, msg, nil
```

### For commands with arguments

Pack arguments with little-endian encoding. Example for a command that takes a file path:

```go
case "example":
    path, _ := args["path"].(string)
    if path == "" {
        return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
            errors.New("nonameax: example: 'path' argument required")
    }
    pathBytes := []byte(path)
    data := make([]byte, 5+len(pathBytes))
    data[0] = CMD_EXAMPLE                                    // cmd_id
    binary.LittleEndian.PutUint32(data[1:5], uint32(len(pathBytes))) // args_len
    copy(data[5:], pathBytes)                                // args
    task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
    msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "example queued"}
    return task, msg, nil
```

---

## Step 6: Go Server -- ProcessTasksResult

**File:** `src_server/agent_nonameax/pl_results.go`

When the beacon sends back a RESULT frame, `ProcessData` decodes it and dispatches by command ID. The command ID is tracked via `pendingCmdIds` -- the server stores the first byte of `task.Data` (the `cmd_id`) when packing the task in `PackTasks`, then retrieves it when the result arrives.

Find the `if cmdIdRaw, ok := pendingCmdIds.LoadAndDelete(taskIdStr); ok {` block and add your case inside it:

```go
case status == STATUS_OK && cmdId == CMD_HOSTNAME:
    displayText = string(data)
```

That is the entire handler for a command whose output is a plain UTF-8 string.

### Structured output

For commands that return binary data, parse the wire format and build a human-readable string:

```go
case status == STATUS_OK && cmdId == CMD_EXAMPLE && len(data) >= 4:
    count := binary.LittleEndian.Uint32(data[0:4])
    displayText = fmt.Sprintf("Found %d items", count)
    // Build clearText with the detailed table for the expandable section
    clearText = formatExampleTable(data[4:])
```

- `displayText` appears as the one-line summary in the operator console.
- `clearText` appears in the expandable details section (used for tables, multi-line output).

### Updating agent metadata

If your command changes agent state visible in the UI (like `sleep` updates the Sleep column), call `Ts.TsAgentUpdateData(updated)` inside the result handler. See the `CMD_SLEEP` case for the pattern.

---

## Step 7: AxScript -- Register the Command

**File:** `src_server/agent_nonameax/ax_config.axs`

In the `RegisterCommands()` function, create and register your command.

### 7a. Create the command object

```javascript
// ---- hostname ----
let cmd_hostname = ax.create_command(
    "hostname",
    "Return the machine's hostname",
    "hostname",
    "Queuing hostname..."
);
```

Arguments to `ax.create_command`:
1. Command name (what the operator types)
2. Description (shown in help)
3. Example usage string
4. Message shown immediately when the command is queued

### 7b. Add arguments (if any)

```javascript
// String argument (required):
cmd_foo.addArgString("path", true, "Target file path");

// String argument (optional):
cmd_foo.addArgString("filter", false, "Optional filter");

// Integer argument:
cmd_foo.addArgInt("count", true, "Number of items");

// Boolean flag -- dash is part of the name, exactly 2 params:
cmd_foo.addArgBool("-v", "Verbose output");

// File upload (content becomes base64 in args):
cmd_foo.addArgFile("file", true, "COFF object file");
```

### 7c. Add to the commands group

Add your command variable to the array in `ax.create_commands_group`:

```javascript
let group = ax.create_commands_group("NoNameAx", [
    // cmd_whoami,
    cmd_sleep,
    cmd_cd, cmd_pwd, cmd_mkdir, cmd_rmdir, cmd_rm, cmd_cat, cmd_ls, cmd_ps,
    cmd_token,
    cmd_screenshot, cmd_download, cmd_upload, cmd_bof,
    cmd_execute,
    cmd_job,
    cmd_chunksize,
    cmd_profile,
    cmd_bof_stomp,
    cmd_sleepmask_set,
    cmd_sleepobf,
    cmd_dll_notify,
    cmd_link, cmd_unlink,
    cmd_lportfwd, cmd_rportfwd, cmd_socks,
    cmd_hostname,       // <-- add here
    cmd_terminate
]);
```

### AxScript gotchas

- **Agent name is case-sensitive.** The filter array must use `"NoNameAx"` (mixed case), matching `config.yaml` exactly.
- **`container.put()` only accepts widget objects**, not bare values. If you add build-UI fields, always pass the widget.
- **`addArgBool` takes exactly 2 parameters.** The dash is part of the name: `addArgBool("-flag", "description")`.
- **Define `addArgBool` BEFORE `addArgString`.** The Adaptix parser iterates arg definitions in order. If a positional `addArgString` is defined first, it greedily consumes the next token — even if that token is a flag like `-r`. Put all `addArgBool` calls before any `addArgString` so flags are matched first:

```javascript
// CORRECT — flags checked before positionals:
cmd_foo.addArgBool("-v", "Verbose output");
cmd_foo.addArgString("path", false, "Target path");

// WRONG — "-v" gets consumed as the path value:
cmd_foo.addArgString("path", false, "Target path");
cmd_foo.addArgBool("-v", "Verbose output");
```

### Sub-commands

For commands with sub-commands (like `ps list`, `ps kill`, `ps run`), create the children first, then attach them:

```javascript
let cmd_foo_bar = ax.create_command("bar", "Description", "foo bar", "Queuing...");
cmd_foo_bar.addArgString("target", true, "Target host");

let cmd_foo_baz = ax.create_command("baz", "Description", "foo baz", "Queuing...");

let cmd_foo = ax.create_command("foo", "Parent command description");
cmd_foo.addSubCommands([cmd_foo_bar, cmd_foo_baz]);
```

In `CreateCommand()`, the parent name arrives as `args["command"]` and the child as `args["subcommand"]`.

---

## Step 8: If You Need New Win32 APIs

If your command uses a Win32 function not already in `NAX_INSTANCE`, you need three changes.

### 8a. Instance.h -- Add to DLL bundle struct

Find the appropriate struct (`NAX_KERNEL32`, `NAX_NTDLL`, `NAX_ADVAPI32`, etc.) and add the declaration **at the END**:

```c
/* ========= [ kernel32.dll ] ========= */

typedef struct {
    HMODULE Handle;
    D_API( ExitProcess );
    D_API( Sleep );
    // ... existing entries ...
    D_API( GetCurrentProcess );
    UINT ( __stdcall *GetACP )( VOID );
    UINT ( __stdcall *GetOEMCP )( VOID );
    D_API( GetComputerNameA );              // <-- add at END
} NAX_KERNEL32;
```

**Critical rule:** Always add new entries at the END of the struct. Mid-struct insertion silently shifts all subsequent function pointer offsets. Every existing call through the struct will resolve to the wrong function, causing crashes or silent corruption. There is no compiler warning -- the struct is just a bag of `void*` to the linker.

### 8b. Bootstrap.c -- Resolve the function

In `NaxBootstrap()`, add the resolution call after the existing ones for that DLL:

```c
Nax->Kernel32.GetComputerNameA = (PVOID)NaxGetProc( hK32, H_GETCOMPUTERNAMEA );
```

### 8c. Macros.h -- Add the hash

If the hash constant does not already exist, compute it. `NaxHashStr` uppercases the input before hashing:

```bash
python3 -c "
import struct
h = 0x811c9dc5
for c in 'GETCOMPUTERNAMEA':
    h ^= ord(c)
    h = (h * 0x01000193) & 0xFFFFFFFF
print(f'#define H_GETCOMPUTERNAMEA  0x{h:08X}u')
"
```

Add the result to `Macros.h`:

```c
#define H_GETCOMPUTERNAMEA  0xD1AFE3BCu
```

### 8d. Full rebuild required

After any header change:

```bash
make clean && make debug
```

The incremental `make link` / `make debug-link` targets only recompile `Config.c` and re-link. They detect header changes and fall back to a full rebuild automatically, but `make clean && make` is the safest path.

---

## Step 9: Build and Test

### Debug build (PIC shellcode with debug prints)

```bash
make clean && make debug
```

This produces `build/http/beacon.x64.debug.bin` -- load it with the loader exactly like the release blob, but `NaxDbgx` / `NaxDbg` output appears in DebugView / x64dbg.

### Quick rebuild (no header changes)

```bash
make debug-link
```

Only recompiles `Config.c` and re-links. Safe when you only changed `.c` files in `src/Commands/` (no header modifications). The Makefile detects stale struct headers and falls back to a full rebuild if needed.

### Go plugin

```bash
cd src_server/agent_nonameax && make
```

Copy the resulting `.so` to `Server/extenders/agent_nonameax/`.

### Verify

1. Deploy the new beacon and Go plugin.
2. Start a listener and get a callback.
3. Type `hostname` in the operator console.
4. Confirm the result appears with a green success status.

---

## Full Example: `hostname` Command

Here is every file change collected in one place.

### Wire.h

```c
#define NAX_CMD_HOSTNAME     0x40u
```

### pl_main.go (constant)

```go
CMD_HOSTNAME byte = 0x40
```

### Hostname.c

```c
/* beacon/src/Commands/Hostname.c
 * CMD_HOSTNAME (0x40) - return machine hostname as UTF-8. */

#include "Macros.h"
#include "Instance.h"
#include "Wire.h"

FUNC INT NaxCmdHostname( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len ) {
    WCHAR wbuf[256];
    DWORD wlen = 256;

    if ( ! Nax->Kernel32.GetComputerNameExW( ComputerNamePhysicalDnsHostname,
                                              wbuf, &wlen ) )
        return NAX_ERR_FAIL;

    INT n = Nax->Kernel32.WideCharToMultiByte( CP_UTF8, 0, wbuf, -1,
                                               (PCHAR)out, (INT)*out_len,
                                               NULL, NULL );
    if ( n <= 0 ) return NAX_ERR_NOMEM;

    *out_len = (UINT32)( n - 1 );
    return NAX_OK;
}
```

### Nax.h (forward declaration)

```c
/* ========= [ command handlers ] ========= */
// ... existing declarations ...
FUNC INT NaxCmdHostname( PNAX_INSTANCE Nax, PBYTE out, UINT32* out_len );
```

### Dispatch.c (switch case)

```c
    /* ---- CMD_HOSTNAME (0x40) ---- */
    case NAX_CMD_HOSTNAME:
        *result_status = ( NaxCmdHostname( Nax, result_data, result_data_len ) == NAX_OK )
                             ? NAX_STATUS_OK : NAX_STATUS_ERR;
        if ( *result_status != NAX_STATUS_OK ) *result_data_len = 0;
        return 1;
```

### Makefile

```makefile
C_SRCS_CORE := Main.c \
               Bootstrap.c Ldr.c Config.c Crypto.c Packer.c Cfg.c Helpers.c \
               Dispatch.c Whoami.c Sleep.c Core.c Bof.c \
               Screenshot.c Download.c Downloader.c Upload.c MemSave.c Ps.c \
               Loader.c Jobs.c BofStomp.c Sleepmask.c DllNotify.c Shell.c \
               Token.c \
               Hostname.c
```

### pl_commands.go

```go
case "hostname":
    task := adaptix.TaskData{
        Type: taskTypeTask,
        Data: []byte{CMD_HOSTNAME, 0x00, 0x00, 0x00, 0x00},
        Sync: true,
    }
    msg := adaptix.ConsoleMessageData{
        Status:  messageSeverityInfo,
        Message: "hostname task queued",
    }
    return task, msg, nil
```

### pl_results.go

Inside the `if cmdIdRaw, ok := pendingCmdIds.LoadAndDelete(taskIdStr); ok {` block:

```go
case status == STATUS_OK && cmdId == CMD_HOSTNAME:
    displayText = string(data)
```

### ax_config.axs

```javascript
// ---- hostname ----
let cmd_hostname = ax.create_command(
    "hostname",
    "Return the machine's hostname",
    "hostname",
    "Queuing hostname..."
);
```

And in the commands group array:

```javascript
let group = ax.create_commands_group("NoNameAx", [
    // cmd_whoami,
    cmd_sleep,
    cmd_cd, cmd_pwd, cmd_mkdir, cmd_rmdir, cmd_rm, cmd_cat, cmd_ls, cmd_ps,
    cmd_token,
    cmd_screenshot, cmd_download, cmd_upload, cmd_bof,
    cmd_execute,
    cmd_job,
    cmd_chunksize,
    cmd_profile,
    cmd_bof_stomp,
    cmd_sleepmask_set,
    cmd_sleepobf,
    cmd_dll_notify,
    cmd_link, cmd_unlink,
    cmd_lportfwd, cmd_rportfwd, cmd_socks,
    cmd_hostname,
    cmd_terminate
]);
```

---

## Checklist

Use this as a pre-commit checklist whenever you add a command:

| # | Layer | File | What to do |
|---|-------|------|------------|
| 1 | Wire ID (C) | `src_beacon/include/Wire.h` | `#define NAX_CMD_YOURNAME 0xNN` |
| 2 | Wire ID (Go) | `src_server/agent_nonameax/pl_main.go` | `CMD_YOURNAME byte = 0xNN` |
| 3 | Handler | `src_beacon/src/Commands/YourName.c` | Implement the beacon-side logic |
| 4 | Dispatch (decl) | `src_beacon/include/Nax.h` | Forward declaration in command handlers section |
| 5 | Dispatch (case) | `src_beacon/src/Commands/Dispatch.c` | `case NAX_CMD_YOURNAME:` in switch |
| 6 | Build | `src_beacon/Makefile` | Add `YourName.c` to `C_SRCS_CORE` |
| 7 | Pack args | `src_server/agent_nonameax/pl_commands.go` | `case "yourname":` in `CreateCommand()` |
| 8 | Parse result | `src_server/agent_nonameax/pl_results.go` | `case cmdId == CMD_YOURNAME:` in `ProcessData()` |
| 9 | UI | `src_server/agent_nonameax/ax_config.axs` | `ax.create_command(...)` + add to group array |
| 10 | APIs (if needed) | `src_beacon/include/Instance.h` | `D_API(Func)` at END of struct |
| 11 | APIs (if needed) | `src_beacon/src/Core/Bootstrap.c` | `NaxGetProc(hDll, H_FUNC)` |
| 12 | APIs (if needed) | `src_beacon/include/Macros.h` | FNV1a hash constant |
| 13 | Build | `src_beacon/` | `make clean && make debug` |
| 14 | Build | `src_server/agent_nonameax/` | `make` |

---

## Common Pitfalls

**Mid-struct insertion in Instance.h.** Adding a `D_API()` entry anywhere except the END of a DLL bundle struct silently shifts all subsequent function pointer offsets. Every call through those pointers will invoke the wrong function. This produces crashes that look completely unrelated to your change.

**String literals in PIC code.** The beacon is position-independent shellcode extracted from `.text`. String literals go into `.rdata`, which is stripped. Use stack-allocated `CHAR` arrays:

```c
/* WRONG - lands in .rdata, crashes at runtime */
char* msg = "hello";

/* CORRECT - stack array, stays in .text */
CHAR msg[] = { 'h', 'e', 'l', 'l', 'o', '\0' };
```

**Mismatched command IDs.** If `Wire.h` says `0x40` but `pl_main.go` says `0x41`, the beacon will return results tagged with the wrong ID. The Go server will not find the `pendingCmdIds` entry, and the result will show as a generic "command failed" with no type-specific formatting.

**Forgetting `pendingCmdIds`.** The server stores the command ID byte when packing tasks (in `PackTasks`). If your `CreateCommand` case sets `Data[0]` to the wrong value, result parsing will route to the wrong handler.

**Stack overflow in beacon.** The beacon runs in a thread with limited stack. Keep stack-allocated buffers under 1 KB. For larger allocations, use:

```c
PBYTE buf = (PBYTE)Nax->Ntdll.RtlAllocateHeap( Nax->Heap, 0, size );
// ... use buf ...
Nax->Ntdll.RtlFreeHeap( Nax->Heap, 0, buf );
```

**GetUserNameW is ADVAPI32, not KERNEL32.** Double-check which DLL exports the function you need. The bundle struct name must match: `Nax->Advapi32.GetUserNameW`, not `Nax->Kernel32.GetUserNameW`.

**FNV1a hashes use uppercase input.** `NaxHashStr` uppercases the input before hashing. When computing hashes with the Python script, pass the function name in uppercase: `GETCOMPUTERNAMEA`, not `GetComputerNameA`.
