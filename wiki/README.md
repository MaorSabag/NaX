# NoNameAx Wiki

Documentation for the NaX C2 agent — beacon internals, wire protocol, evasion techniques, operator reference, and development guides.

## Architecture

Core design and protocol documentation.

| Page | Description |
|------|-------------|
| [Beacon Architecture](Beacon-Architecture.md) | `NAX_INSTANCE` struct, bootstrap sequence, heartbeat loop, PIC constraints, API resolution |
| [Wire Protocol](Wire-Protocol.md) | Frame format, message types (`REGISTER`, `HEARTBEAT`, `RESULT`), command IDs, AES-128-CBC encryption |
| [Malleable C2 Profiles](Malleable-C2-Profiles.md) | OutputConfig encoding pipeline, profile JSON schema, GET/POST transaction config, runtime switching via `profile` command |
| [Module Stomping](Module-Stomping.md) | Loader-phase beacon stomping, DLL selection criteria, LDR entry patching (PEB flags), `.pdata`/`.xdata` injection for clean stack walks |

## BOF System

In-process COFF execution with evasion.

| Page | Description |
|------|-------------|
| [BOF Execution](BOF-Execution.md) | COFF loader internals, sync vs async dispatch, thread pool, media callbacks, Beacon API reference |
| [BOF Module Stomping](BOF-Module-Stomping.md) | Image-backed BOF `.text` sections, near-allocator, IFT `.pdata` injection, slot backup/restore |

## Evasion

Sleep obfuscation and API proxying.

| Page | Description |
|------|-------------|
| [BeaconGate & Sleepmask](BeaconGate-Sleepmask.md) | BeaconGate API call proxy, sleep obfuscation (WFSO PoC), tail-call wait pattern |

## Post-Exploitation

Target interaction and privilege management.

| Page | Description |
|------|-------------|
| [Token Commands](Token-Commands.md) | Token theft (`steal`), impersonation (`use`), credential logon (`make` with 4 logon types), privilege enumeration (`privs`), console header updates |

## Networking

Transport and tunneling.

| Page | Description |
|------|-------------|
| [Tunneling](Tunneling.md) | Local/reverse port forwarding, SOCKS proxy, wire sub-protocol, flow control, OPSEC considerations, SMB transport support |

## Development

Guides for extending and building NaX.

| Page | Description |
|------|-------------|
| [Adding Commands](Adding-Commands.md) | End-to-end walkthrough: define command ID in `Wire.h`, implement C handler, add Go command builder + result decoder, wire up AxScript UI |
| [Stardust Loader Guide](Stardust-Loader-Guide.md) | UDRL architecture deep dive — reflective loading, module stomping mechanics, TLS egghunter, thread pool execution, how to write a loader from scratch |

## Operations

Build, deploy, and operate.

| Page | Description |
|------|-------------|
| [Build and Deploy](Build-and-Deploy.md) | Prerequisites, Makefile targets, debug vs release, module stomping flags, Go plugin compilation, Adaptix server setup |
| [Operator Reference](Operator-Reference.md) | Complete command reference — file ops, process management, tokens, BOF, pivoting, tunneling, runtime config (`sleep`, `profile`, `bof-stomp`, `sleepmask-set`, `sleepobf-config`, `chunksize`, `dll-notify`) |
