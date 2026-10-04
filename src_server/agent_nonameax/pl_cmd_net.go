package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

func cmdLportfwd(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	lport := int(adaptix.GetFloatArgDefault(args, "lport", 0))
	if lport < 1 || lport > 65535 {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: lportfwd: port must be 1-65535")
	}

	taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
	var msg adaptix.ConsoleMessageData

	switch subcommand {
	case "start":
		lhost := adaptix.GetStringArgDefault(args, "lhost", "")
		fwdhost := adaptix.GetStringArgDefault(args, "fwdhost", "")
		fwdport := int(adaptix.GetFloatArgDefault(args, "fwdport", 0))
		if lhost == "" || fwdhost == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: lportfwd start: lhost and fwdhost required")
		}
		if fwdport < 1 || fwdport > 65535 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: lportfwd start: fwdport must be 1-65535")
		}
		tunnelId, err := Ts.TsTunnelCreateLportfwd(agentData.Id, "", lhost, lport, fwdhost, fwdport)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		msg = adaptix.ConsoleMessageData{Status: messageSeveritySuccess, Message: fmt.Sprintf("lportfwd %s:%d -> %s:%d started", lhost, lport, fwdhost, fwdport)}
	case "stop":
		Ts.TsTunnelStopLportfwd(agentData.Id, lport)
		taskData.MessageType = messageSeveritySuccess
		taskData.Message = fmt.Sprintf("lportfwd on port %d stopped", lport)
		msg = adaptix.ConsoleMessageData{Status: messageSeveritySuccess, Message: fmt.Sprintf("lportfwd on port %d stopped", lport)}
	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: lportfwd: subcommand must be 'start' or 'stop'")
	}
	return taskData, msg, nil
}

func cmdRportfwd(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	lport := int(adaptix.GetFloatArgDefault(args, "lport", 0))
	if lport < 1 || lport > 65535 {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: rportfwd: port must be 1-65535")
	}

	taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
	var msg adaptix.ConsoleMessageData

	switch subcommand {
	case "start":
		fwdhost := adaptix.GetStringArgDefault(args, "fwdhost", "")
		fwdport := int(adaptix.GetFloatArgDefault(args, "fwdport", 0))
		if fwdhost == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: rportfwd start: fwdhost required")
		}
		if fwdport < 1 || fwdport > 65535 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: rportfwd start: fwdport must be 1-65535")
		}
		tunnelId, err := Ts.TsTunnelCreateRportfwd(agentData.Id, "", lport, fwdhost, fwdport)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		msg = adaptix.ConsoleMessageData{Status: messageSeveritySuccess, Message: fmt.Sprintf("rportfwd 127.0.0.1:%d -> %s:%d started", lport, fwdhost, fwdport)}
	case "stop":
		Ts.TsTunnelStopRportfwd(agentData.Id, lport)
		taskData.MessageType = messageSeveritySuccess
		taskData.Message = "rportfwd stopped"
		msg = adaptix.ConsoleMessageData{Status: messageSeveritySuccess, Message: fmt.Sprintf("rportfwd on port %d stopped", lport)}
	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: rportfwd: subcommand must be 'start' or 'stop'")
	}
	return taskData, msg, nil
}

func cmdSocks(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
	var msg adaptix.ConsoleMessageData

	switch subcommand {
	case "start":
		address := adaptix.GetStringArgDefault(args, "address", "0.0.0.0")
		port := int(adaptix.GetFloatArgDefault(args, "port", 0))
		if port < 1 || port > 65535 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: socks start: port must be 1-65535")
		}

		socks4 := adaptix.GetBoolArg(args, "-socks4")
		var tunnelId int64
		var err error
		if socks4 {
			tunnelId, err = Ts.TsTunnelCreateSocks4(agentData.Id, "", address, port)
			if err != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
			}
			taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
			if err != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
			}
			msg = adaptix.ConsoleMessageData{Status: messageSeveritySuccess, Message: fmt.Sprintf("SOCKS4 proxy started on %s:%d", address, port)}
		} else {
			auth := adaptix.GetBoolArg(args, "-auth")
			username := adaptix.GetStringArgDefault(args, "username", "")
			password := adaptix.GetStringArgDefault(args, "password", "")
			tunnelId, err = Ts.TsTunnelCreateSocks5(agentData.Id, "", address, port, auth, username, password)
			if err != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
			}
			taskData.TaskId, err = Ts.TsTunnelStart(tunnelId)
			if err != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
			}
			if auth {
				msg = adaptix.ConsoleMessageData{Status: messageSeveritySuccess, Message: fmt.Sprintf("SOCKS5 proxy (auth) started on %s:%d", address, port)}
			} else {
				msg = adaptix.ConsoleMessageData{Status: messageSeveritySuccess, Message: fmt.Sprintf("SOCKS5 proxy started on %s:%d", address, port)}
			}
		}

	case "stop":
		port := int(adaptix.GetFloatArgDefault(args, "port", 0))
		if port < 1 || port > 65535 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: socks stop: port must be 1-65535")
		}
		Ts.TsTunnelStopSocks(agentData.Id, port)
		taskData.MessageType = messageSeveritySuccess
		taskData.Message = fmt.Sprintf("SOCKS proxy on port %d stopped", port)
		msg = adaptix.ConsoleMessageData{Status: messageSeveritySuccess, Message: fmt.Sprintf("SOCKS proxy on port %d stopped", port)}

	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: socks: subcommand must be 'start' or 'stop'")
	}
	return taskData, msg, nil
}

func cmdLink(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	if subcommand != "smb" {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: link: subcommand must be 'smb'")
	}
	target := adaptix.GetStringArgDefault(args, "target", "")
	pipename := adaptix.GetStringArgDefault(args, "pipename", "")
	if target == "" || pipename == "" {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: link smb: 'target' and 'pipename' required")
	}
	pipe := fmt.Sprintf("\\\\%s\\pipe\\%s", target, pipename)
	pipeBytes := []byte(pipe)
	// cmd_id(1)=CMD_LINK | args_len(4LE) | link_type(1) | pipename_len(4LE) | pipename
	argsLen := 1 + 4 + len(pipeBytes)
	data := make([]byte, 5+argsLen)
	data[0] = CMD_LINK
	binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
	data[5] = 1 // link_type=SMB
	binary.LittleEndian.PutUint32(data[6:10], uint32(len(pipeBytes)))
	copy(data[10:], pipeBytes)
	task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("link smb %s queued", pipe)}
	return task, msg, nil
}

func cmdUnlink(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	pivotIdStr, err := adaptix.GetStringArg(args, "pivot_id")
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: unlink: 'pivot_id' required")
	}
	pivotIdVal, err := strconv.ParseUint(pivotIdStr, 16, 32)
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: unlink: invalid pivot_id %q: %w", pivotIdStr, err)
	}
	// cmd_id(1)=CMD_UNLINK | args_len(4LE)=4 | pivot_id(4LE)
	data := make([]byte, 9)
	data[0] = CMD_UNLINK
	binary.LittleEndian.PutUint32(data[1:5], 4)
	binary.LittleEndian.PutUint32(data[5:9], uint32(pivotIdVal))
	task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("unlink %s queued", pivotIdStr)}
	return task, msg, nil
}

func resultLink(agentData adaptix.AgentData, taskId uint32, data []byte) string {
	if len(data) < 5 {
		return string(data)
	}
	linkType := data[0]
	watermark := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))
	beat := data[5:]
	naxLogInfo("CMD_LINK: parent=%d linkType=%d wm=%s beatLen=%d", agentData.Id, linkType, watermark, len(beat))
	if len(beat) >= 16 {
		naxLogInfo("CMD_LINK: beat sessionId=%s cipherLen=%d", string(beat[:16]), len(beat)-16)
	}
	if Ts != nil {
		childAgentId, linkErr := Ts.TsListenerInteralHandler(watermark, beat)
		if linkErr != nil {
			naxLogErr("CMD_LINK: TsListenerInteralHandler wm=%s: %v", watermark, linkErr)
		}
		if childAgentId != 0 {
			pivotIdStr := fmt.Sprintf("%08x", taskId)
			_ = Ts.TsPivotCreate(pivotIdStr, agentData.Id, childAgentId, "", false)
			savePivotToStore(pivotIdStr, agentData.Id, childAgentId)
			emptyMark := ""
			_ = Ts.TsAgentUpdateDataPartial(childAgentId, struct {
				Mark *string `json:"mark"`
			}{Mark: &emptyMark})
			if linkType == 1 {
				return fmt.Sprintf("----- New SMB pivot agent: [%d]===[%d] (pivot: %s) -----", agentData.Id, childAgentId, pivotIdStr)
			}
		} else {
			return "link failed: listener returned empty agent ID"
		}
	}
	return string(data)
}

func resultUnlink(agentData adaptix.AgentData, data []byte) string {
	if len(data) < 5 {
		return string(data)
	}
	pivotId := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[0:4]))
	pivotType := data[4]
	if Ts != nil {
		_, parentAgentId, childAgentId := Ts.TsGetPivotInfoById(pivotId)
		if pivotType != 0 {
			_ = Ts.TsPivotDelete(pivotId)
			deletePivotFromStore(pivotId)
			msgParent := fmt.Sprintf("SMB agent disconnected %d", childAgentId)
			msgChild := fmt.Sprintf(" ----- SMB agent disconnected from [%d] ----- ", parentAgentId)
			Ts.TsAgentConsoleOutput(childAgentId, "", messageSeveritySuccess, msgChild, "\n", true)
			return msgParent
		}
		return fmt.Sprintf("unlink %s: pivot not found", pivotId)
	}
	return string(data)
}
