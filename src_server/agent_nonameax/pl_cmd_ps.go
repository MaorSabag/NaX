package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

func cmdPs(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	switch subcommand {
	case "list":
		task := adaptix.TaskData{
			Type: taskTypeTask,
			Data: []byte{CMD_PS_LIST, 0x00, 0x00, 0x00, 0x00},
			Sync: true,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "ps list task queued"}
		return task, msg, nil

	case "kill":
		pidVal, pidErr := adaptix.GetFloatArg(args, "pid")
		if pidErr != nil || pidVal <= 0 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: ps kill: 'pid' argument required (positive integer)")
		}
		pid := uint32(pidVal)
		data := make([]byte, 9)
		data[0] = CMD_PS_KILL
		binary.LittleEndian.PutUint32(data[1:5], 4)
		binary.LittleEndian.PutUint32(data[5:9], pid)
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("ps kill %d task queued", pid)}
		return task, msg, nil

	case "run":
		cmdline, cmdErr := adaptix.GetStringArg(args, "args")
		if cmdErr != nil || cmdline == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: ps run: 'args' argument required (command line)")
		}
		var flags byte
		if adaptix.GetBoolArg(args, "-o") {
			flags |= 0x01
		}
		if adaptix.GetBoolArg(args, "-s") {
			flags |= 0x02
		}
		if adaptix.GetBoolArg(args, "-i") {
			flags |= 0x04
		}
		cmdlineBytes := []byte(cmdline)
		// beacon args: flags(1) + cmdline_len(4LE) + cmdline
		argsLen := 1 + 4 + len(cmdlineBytes)
		data := make([]byte, 5+argsLen)
		data[0] = CMD_PS_RUN
		binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
		data[5] = flags
		binary.LittleEndian.PutUint32(data[6:10], uint32(len(cmdlineBytes)))
		copy(data[10:], cmdlineBytes)
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		var parts []string
		parts = append(parts, fmt.Sprintf("ps run queued: %s", cmdline))
		if flags&0x01 != 0 {
			parts = append(parts, "output")
		}
		if flags&0x02 != 0 {
			parts = append(parts, "suspended")
		}
		if flags&0x04 != 0 {
			parts = append(parts, "impersonation")
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: strings.Join(parts, " | ")}
		return task, msg, nil

	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: ps: unknown subcommand %q", subcommand)
	}
}

func resultPsKill(data []byte) (string, string) {
	if len(data) >= 4 {
		killedPid := binary.LittleEndian.Uint32(data[0:4])
		return fmt.Sprintf("Process %d terminated", killedPid), ""
	}
	return string(data), ""
}

func resultPsRun(data []byte) (string, string) {
	if len(data) < 5 {
		return string(data), ""
	}
	spawnedPid := binary.LittleEndian.Uint32(data[0:4])
	runFlags := data[4]
	displayText := fmt.Sprintf("Process %d started", spawnedPid)
	if runFlags&0x02 != 0 {
		displayText += " (suspended)"
	}
	clearText := ""
	if runFlags&0x01 != 0 && len(data) > 5 {
		clearText = string(data[5:])
	}
	return displayText, clearText
}

/* ========= [ result decoders ] ========= */

func decodePsListResult(agentData adaptix.AgentData, taskId int64, data []byte) (string, string) {
	if len(data) < 5 {
		return "ps: empty result", ""
	}
	result := data[0]
	if result == 0 {
		code := binary.LittleEndian.Uint32(data[1:5])
		return fmt.Sprintf("ps: error code %d (%s)", code, win32ErrorName(code)), ""
	}

	processCount := int(binary.LittleEndian.Uint32(data[1:5]))
	if processCount == 0 {
		return "ps: no processes found", ""
	}

	type psEntry struct {
		Pid       uint
		Ppid      uint
		SessionId uint
		Arch      string
		Elevated  bool
		Context   string
		Name      string
	}

	cursor := 5
	var proclist []psEntry
	contextMaxSize := 10

	for i := 0; i < processCount; i++ {
		if cursor+8 > len(data) {
			break
		}
		pid := uint(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		ppid := uint(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		session := uint(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
		cursor += 2
		arch64 := data[cursor]
		cursor++
		elev := data[cursor]
		cursor++

		domain, newCursor := readLenPrefixedStringGo(data, cursor)
		cursor = newCursor
		username, newCursor2 := readLenPrefixedStringGo(data, cursor)
		cursor = newCursor2
		procName, newCursor3 := readLenPrefixedStringGo(data, cursor)
		cursor = newCursor3

		archStr := ""
		if arch64 == 1 {
			archStr = "x64"
		} else if arch64 == 0 {
			archStr = "x86"
		}

		ctx := ""
		if username != "" {
			ctx = username
			if domain != "" {
				ctx = domain + "\\" + username
			}
			if elev > 0 {
				ctx += " *"
			}
			if len(ctx) > contextMaxSize {
				contextMaxSize = len(ctx)
			}
		}

		proclist = append(proclist, psEntry{
			Pid: pid, Ppid: ppid, SessionId: session,
			Arch: archStr, Elevated: elev > 0, Context: ctx, Name: procName,
		})
	}

	type treeProc struct {
		Data     psEntry
		Children []*treeProc
	}

	procMap := make(map[uint]*treeProc)
	var roots []*treeProc

	for _, proc := range proclist {
		node := &treeProc{Data: proc}
		procMap[proc.Pid] = node
	}

	for _, node := range procMap {
		if node.Data.Ppid == 0 || node.Data.Pid == node.Data.Ppid {
			roots = append(roots, node)
		} else if parent, ok := procMap[node.Data.Ppid]; ok {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}

	sort.Slice(roots, func(i, j int) bool { return roots[i].Data.Pid < roots[j].Data.Pid })
	var sortChildren func(node *treeProc)
	sortChildren = func(node *treeProc) {
		sort.Slice(node.Children, func(i, j int) bool { return node.Children[i].Data.Pid < node.Children[j].Data.Pid })
		for _, child := range node.Children {
			sortChildren(child)
		}
	}
	for _, root := range roots {
		sortChildren(root)
	}

	format := fmt.Sprintf(" %%-5v   %%-5v   %%-7v   %%-5v   %%-%vv   %%v", contextMaxSize)
	outputText := fmt.Sprintf(format, "PID", "PPID", "Session", "Arch", "Context", "Process")
	outputText += fmt.Sprintf("\n"+format, "---", "----", "-------", "----", "-------", "-------")

	var lines []string
	var formatTree func(node *treeProc, prefix string, isLast bool)
	formatTree = func(node *treeProc, prefix string, isLast bool) {
		branch := "├─ "
		if isLast {
			branch = "└─ "
		}
		treePrefix := prefix + branch
		d := node.Data
		line := fmt.Sprintf(format, d.Pid, d.Ppid, d.SessionId, d.Arch, d.Context, treePrefix+d.Name)
		lines = append(lines, line)

		childPrefix := prefix
		if isLast {
			childPrefix += "    "
		} else {
			childPrefix += "│   "
		}
		for i, child := range node.Children {
			formatTree(child, childPrefix, i == len(node.Children)-1)
		}
	}

	for i, root := range roots {
		formatTree(root, "", i == len(roots)-1)
	}

	outputText += "\n" + strings.Join(lines, "\n")

	var guiProcList []adaptix.ListingProcessDataWin
	for _, p := range proclist {
		guiProcList = append(guiProcList, adaptix.ListingProcessDataWin{
			Pid: p.Pid, Ppid: p.Ppid, SessionId: p.SessionId,
			Arch: p.Arch, Context: p.Context, ProcessName: p.Name,
		})
	}
	if Ts != nil {
		task := adaptix.TaskData{AgentId: agentData.Id, TaskId: taskId}
		Ts.TsClientGuiProcessWindows(task, guiProcList)
	}

	return fmt.Sprintf("Process list (%d entries)", len(proclist)), outputText
}
