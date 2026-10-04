package main

import (
	"fmt"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

type cmdBuilder func(adaptix.AgentData, map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error)

var cmdTable = map[string]cmdBuilder{
	"whoami":        cmdWhoami,
	"sleep":         cmdSleep,
	"terminate":     cmdTerminate,
	"chunksize":     cmdChunksize,
	"cd":            cmdCd,
	"pwd":           cmdPwd,
	"mkdir":         cmdMkdir,
	"rmdir":         cmdRmdir,
	"rm":            cmdRm,
	"cp":            cmdCp,
	"mv":            cmdMv,
	"cat":           cmdCat,
	"ls":            cmdLs,
	"bof":           cmdBof,
	"execute":       cmdExecute,
	"bof-stomp":     cmdBofStomp,
	"sleepmask-set": cmdSleepmaskSet,
	"sleepobf-config": cmdSleepobfConfig,
	"token":         cmdToken,
	"ps":            cmdPs,
	"lportfwd":      cmdLportfwd,
	"rportfwd":      cmdRportfwd,
	"socks":         cmdSocks,
	"link":          cmdLink,
	"unlink":        cmdUnlink,
	"screenshot":    cmdScreenshot,
	"download":      cmdDownload,
	"upload":        cmdUpload,
	"profile":       cmdProfile,
	"job":           cmdJob,
	"watchdog":      cmdWatchdog,
	"dll-notify":    cmdDllNotify,
}

func naxCreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	command, _ := args["command"].(string)
	handler, ok := cmdTable[command]
	if !ok {
		return adaptix.TaskData{}, adaptix.ConsoleMessageData{},
			fmt.Errorf("nonameax: unknown command %q", command)
	}
	return handler(agentData, args)
}
