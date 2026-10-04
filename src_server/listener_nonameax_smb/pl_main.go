package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

type PluginListener struct{}

type extenderListener struct {
	name       string
	pipename   string
	encryptKey []byte
}

var (
	Ts              adaptix.Teamserver
	ModuleDir       string
	ListenerDataDir string
)

func (p *PluginListener) Call(operator string, listenerName string, function string, args string) {
	_ = operator
	_ = listenerName
	_ = function
	_ = args
}

func InitPlugin(ts any, moduleDir string, listenerDir string) adaptix.PluginListener {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir
	Ts = ts.(adaptix.Teamserver)
	return &PluginListener{}
}

func (p *PluginListener) Create(name, config string, customData []byte) (adaptix.ExtenderListener, adaptix.ListenerData, []byte, error) {
	var cfg struct {
		Pipename   string `json:"pipename"`
		EncryptKey string `json:"encrypt_key"`
	}
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, adaptix.ListenerData{}, nil, fmt.Errorf("smb listener: parse config: %w", err)
	}
	if cfg.Pipename == "" {
		cfg.Pipename = "naxsmb"
	}
	if cfg.EncryptKey == "" {
		return nil, adaptix.ListenerData{}, nil, fmt.Errorf("smb listener: encrypt_key required")
	}
	keyBytes, err := hex.DecodeString(cfg.EncryptKey)
	if err != nil || len(keyBytes) != 16 {
		return nil, adaptix.ListenerData{}, nil, fmt.Errorf("smb listener: encrypt_key must be 32 hex chars (16 bytes)")
	}

	listenerData := adaptix.ListenerData{
		Name:      name,
		BindHost:  "",
		BindPort:  "",
		AgentAddr: `\\.\pipe\` + cfg.Pipename,
		Protocol:  "bind_smb",
		Type:      "internal",
		Status:    "running",
	}

	ext := &extenderListener{
		name:       name,
		pipename:   cfg.Pipename,
		encryptKey: keyBytes,
	}
	return ext, listenerData, []byte(config), nil
}

func (a *extenderListener) Start() error {
	return nil
}

func (a *extenderListener) Stop() error {
	return nil
}

func (a *extenderListener) Edit(config string) (adaptix.ListenerData, []byte, error) {
	listenerData := adaptix.ListenerData{
		Name:      a.name,
		BindHost:  "",
		BindPort:  "",
		AgentAddr: `\\.\pipe\` + a.pipename,
		Protocol:  "bind_smb",
		Type:      "internal",
		Status:    "running",
	}
	return listenerData, []byte(config), nil
}

func (a *extenderListener) GetProfile() ([]byte, error) {
	profile := map[string]any{
		"pipename":    a.pipename,
		"encrypt_key": hex.EncodeToString(a.encryptKey),
	}
	return json.Marshal(profile)
}

func (a *extenderListener) InternalHandler(data []byte) (int64, error) {
	if Ts == nil {
		return 0, fmt.Errorf("smb listener: teamserver not available")
	}
	if len(data) < 17 {
		return 0, fmt.Errorf("smb listener: data too short (%d)", len(data))
	}
	beaconID := string(data[:16])

	Ts.TsLogAdd(adaptix.LogStatusInfo, 1, "NoNameAx-SMB", "", "InternalHandler: listener=%s beaconID=%s dataLen=%d keyPrefix=%x", a.name, beaconID, len(data), a.encryptKey[:4])

	if id, ok := Ts.TsAgentIdByUID([]byte(beaconID)); ok {
		Ts.TsLogAdd(adaptix.LogStatusInfo, 1, "NoNameAx-SMB", "", "InternalHandler: agent already exists, returning %d", id)
		return id, nil
	}

	ciphertext := data[16:]
	Ts.TsLogAdd(adaptix.LogStatusInfo, 1, "NoNameAx-SMB", "", "InternalHandler: ciphertextLen=%d first16=%x", len(ciphertext), ciphertext[:min(16, len(ciphertext))])

	beatWithId := make([]byte, 16+16+len(ciphertext))
	copy(beatWithId[:16], beaconID)
	copy(beatWithId[16:32], a.encryptKey)
	copy(beatWithId[32:], ciphertext)

	agentData, err := Ts.TsAgentCreate("a04a4178", []byte(beaconID), beatWithId, a.name, "", false)
	if err != nil {
		return 0, fmt.Errorf("smb listener: TsAgentCreate: %w", err)
	}
	Ts.TsLogAdd(adaptix.LogStatusSuccess, 1, "NoNameAx-SMB", "", "InternalHandler: agent created id=%d", agentData.Id)
	return agentData.Id, nil
}

func main() {}
