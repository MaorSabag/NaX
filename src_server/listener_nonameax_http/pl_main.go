package main

import (
	"fmt"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2"
)

// Teamserver is the subset of Adaptix host callbacks the listener uses.
// Method signatures mirror those declared in
//
//	out_source_projects/Kharon/listener_kharon_http/src_server/pl_main.go:11-15
//
// Add to it as Phase 3+ tasks need more callbacks.
type Teamserver interface {
	// TsAgentIsExists returns true when the server has a registered agent
	// with the given Id (the server-assigned AgentData.Id, *not* a beaconID).
	// Used by the listener to invalidate stale beaconID → adaptixID entries
	// after an operator deletes a session from the GUI.
	TsAgentIsExists(agentId string) bool

	// TsAgentCreate registers a new agent. The returned AgentData.Id is the
	// server-assigned ID that must be used for all subsequent agent calls.
	TsAgentCreate(agentCrc, agentId string, beat []byte,
		listenerName, ExternalIP string, Async bool) (adaptix.AgentData, error)

	// TsAgentProcessData hands a decrypted beacon body up to the server.
	// agentId must be the server-assigned AgentData.Id (not the beaconID).
	TsAgentProcessData(agentId string, bodyData []byte) error

	// TsAgentGetHostedAll retrieves pre-packed task bytes for the agent
	// (the output of ExtenderAgent.PackTasks).  Returns (nil, nil) when no
	// tasks are queued.  maxSize=0 means no cap on the returned data.
	// agentId must be the server-assigned AgentData.Id (not the beaconID).
	TsAgentGetHostedAll(agentId string, maxSize int) ([]byte, error)

	// TsAgentSetTick stamps LastTick = now and sets agent.Tick = true.
	// A background goroutine (TsAgentTickUpdate, ~800 ms) collects all agents
	// with Tick = true and sends a SpAgentTick packet to connected clients,
	// which drives the "Last" column countdown in the operator UI.
	// Must be called on every successful beacon round-trip.
	TsAgentSetTick(agentId string, listenerName string) error

	TsExtenderDataLoad(extenderName, key string) ([]byte, error)
	TsExtenderDataKeys(extenderName string) ([]string, error)
}

type PluginListener struct{}

// extenderListener implements adaptix.ExtenderListener and delegates lifecycle
// calls to httpServer (defined in pl_http.go, Task 1.11).
type extenderListener struct {
	name string
	srv  *httpServer
}

var (
	Ts              Teamserver
	ModuleDir       string
	ListenerDataDir string
)

// InitPlugin is the symbol Adaptix Server looks up after loading the .so.
// Signature mirrors the Kharon reference listener plugin (three params).
func InitPlugin(ts any, moduleDir string, listenerDir string) adaptix.PluginListener {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir
	if ts != nil {
		Ts, _ = ts.(Teamserver)
	}
	return &PluginListener{}
}

// Create builds a ListenerData + ExtenderListener from the operator-supplied
// JSON config. Signature matches axc2 v1.2.0 PluginListener interface.
func (p *PluginListener) Create(name, config string, customData []byte) (adaptix.ExtenderListener, adaptix.ListenerData, []byte, error) {
	srv, err := newHTTPServer(name, config, Ts)
	if err != nil {
		return nil, adaptix.ListenerData{}, nil, err
	}
	agentAddr := ""
	if len(srv.profile.Hosts) > 0 {
		agentAddr = strings.Join(srv.profile.Hosts, ", ")
	}
	proto := "http"
	if srv.ssl {
		proto = "https"
	}
	listenerData := adaptix.ListenerData{
		Name:      name,
		BindHost:  srv.bindHost(),
		BindPort:  fmt.Sprintf("%d", srv.bindPort()),
		AgentAddr: agentAddr,
		Protocol:  proto,
		Type:      "external",
		Status:    "stopped",
	}
	return &extenderListener{name: name, srv: srv}, listenerData, []byte(config), nil
}

// --- adaptix.ExtenderListener implementation ---

func (a *extenderListener) Start() error {
	return a.srv.start()
}

func (a *extenderListener) Stop() error {
	return a.srv.stop()
}

func (a *extenderListener) Edit(config string) (adaptix.ListenerData, []byte, error) {
	return a.srv.edit(config)
}

func (a *extenderListener) GetProfile() ([]byte, error) {
	return a.srv.profileJSON()
}

// InternalHandler processes a child agent's first beat arriving via a pivot
// (SMB named pipe). The parent extracted the watermark and the server used it
// to route here. data = sessionId(16) + encrypted_frame.
func (a *extenderListener) InternalHandler(data []byte) (string, error) {
	naxListenerLogInfo("InternalHandler: data len=%d", len(data))
	if len(data) < 17 {
		return "", fmt.Errorf("InternalHandler: data too short (%d)", len(data))
	}
	beaconID := string(data[:16])
	ciphertext := data[16:]
	naxListenerLogInfo("InternalHandler: beaconID=%s ciphertextLen=%d keyPrefix=%x", beaconID, len(ciphertext), a.srv.encryptKey[:4])

	beatWithId := make([]byte, 16+16+len(ciphertext))
	copy(beatWithId[:16], beaconID)
	copy(beatWithId[16:32], a.srv.encryptKey)
	copy(beatWithId[32:], ciphertext)

	agentData, err := a.srv.ts.TsAgentCreate(agentWatermark, beaconID, beatWithId, a.name, "0.0.0.0", false)
	if err != nil {
		naxListenerLogErr("InternalHandler: TsAgentCreate failed: %v", err)
		return "", fmt.Errorf("InternalHandler: TsAgentCreate: %w", err)
	}
	naxListenerLogInfo("InternalHandler: child agent created id=%s", agentData.Id)
	a.srv.agentIDMap.Store(beaconID, agentData.Id)
	return agentData.Id, nil
}

func main() {}
