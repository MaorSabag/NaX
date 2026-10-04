package main

import (
	"fmt"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

type PluginListener struct{}

// extenderListener implements adaptix.ExtenderListener and delegates lifecycle
// calls to httpServer (defined in pl_http.go, Task 1.11).
type extenderListener struct {
	name string
	srv  *httpServer
}

var (
	Ts              adaptix.Teamserver
	ModuleDir       string
	ListenerDataDir string
)

// InitPlugin is the symbol Adaptix Server looks up after loading the .so.
// Signature mirrors the Kharon reference listener plugin (three params).
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
func (a *extenderListener) InternalHandler(data []byte) (int64, error) {
	naxListenerLogInfo("InternalHandler: data len=%d", len(data))
	if len(data) < 17 {
		return 0, fmt.Errorf("InternalHandler: data too short (%d)", len(data))
	}
	beaconID := string(data[:16])
	naxListenerLogInfo("InternalHandler: beaconID=%s dataLen=%d keyPrefix=%x", beaconID, len(data), a.srv.encryptKey[:4])

	if a.srv.ts != nil {
		if id, found := a.srv.ts.TsAgentIdByUID([]byte(beaconID)); found {
			naxListenerLogInfo("InternalHandler: agent already exists, returning %d", id)
			a.srv.agentIDMap.Store(beaconID, id)
			return id, nil
		}
	}

	ciphertext := data[16:]
	beatWithId := make([]byte, 16+16+len(ciphertext))
	copy(beatWithId[:16], beaconID)
	copy(beatWithId[16:32], a.srv.encryptKey)
	copy(beatWithId[32:], ciphertext)

	agentData, err := a.srv.ts.TsAgentCreate(agentWatermark, []byte(beaconID), beatWithId, a.name, "0.0.0.0", false)
	if err != nil {
		naxListenerLogErr("InternalHandler: TsAgentCreate failed: %v", err)
		return 0, fmt.Errorf("InternalHandler: TsAgentCreate: %w", err)
	}
	naxListenerLogOk("InternalHandler: child agent created id=%d", agentData.Id)
	a.srv.agentIDMap.Store(beaconID, agentData.Id)
	return agentData.Id, nil
}

func main() {}
