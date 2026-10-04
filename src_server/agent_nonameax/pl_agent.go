package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
	"nonameax/naxwire"
)

// cachedAgentIdentity holds the identity fields persisted via TsExtenderData
// so that they survive teamserver restarts. Only the fields populated from a
// REGISTER frame are stored.
type cachedAgentIdentity struct {
	Computer   string
	Username   string
	Pid        string
	Tid        string
	Arch       string
	Sleep      uint
	InternalIP string
	Domain     string
	Process    string
	Elevated   bool
	ACP        int
	OemCP      int
	OsDesc     string
}

// loadCacheFromStore reads the persisted identity cache into agentIdentityCache.
func loadCacheFromStore() {
	if Ts == nil {
		return
	}
	keys, err := Ts.TsExtenderDataKeys(extenderNameAgents)
	if err != nil || len(keys) == 0 {
		return
	}
	count := 0
	for _, key := range keys {
		raw, err := Ts.TsExtenderDataLoad(extenderNameAgents, key)
		if err != nil || len(raw) == 0 {
			continue
		}
		var e cachedAgentIdentity
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		ad := adaptix.AgentData{
			Computer: e.Computer, Username: e.Username, Pid: e.Pid,
			Tid: e.Tid, Arch: e.Arch, Sleep: e.Sleep,
			InternalIP: e.InternalIP, Domain: e.Domain,
			Process: e.Process, Elevated: e.Elevated,
			ACP: e.ACP, OemCP: e.OemCP, OsDesc: e.OsDesc,
		}
		agentIdentityCache.Store(key, ad)
		count++
	}
	naxLogInfo("loadCacheFromStore: loaded %d agent(s)", count)
}

// saveCacheEntry persists a single agent's identity to the teamserver store.
func saveCacheEntry(beaconID string, ad adaptix.AgentData) {
	if Ts == nil {
		return
	}
	e := cachedAgentIdentity{
		Computer: ad.Computer, Username: ad.Username, Pid: ad.Pid,
		Tid: ad.Tid, Arch: ad.Arch, Sleep: ad.Sleep,
		InternalIP: ad.InternalIP, Domain: ad.Domain,
		Process: ad.Process, Elevated: ad.Elevated,
		ACP: ad.ACP, OemCP: ad.OemCP, OsDesc: ad.OsDesc,
	}
	data, err := json.Marshal(e)
	if err != nil {
		naxLogErr("saveCacheEntry: JSON encode error: %v", err)
		return
	}
	if err := Ts.TsExtenderDataSave(extenderNameAgents, beaconID, data); err != nil {
		naxLogErr("saveCacheEntry: save error: %v", err)
	}
}

// --- Pivot persistence ---

type cachedPivot struct {
	ParentAgentId int64
	ChildAgentId  int64
}

func clearChildMark(childAgentId int64) {
	if Ts == nil || childAgentId == 0 {
		return
	}
	emptyMark := ""
	_ = Ts.TsAgentUpdateDataPartial(childAgentId, struct {
		Mark *string `json:"mark"`
	}{Mark: &emptyMark})
}

func savePivotToStore(pivotId string, parentAgentId int64, childAgentId int64) {
	if Ts == nil {
		return
	}
	data, err := json.Marshal(cachedPivot{ParentAgentId: parentAgentId, ChildAgentId: childAgentId})
	if err != nil {
		return
	}
	_ = Ts.TsExtenderDataSave(extenderNamePivots, pivotId, data)
}

func deletePivotFromStore(pivotId string) {
	if Ts == nil {
		return
	}
	_ = Ts.TsExtenderDataDelete(extenderNamePivots, pivotId)
}

func deleteAgentPivotsFromStore(agentId int64) {
	if Ts == nil {
		return
	}
	keys, err := Ts.TsExtenderDataKeys(extenderNamePivots)
	if err != nil {
		return
	}
	for _, pivotId := range keys {
		raw, err := Ts.TsExtenderDataLoad(extenderNamePivots, pivotId)
		if err != nil || len(raw) == 0 {
			continue
		}
		var p cachedPivot
		if err := json.Unmarshal(raw, &p); err != nil {
			continue
		}
		if p.ParentAgentId == agentId || p.ChildAgentId == agentId {
			_ = Ts.TsExtenderDataDelete(extenderNamePivots, pivotId)
		}
	}
}

// registerCleanupHooks registers event hooks that clean up persisted data
// when an agent is terminated from the operator UI.
func registerCleanupHooks() {
	if Ts == nil {
		return
	}
	Ts.TsEventHookRegister("agent.terminate", "nax_cleanup_agent", 1, 0, func(data any) error {
		agentId, ok := data.(int64)
		if !ok {
			return nil
		}
		beaconID := ""
		if raw, found := agentIdToBeaconId.LoadAndDelete(agentId); found {
			beaconID = raw.(string)
		}
		if beaconID != "" {
			agentIdentityCache.Delete(beaconID)
			_ = Ts.TsExtenderDataDelete(extenderNameAgents, beaconID)
		}
		agentIdStr := strconv.FormatInt(agentId, 10)
		_ = Ts.TsExtenderDataDelete(extenderNameProfiles, agentIdStr)
		deleteAgentPivotsFromStore(agentId)
		pendingProfiles.Delete(agentId)
		naxLogInfo("agent.terminate cleanup: %d", agentId)
		return nil
	})
}

// CreateAgent decodes the first beacon body and returns a populated AgentData.
//
// The listener prepends the 16-char hex beaconID (from X-Beacon-Id) to the
// wire frame before calling TsAgentCreate, so that we can set AgentData.UID
// to that same ID.  Adaptix uses AgentData.Id (server-assigned int64) as the
// session lookup key for TsAgentIsExists / TsAgentProcessData /
// TsAgentGetHostedAll.
//
// CreateAgent is invoked both for the genuine first contact (REGISTER frame
// from a fresh implant) AND when the listener has to re-register an agent
// the operator deleted from the UI (the implant has no way to know about
// the deletion, so it keeps sending HEARTBEAT). For the HEARTBEAT case we
// fall back to placeholder values - the implant's identity is unknown until
// it sends another REGISTER on its own (e.g. after restart).
func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.AgentFunctions, error) {
	if len(beat) < 32 {
		return adaptix.AgentData{}, adaptix.AgentFunctions{}, errors.New("nonameax: CreateAgent: beat too short (need >=32 bytes: 16 beaconID + 16 AES key)")
	}
	beaconID := string(beat[:16])
	aesKey := make([]byte, 16)
	copy(aesKey, beat[16:32])
	frameData := beat[32:]

	ad := adaptix.AgentData{
		UID:        []byte(beaconID),
		Os:         adaptix.OS_WINDOWS,
		SessionKey: aesKey,
	}

	naxLogInfo("CreateAgent: beaconID=%s keyPrefix=%x frameDataLen=%d first16=%x", beaconID, aesKey[:4], len(frameData), frameData[:min(16, len(frameData))])
	decrypted, err := naxwire.DecryptCBC(aesKey, frameData)
	if err != nil {
		naxLogErr("CreateAgent: decrypt FAILED beaconID=%s keyPrefix=%x frameDataLen=%d: %v", beaconID, aesKey[:4], len(frameData), err)
		return ad, buildAgentFunctions(), nil
	}
	frameData = decrypted
	msgType, _, body, err := naxwire.DecodeFrame(frameData)
	if err != nil {
		naxLogErr("CreateAgent: DecodeFrame failed: %v (frameData len=%d)", err, len(frameData))
		return ad, buildAgentFunctions(), nil
	}
	naxLogInfo("CreateAgent: frame type=0x%02x bodyLen=%d", msgType, len(body))

	if msgType != naxwire.WireTypeRegister {
		if cached, ok := agentIdentityCache.Load(beaconID); ok {
			cachedAd := cached.(adaptix.AgentData)
			ad.Computer   = cachedAd.Computer
			ad.Username   = cachedAd.Username
			ad.Pid        = cachedAd.Pid
			ad.Tid        = cachedAd.Tid
			ad.Arch       = cachedAd.Arch
			ad.Sleep      = cachedAd.Sleep
			ad.InternalIP = cachedAd.InternalIP
			ad.Domain     = cachedAd.Domain
			ad.Process    = cachedAd.Process
			ad.Elevated   = cachedAd.Elevated
			ad.ACP        = cachedAd.ACP
			ad.OemCP      = cachedAd.OemCP
			ad.OsDesc     = cachedAd.OsDesc
		}
		return ad, buildAgentFunctions(), nil
	}

	reg, err := naxwire.DecodeRegister(body)
	if err != nil {
		return adaptix.AgentData{}, adaptix.AgentFunctions{}, err
	}

	archStr := "x64"
	if reg.Arch == 0x02 {
		archStr = "x86"
	}

	ad.Computer   = reg.Hostname
	ad.Username   = reg.Username
	ad.Pid        = fmt.Sprintf("%d", reg.Pid)
	ad.Tid        = fmt.Sprintf("%d", reg.Tid)
	ad.Arch       = archStr
	ad.Sleep      = uint(reg.SleepMs / 1000)
	ad.InternalIP = reg.Ip
	ad.Domain     = reg.Domain
	ad.Process    = reg.ProcessName
	ad.Elevated   = reg.Elevated != 0
	ad.ACP        = int(reg.Acp)
	ad.OemCP      = int(reg.OemCp)
	ad.OsDesc     = naxOsVersion(reg.OsMajor, reg.OsMinor, reg.OsBuild, archStr)

	naxLogOk("CreateAgent: beaconID=%s host=%s user=%s pid=%d tid=%d arch=%s ip=%s domain=%s proc=%s elevated=%v os=%s acp=%d oemcp=%d ppid=%d img=%s",
		beaconID, reg.Hostname, reg.Username, reg.Pid, reg.Tid, archStr, reg.Ip, reg.Domain, reg.ProcessName, ad.Elevated, ad.OsDesc, reg.Acp, reg.OemCp, reg.ParentPid, reg.ImgPath)

	agentIdentityCache.Store(beaconID, ad)
	saveCacheEntry(beaconID, ad)

	return ad, buildAgentFunctions(), nil
}
