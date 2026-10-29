package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

const (
	extenderNameAgents   = "nax_agents"
	extenderNameProfiles = "nax_profiles"
)

var (
	Ts        adaptix.Teamserver
	ModuleDir string
)

type PluginService struct{}

type storeEntry struct {
	ID       string `json:"id"`
	Computer string `json:"computer"`
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Arch     string `json:"arch"`
	Profile  string `json:"profile"`
}

type listResponse struct {
	Action  string       `json:"action"`
	Success bool         `json:"success"`
	Entries []storeEntry `json:"entries"`
	Count   int          `json:"count"`
}

type resultResponse struct {
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

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

func sendJSON(operator string, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		if Ts != nil {
			Ts.TsLogAdd(adaptix.LogStatusError, 0, "nax_store", "JSON marshal failure: %v", err)
		}
		return
	}
	Ts.TsServiceSendDataClient(operator, "nax_store", string(data))
}

func InitPlugin(ts any, moduleDir string, serviceConfig string) adaptix.PluginService {
	Ts = ts.(adaptix.Teamserver)
	ModuleDir = moduleDir
	if Ts != nil {
		Ts.TsLogAdd(adaptix.LogStatusSuccess, 1, "nax_store", "InitPlugin → service registered")
	}
	return &PluginService{}
}

func (p *PluginService) CallRPC(operator string, function string, args string) (string, error) {
	p.Call(operator, function, args)
	return "", nil
}

func (p *PluginService) Call(operator string, function string, args string) {
	if Ts != nil {
		Ts.TsLogAdd(adaptix.LogStatusInfo, 1, "nax_store", "RPC: operator=%q function=%q", operator, function)
	}

	switch strings.ToLower(function) {
	case "list":
		handleList(operator)
	case "details":
		handleDetails(operator, args)
	case "delete":
		handleDelete(operator, args)
	case "clear":
		handleClear(operator)
	default:
		sendJSON(operator, resultResponse{
			Action:  "error",
			Success: false,
			Error:   fmt.Sprintf("unknown function: %s", function),
		})
	}
}

func handleList(operator string) {
	agentKeys, _ := Ts.TsExtenderDataKeys(extenderNameAgents)
	profileKeys, _ := Ts.TsExtenderDataKeys(extenderNameProfiles)

	allKeys := make(map[string]bool)
	for _, k := range agentKeys {
		allKeys[k] = true
	}
	for _, k := range profileKeys {
		allKeys[k] = true
	}

	sorted := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	entries := make([]storeEntry, 0, len(sorted))
	for _, id := range sorted {
		e := storeEntry{
			ID:       id,
			Computer: "-",
			Username: "-",
			Domain:   "-",
			Arch:     "-",
			Profile:  "(default)",
		}

		if raw, err := Ts.TsExtenderDataLoad(extenderNameAgents, id); err == nil && len(raw) > 0 {
			var ci cachedAgentIdentity
			if json.Unmarshal(raw, &ci) == nil {
				if ci.Computer != "" {
					e.Computer = ci.Computer
				}
				if ci.Username != "" {
					e.Username = ci.Username
				}
				if ci.Domain != "" {
					e.Domain = ci.Domain
				}
				if ci.Arch != "" {
					e.Arch = ci.Arch
				}
			}
		}

		if raw, err := Ts.TsExtenderDataLoad(extenderNameProfiles, id); err == nil && len(raw) > 0 {
			var pd map[string]any
			if json.Unmarshal(raw, &pd) == nil {
				if h, ok := pd["beacon_id_header"].(string); ok && h != "" {
					e.Profile = h
				}
			}
		}

		entries = append(entries, e)
	}

	sendJSON(operator, listResponse{
		Action:  "list_result",
		Success: true,
		Entries: entries,
		Count:   len(entries),
	})
}

type detailsResponse struct {
	Action  string `json:"action"`
	Success bool   `json:"success"`
	ID      string `json:"id"`

	Computer   string `json:"computer"`
	Username   string `json:"username"`
	Domain     string `json:"domain"`
	Arch       string `json:"arch"`
	Pid        string `json:"pid"`
	Tid        string `json:"tid"`
	Process    string `json:"process"`
	InternalIP string `json:"internal_ip"`
	OsDesc     string `json:"os_desc"`
	Elevated   bool   `json:"elevated"`
	Sleep      uint   `json:"sleep"`

	HasProfile    bool     `json:"has_profile"`
	BeaconHeader  string   `json:"beacon_header"`
	UserAgent     string   `json:"user_agent"`
	Hosts         []string `json:"hosts"`
	Rotation      string   `json:"rotation"`
	GetURICount   int      `json:"get_uri_count"`
	PostURICount  int      `json:"post_uri_count"`
}

func handleDetails(operator string, args string) {
	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.AgentID == "" {
		sendJSON(operator, resultResponse{
			Action:  "details_result",
			Success: false,
			Error:   "agent_id required",
		})
		return
	}

	resp := detailsResponse{
		Action:  "details_result",
		Success: true,
		ID:      req.AgentID,
	}

	if raw, err := Ts.TsExtenderDataLoad(extenderNameAgents, req.AgentID); err == nil && len(raw) > 0 {
		var ci cachedAgentIdentity
		if json.Unmarshal(raw, &ci) == nil {
			resp.Computer = ci.Computer
			resp.Username = ci.Username
			resp.Domain = ci.Domain
			resp.Arch = ci.Arch
			resp.Pid = ci.Pid
			resp.Tid = ci.Tid
			resp.Process = ci.Process
			resp.InternalIP = ci.InternalIP
			resp.OsDesc = ci.OsDesc
			resp.Elevated = ci.Elevated
			resp.Sleep = ci.Sleep
		}
	}

	if raw, err := Ts.TsExtenderDataLoad(extenderNameProfiles, req.AgentID); err == nil && len(raw) > 0 {
		var pd map[string]any
		if json.Unmarshal(raw, &pd) == nil {
			resp.HasProfile = true
			if h, ok := pd["beacon_id_header"].(string); ok {
				resp.BeaconHeader = h
			}
			if prof, ok := pd["profile"].(map[string]any); ok {
				if ua, ok := prof["UserAgent"].(string); ok {
					resp.UserAgent = ua
				}
				if rot, ok := prof["Rotation"].(string); ok {
					resp.Rotation = rot
				}
				if hosts, ok := prof["Hosts"].([]any); ok {
					for _, h := range hosts {
						if s, ok := h.(string); ok {
							resp.Hosts = append(resp.Hosts, s)
						}
					}
				}
				if get, ok := prof["Get"].(map[string]any); ok {
					if uris, ok := get["URIs"].([]any); ok {
						resp.GetURICount = len(uris)
					}
				}
				if post, ok := prof["Post"].(map[string]any); ok {
					if uris, ok := post["URIs"].([]any); ok {
						resp.PostURICount = len(uris)
					}
				}
			}
		}
	} else {
		resp.HasProfile = false
		resp.BeaconHeader = "(default)"
	}

	sendJSON(operator, resp)
}

func handleDelete(operator string, args string) {
	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.Unmarshal([]byte(args), &req); err != nil || req.AgentID == "" {
		sendJSON(operator, resultResponse{
			Action:  "delete_result",
			Success: false,
			Error:   "agent_id required",
		})
		return
	}

	_ = Ts.TsExtenderDataDelete(extenderNameAgents, req.AgentID)
	_ = Ts.TsExtenderDataDelete(extenderNameProfiles, req.AgentID)

	if Ts != nil {
		Ts.TsLogAdd(adaptix.LogStatusInfo, 1, "nax_store", "Deleted store entry: %s", req.AgentID)
	}
	sendJSON(operator, resultResponse{
		Action:  "delete_result",
		Success: true,
		Output:  fmt.Sprintf("Deleted %s", req.AgentID),
	})
}

func handleClear(operator string) {
	count := 0
	if keys, err := Ts.TsExtenderDataKeys(extenderNameAgents); err == nil {
		for _, k := range keys {
			_ = Ts.TsExtenderDataDelete(extenderNameAgents, k)
			count++
		}
	}
	if keys, err := Ts.TsExtenderDataKeys(extenderNameProfiles); err == nil {
		for _, k := range keys {
			_ = Ts.TsExtenderDataDelete(extenderNameProfiles, k)
			count++
		}
	}

	if Ts != nil {
		Ts.TsLogAdd(adaptix.LogStatusInfo, 1, "nax_store", "Cleared %d store entries", count)
	}
	sendJSON(operator, resultResponse{
		Action:  "clear_result",
		Success: true,
		Output:  fmt.Sprintf("Cleared %d entries", count),
	})
}
