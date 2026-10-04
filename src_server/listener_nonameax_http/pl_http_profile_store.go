package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"nonameax/naxwire"
)

/* ========= [ Per-agent profile overrides ] ========= */

const extenderNameProfiles = "nax_profiles"

// loadProfileOverrides reads all persisted profile overrides from the
// teamserver's TsExtenderData store and populates the agentProfiles map.
func (s *httpServer) loadProfileOverrides() {
	if s.ts == nil {
		return
	}
	keys, err := s.ts.TsExtenderDataKeys(extenderNameProfiles)
	if err != nil || len(keys) == 0 {
		return
	}
	for _, agentID := range keys {
		s.loadProfileFromStore(agentID)
	}
	s.rebuildBeaconIDHeaders()
}

// loadProfileFromStore reads a single agent's profile override from the store.
// Returns the resolved beaconID (empty if failed) and whether the profile changed.
func (s *httpServer) loadProfileFromStore(agentID string) (string, bool) {
	if s.ts == nil {
		return "", false
	}
	raw, err := s.ts.TsExtenderDataLoad(extenderNameProfiles, agentID)
	if err != nil || len(raw) == 0 {
		return "", false
	}
	var wrapper struct {
		BeaconID       string         `json:"beacon_id"`
		BeaconIdHeader string         `json:"beacon_id_header"`
		Profile        map[string]any `json:"profile"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		naxListenerLogErr("loadProfileFromStore: parse agent %s: %v", agentID, err)
		return "", false
	}
	if wrapper.Profile == nil {
		return "", false
	}

	mapKey := wrapper.BeaconID
	if mapKey == "" {
		s.agentIDMap.Range(func(k, v any) bool {
			if fmt.Sprintf("%d", v.(int64)) == agentID {
				mapKey = k.(string)
				return false
			}
			return true
		})
	}
	if mapKey == "" && s.ts != nil {
		var agentInt int64
		if _, err := fmt.Sscanf(agentID, "%d", &agentInt); err == nil {
			if ad, ok := s.ts.TsAgentGetById(agentInt); ok && len(ad.UID) > 0 {
				mapKey = string(ad.UID)
			} else if !ok {
				return "", false
			}
		}
	}
	if mapKey == "" {
		naxListenerLogErr("loadProfileFromStore: cannot resolve beaconID for agent %s, skipping", agentID)
		return "", false
	}

	if prev, ok := s.profileStoreRaw.Load(agentID); ok && bytes.Equal(prev.([]byte), raw) {
		return mapKey, false
	}
	s.profileStoreRaw.Store(agentID, raw)

	profCfg := parseProfileFromStoreEntry(wrapper.Profile, wrapper.BeaconIdHeader)
	if existing, ok := s.agentProfiles.Load(mapKey); ok {
		s.agentPrevProfiles.Store(mapKey, existing)
		naxListenerLogOk("updated profile override for beacon %s (beacon_id_header=%s), previous preserved", mapKey, profCfg.BeaconIdHeader)
	} else {
		naxListenerLogOk("loaded profile override for beacon %s (beacon_id_header=%s)", mapKey, profCfg.BeaconIdHeader)
	}
	s.agentProfiles.Store(mapKey, profCfg)
	return mapKey, true
}

// parseProfileFromStoreEntry builds a ProfileConfig from the stored JSON.
func parseProfileFromStoreEntry(raw map[string]any, beaconHdr string) *naxwire.ProfileConfig {
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return &naxwire.ProfileConfig{}
	}
	var profMap map[string]any
	if err := json.Unmarshal(jsonBytes, &profMap); err != nil {
		return &naxwire.ProfileConfig{}
	}
	p := &naxwire.ProfileConfig{
		Rotation: "sequential",
		Error: naxwire.ServerError{
			Status:  404,
			Body:    "<!DOCTYPE html>\n<html><body><h1>404</h1></body></html>\n",
			Headers: map[string]string{"Content-Type": "text/html"},
		},
	}
	if ua, ok := profMap["UserAgent"].(string); ok {
		p.UserAgent = ua
	}
	if bh, ok := profMap["BeaconIdHeader"].(string); ok {
		p.BeaconIdHeader = bh
	}
	if beaconHdr != "" {
		p.BeaconIdHeader = beaconHdr
	}
	if rot, ok := profMap["Rotation"].(string); ok {
		p.Rotation = rot
	}
	if hosts, ok := profMap["Hosts"].([]any); ok {
		for _, h := range hosts {
			if s, ok := h.(string); ok {
				p.Hosts = append(p.Hosts, s)
			}
		}
	}
	if errMap, ok := profMap["Error"].(map[string]any); ok {
		if st, ok := errMap["Status"].(float64); ok {
			p.Error.Status = int(st)
		}
		if body, ok := errMap["Body"].(string); ok {
			p.Error.Body = body
		}
		if hdrs, ok := errMap["Headers"].(map[string]any); ok {
			p.Error.Headers = map[string]string{}
			for k, v := range hdrs {
				if s, ok := v.(string); ok {
					p.Error.Headers[k] = s
				}
			}
		}
	}
	parseHTTPTransactionFromStore(profMap, "Get", &p.Get, false)
	parseHTTPTransactionFromStore(profMap, "Post", &p.Post, true)
	return p
}

func parseHTTPTransactionFromStore(profMap map[string]any, key string, tx *naxwire.HTTPTransaction, isPost bool) {
	raw, ok := profMap[key].(map[string]any)
	if !ok {
		return
	}
	if uris, ok := raw["URIs"].([]any); ok {
		for _, u := range uris {
			if s, ok := u.(string); ok {
				tx.URIs = append(tx.URIs, s)
			}
		}
	}
	if hdrs, ok := raw["ClientHeaders"].(map[string]any); ok {
		tx.ClientHeaders = map[string]string{}
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				tx.ClientHeaders[k] = s
			}
		}
	}
	if params, ok := raw["ClientParams"].(map[string]any); ok {
		tx.ClientParams = map[string]string{}
		for k, v := range params {
			if s, ok := v.(string); ok {
				tx.ClientParams[k] = s
			}
		}
	}
	if meta, ok := raw["ClientMeta"].(map[string]any); ok {
		tx.ClientMeta = parseOutputConfigFromStore(meta)
	}
	if isPost {
		if out, ok := raw["ClientOutput"].(map[string]any); ok {
			cfg := parseOutputConfigFromStore(out)
			tx.ClientOutput = &cfg
		}
	}
	if shdrs, ok := raw["ServerHeaders"].(map[string]any); ok {
		tx.ServerHeaders = map[string]string{}
		for k, v := range shdrs {
			if s, ok := v.(string); ok {
				tx.ServerHeaders[k] = s
			}
		}
	}
	if sout, ok := raw["ServerOutput"].(map[string]any); ok {
		tx.ServerOutput = parseOutputConfigFromStore(sout)
	}
}

func parseOutputConfigFromStore(raw map[string]any) naxwire.OutputConfig {
	cfg := naxwire.OutputConfig{}
	if f, ok := raw["Format"].(string); ok {
		cfg.Format = f
	}
	if m, ok := raw["Mask"].(bool); ok {
		cfg.Mask = m
	}
	if p, ok := raw["Placement"].(string); ok {
		cfg.Placement = p
	}
	if n, ok := raw["Name"].(string); ok {
		cfg.Name = n
	}
	if pre, ok := raw["Prepend"].(string); ok {
		cfg.Prepend = pre
	}
	if app, ok := raw["Append"].(string); ok {
		cfg.Append = app
	}
	if er, ok := raw["EmptyResp"].(string); ok {
		cfg.EmptyResp = er
	}
	return cfg
}

// rebuildBeaconIDHeaders builds the deduped list of all known beacon ID headers
// (default + current overrides + previous overrides).
func (s *httpServer) rebuildBeaconIDHeaders() {
	seen := map[string]bool{s.hbHeader: true}
	headers := []string{s.hbHeader}
	addFrom := func(_, v any) bool {
		p := v.(*naxwire.ProfileConfig)
		hdr := p.BeaconIdHeader
		if hdr == "" {
			hdr = "X-Beacon-Id"
		}
		if !seen[hdr] {
			seen[hdr] = true
			headers = append(headers, hdr)
		}
		return true
	}
	s.agentProfiles.Range(addFrom)
	s.agentPrevProfiles.Range(addFrom)
	s.beaconIDHeaders = headers
}

// pollProfileStore checks the teamserver store for new or updated profile
// overrides at most once every 5 seconds.
func (s *httpServer) pollProfileStore() {
	now := time.Now()
	if now.Sub(s.profileStoreCheck) < 5*time.Second {
		return
	}
	s.profileStoreCheck = now
	s.reloadAllProfiles()
}

// forceReloadProfiles bypasses the 5-second throttle and reloads all profiles
// from the store immediately.
func (s *httpServer) forceReloadProfiles() {
	s.reloadAllProfiles()
	s.profileStoreCheck = time.Now()
}

func (s *httpServer) reloadAllProfiles() {
	if s.ts == nil {
		return
	}
	keys, err := s.ts.TsExtenderDataKeys(extenderNameProfiles)
	if err != nil {
		return
	}
	activeBeaconIDs := make(map[string]struct{}, len(keys))
	activeStoreKeys := make(map[string]struct{}, len(keys))
	changed := false
	for _, agentID := range keys {
		activeStoreKeys[agentID] = struct{}{}
		beaconID, updated := s.loadProfileFromStore(agentID)
		if beaconID != "" {
			activeBeaconIDs[beaconID] = struct{}{}
		}
		if updated {
			changed = true
		}
	}
	s.agentProfiles.Range(func(key, _ any) bool {
		if _, ok := activeBeaconIDs[key.(string)]; !ok {
			s.agentProfiles.Delete(key)
			s.agentPrevProfiles.Delete(key)
			naxListenerLogInfo("removed stale profile override for beacon %s", key.(string))
			changed = true
		}
		return true
	})
	s.profileStoreRaw.Range(func(key, _ any) bool {
		if _, ok := activeStoreKeys[key.(string)]; !ok {
			s.profileStoreRaw.Delete(key)
		}
		return true
	})
	if changed {
		s.rebuildBeaconIDHeaders()
	}
}
