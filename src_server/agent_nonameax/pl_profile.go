package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func saveProfileToStore(agentId string, profile *ProfileConfig) error {
	if Ts == nil {
		return fmt.Errorf("teamserver not available")
	}
	data, err := json.Marshal(map[string]any{
		"beacon_id_header": profile.BeaconIdHeader,
		"profile":          profile,
	})
	if err != nil {
		return err
	}
	return Ts.TsExtenderDataSave(extenderNameProfiles, agentId, data)
}

func removeProfileFromStore(agentId string) {
	if Ts == nil {
		return
	}
	if err := Ts.TsExtenderDataDelete(extenderNameProfiles, agentId); err != nil {
		naxLogErr("removeProfileFromStore: %v", err)
	}
}

/* ========= [ profile config from listener JSON ] ========= */

// parseProfileFromListenerConfig builds a ProfileConfig from the listener config
// JSON (map[string]any). This is a copy of the listener's parseProfileConfig -
// the two plugins are separate .so files so they cannot share code (ADR-002).
func parseProfileFromListenerConfig(cfg map[string]any) *ProfileConfig {
	p := &ProfileConfig{
		Rotation: "sequential",
		Error: ServerError{
			Status:  404,
			Body:    "<!DOCTYPE html>\n<html><body><h1>404</h1></body></html>\n",
			Headers: map[string]string{"Content-Type": "text/html"},
		},
	}

	// v2 JSON from profile_json textarea (Import JSON button in listener UI)
	if jsonStr, ok := cfg["profile_json"].(string); ok && jsonStr != "" {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
			if arr, ok := parsed["callbacks"].([]any); ok && len(arr) > 0 {
				if cb, ok := arr[0].(map[string]any); ok {
					parseCallbackV2Agent(cb, p)
				}
			}
			return p
		}
	}

	// v2 JSON format: if "callbacks" array is present at top level, parse it directly
	if raw, ok := cfg["callbacks"]; ok {
		if arr, ok := raw.([]any); ok && len(arr) > 0 {
			if cb, ok := arr[0].(map[string]any); ok {
				parseCallbackV2Agent(cb, p)
			}
		}
		return p
	}

	// Build ProfileConfig from flat listener config fields
	if raw, ok := cfg["callbacks_hosts"].([]any); ok {
		for _, h := range raw {
			if s, ok := h.(string); ok && s != "" {
				p.Hosts = append(p.Hosts, s)
			}
		}
	}
	if uas, ok := cfg["user_agents"].([]any); ok && len(uas) > 0 {
		if s, ok := uas[0].(string); ok {
			p.UserAgent = s
		}
	}
	if rot, ok := cfg["rotation"].(string); ok && rot != "" {
		p.Rotation = rot
	}

	// GET URIs
	if raw, ok := cfg["get_uris"].([]any); ok {
		for _, u := range raw {
			if s, ok := u.(string); ok && s != "" {
				p.Get.URIs = append(p.Get.URIs, s)
			}
		}
	}
	// POST URIs
	if raw, ok := cfg["post_uris"].([]any); ok {
		for _, u := range raw {
			if s, ok := u.(string); ok && s != "" {
				p.Post.URIs = append(p.Post.URIs, s)
			}
		}
	}

	if raw, ok := cfg["extra_headers"].([]any); ok && len(raw) > 0 {
		p.Get.ClientHeaders = map[string]string{}
		for _, u := range raw {
			if s, ok := u.(string); ok && s != "" {
				if idx := strings.Index(s, ": "); idx > 0 {
					p.Get.ClientHeaders[s[:idx]] = s[idx+2:]
				}
			}
		}
	}

	cookieName := "__session"
	if cn, ok := cfg["cookie_name"].(string); ok && cn != "" {
		cookieName = cn
	}
	p.Get.ClientMeta = OutputConfig{Format: "base64", Placement: "cookie", Name: cookieName}

	// POST defaults
	p.Post.ClientMeta = OutputConfig{Format: "raw", Placement: "header", Name: "X-Beacon-Id"}
	p.Post.ClientOutput = &OutputConfig{Format: "raw", Placement: "body"}
	p.Post.ServerOutput = OutputConfig{Format: "raw", Placement: "body"}
	p.Get.ServerOutput = OutputConfig{Format: "raw", Placement: "body"}

	// Server response headers
	p.Get.ServerHeaders = map[string]string{"Content-Type": "application/octet-stream", "Connection": "keep-alive"}
	p.Post.ServerHeaders = map[string]string{"Content-Type": "application/octet-stream", "Connection": "keep-alive"}

	// Error page
	if errBody, ok := cfg["page-error"].(string); ok && errBody != "" {
		p.Error.Body = errBody
	}

	return p
}

func parseCallbackV2Agent(cb map[string]any, p *ProfileConfig) {
	if raw, ok := cb["hosts"].([]any); ok {
		for _, h := range raw {
			if s, ok := h.(string); ok && s != "" {
				p.Hosts = append(p.Hosts, s)
			}
		}
	}
	if ua, ok := cb["user_agent"].(string); ok {
		p.UserAgent = ua
	}
	if bh, ok := cb["beacon_id_header"].(string); ok {
		p.BeaconIdHeader = bh
	}
	if rot, ok := cb["rotation"].(string); ok {
		p.Rotation = rot
	}
	if se, ok := cb["server_error"].(map[string]any); ok {
		if st, ok := se["status"].(float64); ok {
			p.Error.Status = int(st)
		} else if st, ok := se["http_status"].(float64); ok {
			p.Error.Status = int(st)
		}
		if body, ok := se["body"].(string); ok {
			p.Error.Body = body
		} else if body, ok := se["response"].(string); ok {
			p.Error.Body = body
		}
		if hdrs, ok := se["headers"].(map[string]any); ok {
			p.Error.Headers = map[string]string{}
			for k, v := range hdrs {
				if s, ok := v.(string); ok {
					p.Error.Headers[k] = s
				}
			}
		}
	}
	if get, ok := cb["get"].(map[string]any); ok {
		parseHTTPTransactionV2Agent(get, &p.Get, false)
	}
	if post, ok := cb["post"].(map[string]any); ok {
		parseHTTPTransactionV2Agent(post, &p.Post, true)
	}
}

func parseHTTPTransactionV2Agent(raw map[string]any, tx *HTTPTransaction, isPost bool) {
	uriKey := "uri"
	if _, ok := raw[uriKey]; !ok {
		uriKey = "uris"
	}
	if uris, ok := raw[uriKey].([]any); ok {
		for _, u := range uris {
			if s, ok := u.(string); ok && s != "" {
				tx.URIs = append(tx.URIs, s)
			}
		}
	}

	client := raw
	if c, ok := raw["client"].(map[string]any); ok {
		client = c
	}

	if hdrs, ok := client["headers"].(map[string]any); ok {
		tx.ClientHeaders = map[string]string{}
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				tx.ClientHeaders[k] = s
			}
		}
	}
	if meta, ok := client["metadata"].(map[string]any); ok {
		tx.ClientMeta = parseOutputConfigV2Agent(meta)
	} else if meta, ok := raw["client_meta"].(map[string]any); ok {
		tx.ClientMeta = parseOutputConfigV2Agent(meta)
	}
	if isPost {
		if out, ok := client["output"].(map[string]any); ok {
			cfg := parseOutputConfigV2Agent(out)
			tx.ClientOutput = &cfg
		} else if out, ok := raw["client_output"].(map[string]any); ok {
			cfg := parseOutputConfigV2Agent(out)
			tx.ClientOutput = &cfg
		}
	}
	if params, ok := client["parameters"].(map[string]any); ok {
		tx.ClientParams = map[string]string{}
		for k, v := range params {
			if s, ok := v.(string); ok {
				tx.ClientParams[k] = s
			}
		}
	}

	server := raw
	if s, ok := raw["server"].(map[string]any); ok {
		server = s
	}

	if shdrs, ok := server["headers"].(map[string]any); ok {
		tx.ServerHeaders = map[string]string{}
		for k, v := range shdrs {
			if s, ok := v.(string); ok {
				tx.ServerHeaders[k] = s
			}
		}
	}
	if sout, ok := server["output"].(map[string]any); ok {
		tx.ServerOutput = parseOutputConfigV2Agent(sout)
	} else if sout, ok := raw["server_output"].(map[string]any); ok {
		tx.ServerOutput = parseOutputConfigV2Agent(sout)
	}
}

func parseOutputConfigV2Agent(raw map[string]any) OutputConfig {
	cfg := OutputConfig{}
	if f, ok := raw["format"].(string); ok {
		cfg.Format = f
	}
	if m, ok := raw["mask"].(bool); ok {
		cfg.Mask = m
	}
	if p, ok := raw["placement"].(string); ok {
		cfg.Placement = p
	}
	if n, ok := raw["name"].(string); ok {
		cfg.Name = n
	}
	if pre, ok := raw["prepend"].(string); ok {
		cfg.Prepend = pre
	}
	if app, ok := raw["append"].(string); ok {
		cfg.Append = app
	}
	if er, ok := raw["empty_resp"].(string); ok {
		cfg.EmptyResp = er
	}
	return cfg
}
