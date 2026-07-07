package main

import (
	"encoding/json"
	"strings"
)

/* ========= [ Profile parsing ] ========= */

// parseProfileConfig builds a ProfileConfig from the listener config JSON.
// Handles both the flat field format (current UI) and the v2 callbacks format
// (future JSON import).
func parseProfileConfig(cfg map[string]any) *ProfileConfig {
	p := &ProfileConfig{
		Rotation: "sequential",
		Error: ServerError{
			Status:  404,
			Body:    "<!DOCTYPE html>\n<html><body><h1>404</h1></body></html>\n",
			Headers: map[string]string{"Content-Type": "text/html"},
		},
	}

	keys := make([]string, 0, len(cfg))
	for k := range cfg { keys = append(keys, k) }
	naxListenerLogInfo("parseProfileConfig: keys=%v", keys)

	// v2 JSON from profile_json textarea (Import JSON button)
	if jsonStr, ok := cfg["profile_json"].(string); ok && jsonStr != "" {
		naxListenerLogInfo("parseProfileConfig: found profile_json (%d chars)", len(jsonStr))
		var parsed map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err == nil {
			if arr, ok := parsed["callbacks"].([]any); ok && len(arr) > 0 {
				if cb, ok := arr[0].(map[string]any); ok {
					parseCallbackV2(cb, p)
				}
			}
			return p
		}
	}

	// v2 JSON format: if "callbacks" array is present at top level, parse it directly
	if raw, ok := cfg["callbacks"]; ok {
		if arr, ok := raw.([]any); ok && len(arr) > 0 {
			if cb, ok := arr[0].(map[string]any); ok {
				parseCallbackV2(cb, p)
			}
		}
		return p
	}

	// Build ProfileConfig from flat listener config fields (v2 UI keys).

	// --- General ---
	if ua, ok := cfg["user_agents"].(string); ok && ua != "" {
		p.UserAgent = ua
	} else if uas, ok := cfg["user_agents"].([]any); ok && len(uas) > 0 {
		if s, ok := uas[0].(string); ok {
			p.UserAgent = s
		}
	}
	if rot, ok := cfg["rotation"].(string); ok && rot != "" {
		p.Rotation = rot
	}
	if raw, ok := cfg["callbacks_hosts"].([]any); ok {
		for _, h := range raw {
			if s, ok := h.(string); ok && s != "" {
				p.Hosts = append(p.Hosts, s)
			}
		}
	}

	// --- GET URIs ---
	if raw, ok := cfg["get_uris"].([]any); ok {
		for _, u := range raw {
			if s, ok := u.(string); ok && s != "" {
				p.Get.URIs = append(p.Get.URIs, s)
			}
		}
	}

	p.Get.ClientHeaders = parseHeaderList(cfg, "get_client_headers")
	p.Get.ClientMeta = parseFlatOutputConfig(cfg, "get_meta")
	p.Get.ServerOutput = parseFlatOutputConfig(cfg, "get_srv")
	if empty, ok := cfg["get_srv_empty"].(string); ok {
		p.Get.ServerOutput.EmptyResp = empty
	}
	p.Get.ServerHeaders = parseHeaderList(cfg, "get_srv_headers")
	if len(p.Get.ServerHeaders) == 0 {
		p.Get.ServerHeaders = map[string]string{"Content-Type": "application/octet-stream", "Connection": "keep-alive"}
	}

	// --- POST URIs ---
	if raw, ok := cfg["post_uris"].([]any); ok {
		for _, u := range raw {
			if s, ok := u.(string); ok && s != "" {
				p.Post.URIs = append(p.Post.URIs, s)
			}
		}
	}

	p.Post.ClientHeaders = parseHeaderList(cfg, "post_client_headers")
	p.Post.ClientMeta = parseFlatOutputConfig(cfg, "post_meta")
	postOut := parseFlatOutputConfig(cfg, "post_out")
	p.Post.ClientOutput = &postOut
	p.Post.ServerOutput = parseFlatOutputConfig(cfg, "post_srv")
	if empty, ok := cfg["post_srv_empty"].(string); ok {
		p.Post.ServerOutput.EmptyResp = empty
	}
	p.Post.ServerHeaders = parseHeaderList(cfg, "post_srv_headers")
	if len(p.Post.ServerHeaders) == 0 {
		p.Post.ServerHeaders = map[string]string{"Content-Type": "application/octet-stream", "Connection": "keep-alive"}
	}

	// Legacy compat: "extra_headers" -> GET client headers (old UI key)
	if len(p.Get.ClientHeaders) == 0 {
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
	}

	if p.Get.ClientMeta.Format == "" && p.Get.ClientMeta.Placement == "" {
		cookieName := "__session"
		if cn, ok := cfg["cookie_name"].(string); ok && cn != "" {
			cookieName = cn
		}
		p.Get.ClientMeta = OutputConfig{Format: "base64", Placement: "cookie", Name: cookieName}
	}

	if p.Post.ClientMeta.Format == "" && p.Post.ClientMeta.Placement == "" {
		p.Post.ClientMeta = OutputConfig{Format: "raw", Placement: "header", Name: "X-Beacon-Id"}
	}
	if p.Post.ClientOutput != nil && p.Post.ClientOutput.Format == "" && p.Post.ClientOutput.Placement == "" {
		p.Post.ClientOutput = &OutputConfig{Format: "raw", Placement: "body"}
	}

	// --- Error page ---
	if errStatus, ok := cfg["err_status"].(float64); ok && errStatus > 0 {
		p.Error.Status = int(errStatus)
	}
	if errBody, ok := cfg["err_body"].(string); ok && errBody != "" {
		p.Error.Body = errBody
	}
	if errHdrs := parseHeaderList(cfg, "err_headers"); len(errHdrs) > 0 {
		p.Error.Headers = errHdrs
	}
	if errBody, ok := cfg["page-error"].(string); ok && errBody != "" {
		p.Error.Body = errBody
	}

	return p
}

// parseCallbackV2 populates a ProfileConfig from a v2 callbacks JSON object.
func parseCallbackV2(cb map[string]any, p *ProfileConfig) {
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
		parseHTTPTransactionV2(get, &p.Get, false)
	}
	if post, ok := cb["post"].(map[string]any); ok {
		parseHTTPTransactionV2(post, &p.Post, true)
	}
}

func parseHTTPTransactionV2(raw map[string]any, tx *HTTPTransaction, isPost bool) {
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
		tx.ClientMeta = parseOutputConfigV2(meta)
	} else if meta, ok := raw["client_meta"].(map[string]any); ok {
		tx.ClientMeta = parseOutputConfigV2(meta)
	}
	if isPost {
		if out, ok := client["output"].(map[string]any); ok {
			cfg := parseOutputConfigV2(out)
			tx.ClientOutput = &cfg
		} else if out, ok := raw["client_output"].(map[string]any); ok {
			cfg := parseOutputConfigV2(out)
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
		tx.ServerOutput = parseOutputConfigV2(sout)
	} else if sout, ok := raw["server_output"].(map[string]any); ok {
		tx.ServerOutput = parseOutputConfigV2(sout)
	}
}

func parseOutputConfigV2(raw map[string]any) OutputConfig {
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

func parseFlatOutputConfig(cfg map[string]any, prefix string) OutputConfig {
	oc := OutputConfig{}
	if f, ok := cfg[prefix+"_format"].(string); ok {
		oc.Format = f
	}
	if m, ok := cfg[prefix+"_mask"].(bool); ok {
		oc.Mask = m
	}
	if p, ok := cfg[prefix+"_placement"].(string); ok {
		oc.Placement = p
	}
	if n, ok := cfg[prefix+"_name"].(string); ok {
		oc.Name = n
	}
	if pre, ok := cfg[prefix+"_prepend"].(string); ok {
		oc.Prepend = pre
	}
	if app, ok := cfg[prefix+"_append"].(string); ok {
		oc.Append = app
	}
	return oc
}

func parseHeaderList(cfg map[string]any, key string) map[string]string {
	if raw, ok := cfg[key].([]any); ok && len(raw) > 0 {
		m := map[string]string{}
		for _, u := range raw {
			if s, ok := u.(string); ok && s != "" {
				if idx := strings.Index(s, ": "); idx > 0 {
					m[s[:idx]] = s[idx+2:]
				}
			}
		}
		return m
	}
	if raw, ok := cfg[key].(map[string]any); ok {
		m := map[string]string{}
		for k, v := range raw {
			if s, ok := v.(string); ok {
				m[k] = s
			}
		}
		return m
	}
	return nil
}
