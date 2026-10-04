package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"

	"nonameax/naxwire"
)

/* ========= [ Transform functions ] ========= */

// xorMask applies a 4-byte random XOR mask: output = key(4) || masked_data.
func xorMask(data []byte) []byte {
	key := make([]byte, 4)
	_, _ = rand.Read(key)
	out := make([]byte, 4+len(data))
	copy(out[:4], key)
	for i, b := range data {
		out[4+i] = b ^ key[i%4]
	}
	return out
}

// xorUnmask strips a 4-byte key prefix and XOR-unmasks the rest.
func xorUnmask(data []byte) []byte {
	if len(data) < 4 {
		return nil
	}
	key := data[:4]
	out := make([]byte, len(data)-4)
	for i := range out {
		out[i] = data[4+i] ^ key[i%4]
	}
	return out
}

// formatEncode applies the specified encoding format.
func formatEncode(format string, data []byte) []byte {
	switch format {
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(data))
	case "base64url":
		return []byte(base64.RawURLEncoding.EncodeToString(data))
	case "hex":
		return []byte(hex.EncodeToString(data))
	default:
		return data // raw
	}
}

// formatDecode reverses the specified encoding format.
func formatDecode(format string, data []byte) ([]byte, error) {
	switch format {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(string(data))
		}
		return decoded, err
	case "base64url":
		decoded, err := base64.RawURLEncoding.DecodeString(string(data))
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(string(data))
		}
		return decoded, err
	case "hex":
		return hex.DecodeString(string(data))
	default:
		return data, nil // raw
	}
}

// encodeServerOutput applies forward transforms to pre-encrypted data:
// mask -> encode -> prepend/append.  AES encryption is handled by the agent
// plugin's Encrypt (called in PackData), NOT here.
func encodeServerOutput(cfg *naxwire.OutputConfig, data []byte) ([]byte, error) {
	if cfg.Mask {
		data = xorMask(data)
	}

	data = formatEncode(cfg.Format, data)

	if cfg.Prepend != "" || cfg.Append != "" {
		var buf []byte
		if cfg.Prepend != "" {
			buf = append(buf, []byte(cfg.Prepend)...)
		}
		buf = append(buf, data...)
		if cfg.Append != "" {
			buf = append(buf, []byte(cfg.Append)...)
		}
		data = buf
	}

	return data, nil
}

// decodeClientInput reverses profile-level transforms:
// strip prepend/append -> decode -> unmask.  AES decryption is handled by the
// agent plugin's Decrypt (called by the server in Agent.ProcessData), NOT here.
func decodeClientInput(cfg *naxwire.OutputConfig, encoded []byte) ([]byte, error) {
	data := encoded

	// Strip prepend/append
	prependStripped := false
	if cfg.Prepend != "" {
		pre := []byte(cfg.Prepend)
		if len(data) >= len(pre) && string(data[:len(pre)]) == cfg.Prepend {
			data = data[len(pre):]
			prependStripped = true
		}
	}
	appendStripped := false
	if cfg.Append != "" {
		app := []byte(cfg.Append)
		if len(data) >= len(app) && string(data[len(data)-len(app):]) == cfg.Append {
			data = data[:len(data)-len(app)]
			appendStripped = true
		}
	}
	if (cfg.Prepend != "" && !prependStripped) || (cfg.Append != "" && !appendStripped) {
		naxListenerLogInfo("decodeClientInput: strip failed prepend=%v(%d) append=%v(%d) dataLen=%d", prependStripped, len(cfg.Prepend), appendStripped, len(cfg.Append), len(encoded))
	}

	// Format decode
	decoded, err := formatDecode(cfg.Format, data)
	if err != nil {
		return nil, fmt.Errorf("format decode (%s) dataLen=%d: %w", cfg.Format, len(data), err)
	}
	data = decoded

	// XOR unmask
	if cfg.Mask {
		data = xorUnmask(data)
		if data == nil {
			return nil, errors.New("xor unmask: data too short for 4-byte key")
		}
	}

	return data, nil
}

/* ========= [ Extraction helpers ] ========= */

// extractMeta reads the session ID (beaconID) from the location specified
// by the OutputConfig placement. Returns the raw (still-encoded) value.
func extractMeta(cfg *naxwire.OutputConfig, r *http.Request) (string, error) {
	switch cfg.Placement {
	case "header":
		val := r.Header.Get(cfg.Name)
		if val == "" {
			return "", errors.New("missing header: " + cfg.Name)
		}
		return val, nil
	case "cookie":
		cookie, err := r.Cookie(cfg.Name)
		if err != nil || cookie.Value == "" {
			return "", errors.New("missing cookie: " + cfg.Name)
		}
		return cookie.Value, nil
	case "parameter":
		val := r.URL.Query().Get(cfg.Name)
		if val == "" {
			return "", errors.New("missing query param: " + cfg.Name)
		}
		return val, nil
	case "body":
		return "", errors.New("meta from body not supported for session ID extraction")
	default:
		return "", errors.New("unknown placement: " + cfg.Placement)
	}
}

// extractClientOutput reads the client data payload from the POST request
// based on the OutputConfig placement.
func extractClientOutput(cfg *naxwire.OutputConfig, r *http.Request) ([]byte, error) {
	switch cfg.Placement {
	case "body":
		return io.ReadAll(http.MaxBytesReader(nil, r.Body, 32<<20))
	case "header":
		val := r.Header.Get(cfg.Name)
		if val == "" {
			return nil, errors.New("missing header: " + cfg.Name)
		}
		return []byte(val), nil
	case "cookie":
		cookie, err := r.Cookie(cfg.Name)
		if err != nil || cookie.Value == "" {
			return nil, errors.New("missing cookie: " + cfg.Name)
		}
		return []byte(cookie.Value), nil
	case "parameter":
		val := r.URL.Query().Get(cfg.Name)
		if val == "" {
			return nil, errors.New("missing query param: " + cfg.Name)
		}
		return []byte(val), nil
	default:
		return nil, errors.New("unknown placement: " + cfg.Placement)
	}
}

// decodeMetaToBeaconID decodes the raw meta value into a beaconID string.
// For most formats this means format-decode then take the hex string;
// for "raw" format the value is already the beaconID string.
func decodeMetaToBeaconID(cfg *naxwire.OutputConfig, rawMeta string) (string, error) {
	if cfg.Format == "raw" || cfg.Format == "" {
		return rawMeta, nil
	}

	data := []byte(rawMeta)

	// Strip prepend/append from meta
	if cfg.Prepend != "" {
		pre := []byte(cfg.Prepend)
		if len(data) >= len(pre) && string(data[:len(pre)]) == cfg.Prepend {
			data = data[len(pre):]
		}
	}
	if cfg.Append != "" {
		app := []byte(cfg.Append)
		if len(data) >= len(app) && string(data[len(data)-len(app):]) == cfg.Append {
			data = data[:len(data)-len(app)]
		}
	}

	decoded, err := formatDecode(cfg.Format, data)
	if err != nil {
		return "", fmt.Errorf("meta decode (%s): %w", cfg.Format, err)
	}

	return string(decoded), nil
}
