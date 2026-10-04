package naxwire

import (
	"bytes"
	"testing"
)

func TestEncodeFrameNoTasksProducesSixBytes(t *testing.T) {
	got := EncodeFrame(WireTypeNoTasks, nil)
	// type=0x80, flags=0x00, bodylen=0x00000000 (LE u32)
	want := []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("NO_TASKS frame: got %x, want %x", got, want)
	}
}

func TestEncodeFrameRoundTripsThroughDecode(t *testing.T) {
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	frame := EncodeFrame(WireTypeResult, body)
	typ, flags, gotBody, err := DecodeFrame(frame)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if typ != WireTypeResult {
		t.Errorf("type: got %#x, want %#x", typ, WireTypeResult)
	}
	if flags != 0 {
		t.Errorf("flags: got %#x, want 0", flags)
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("body: got %x, want %x", gotBody, body)
	}
}

func TestDecodeFrameRejectsTooShort(t *testing.T) {
	if _, _, _, err := DecodeFrame([]byte{0x01, 0x00, 0x05}); err == nil {
		t.Error("expected error for under-4-byte frame")
	}
}

func TestDecodeFrameRejectsTruncatedBody(t *testing.T) {
	// bodylen claims 10 but only 2 follow
	bad := []byte{0x01, 0x00, 0x0a, 0x00, 0xaa, 0xbb}
	if _, _, _, err := DecodeFrame(bad); err == nil {
		t.Error("expected error for truncated body")
	}
}

func TestDecodeRegisterBodyHappyPath(t *testing.T) {
	// Construct a REGISTER body matching docs/protocol/wire-v0.md
	body := []byte{}
	body = append(body, 0x04, 0x00) // hostname_len = 4
	body = append(body, []byte("HOST")...)
	body = append(body, 0x05, 0x00) // username_len = 5
	body = append(body, []byte("alice")...)
	body = append(body, 0x01)                   // arch = x64
	body = append(body, 0x39, 0x05, 0x00, 0x00) // pid = 1337
	body = append(body, 0xe8, 0x03, 0x00, 0x00) // sleep_ms = 1000

	reg, err := DecodeRegister(body)
	if err != nil {
		t.Fatalf("DecodeRegister: %v", err)
	}
	if reg.Hostname != "HOST" {
		t.Errorf("hostname: got %q, want HOST", reg.Hostname)
	}
	if reg.Username != "alice" {
		t.Errorf("username: got %q, want alice", reg.Username)
	}
	if reg.Arch != 0x01 {
		t.Errorf("arch: got %#x, want 0x01", reg.Arch)
	}
	if reg.Pid != 1337 {
		t.Errorf("pid: got %d, want 1337", reg.Pid)
	}
	if reg.SleepMs != 1000 {
		t.Errorf("sleep_ms: got %d, want 1000", reg.SleepMs)
	}
}

func TestDecodeRegisterRejectsTruncatedHostname(t *testing.T) {
	bad := []byte{0xff, 0x00, 0x41, 0x41}
	if _, err := DecodeRegister(bad); err == nil {
		t.Error("expected error for truncated hostname")
	}
}

func TestEncodeTaskBodyProducesCorrectLayout(t *testing.T) {
	// wire-v0 §"Worked example": task_id=1, cmd_id=CMD_WHOAMI(0x10), args_len=0
	// Expected body: 01 00 00 00  10  00 00
	cmdData := []byte{0x10, 0x00, 0x00}
	got := EncodeTaskBody(1, cmdData)
	want := []byte{0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeTaskBody: got %x, want %x", got, want)
	}
}

func TestDecodeResultBodyHappyPath(t *testing.T) {
	// wire-v0 §"Worked example" RESULT body: task_id=1, status=OK, data="WIN10\user12"
	resultBody := []byte{
		0x01, 0x00, 0x00, 0x00, // task_id = 1
		0x00,                   // status = OK
		0x0c, 0x00, 0x00, 0x00, // data_len = 12
		'W', 'I', 'N', '1', '0', '\\', 'u', 's', 'e', 'r', '1', '2',
	}
	taskId, status, data, err := DecodeResultBody(resultBody)
	if err != nil {
		t.Fatalf("DecodeResultBody: %v", err)
	}
	if taskId != 1 {
		t.Errorf("taskId: got %d, want 1", taskId)
	}
	if status != 0x00 {
		t.Errorf("status: got %#x, want 0x00", status)
	}
	if string(data) != `WIN10\user12` {
		t.Errorf("data: got %q, want %q", string(data), `WIN10\user12`)
	}
}

func TestDecodeResultBodyRejectsTooShort(t *testing.T) {
	if _, _, _, err := DecodeResultBody([]byte{0x01, 0x00, 0x00}); err == nil {
		t.Error("expected error for under-9-byte RESULT body")
	}
}

func TestDecodeResultBodyRejectsTruncatedData(t *testing.T) {
	// claims data_len = 100 but only 3 bytes follow
	bad := []byte{
		0x01, 0x00, 0x00, 0x00, // task_id
		0x00,                   // status
		0x64, 0x00, 0x00, 0x00, // data_len = 100
		0xAA, 0xBB, 0xCC,       // only 3 bytes
	}
	if _, _, _, err := DecodeResultBody(bad); err == nil {
		t.Error("expected error for truncated data field")
	}
}
