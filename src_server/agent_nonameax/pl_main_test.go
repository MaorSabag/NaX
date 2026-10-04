package main

import (
	"testing"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
	"nonameax/naxwire"
)

func TestInitPluginReturnsNonNilAgent(t *testing.T) {
	got := InitPlugin(stubTeamserver{}, "/tmp/nonameax-test", "no4a4178")
	if got == nil {
		t.Fatal("InitPlugin returned nil")
	}
}

type stubTeamserver struct{ adaptix.Teamserver }

func (s stubTeamserver) TsExtenderDataKeys(name string) ([]string, error)           { return nil, nil }
func (s stubTeamserver) TsExtenderDataLoad(name, key string) ([]byte, error)         { return nil, nil }
func (s stubTeamserver) TsExtenderDataSave(name, key string, data []byte) error      { return nil }
func (s stubTeamserver) TsExtenderDataDelete(name, key string) error                 { return nil }
func (s stubTeamserver) TsEventHookRegister(eventType, name string, phase, priority int, handler func(event any) error) string {
	return ""
}
func (s stubTeamserver) TsLogAdd(status adaptix.LogStatus, level int, source, category string, format string, args ...any) {
}
func (s stubTeamserver) TsTaskUpdate(agentId int64, data adaptix.TaskData)                         {}
func (s stubTeamserver) TsTaskCreate(agentId int64, cmdline string, client string, data adaptix.TaskData) {
}
func (s stubTeamserver) TsAgentConsoleOutput(agentId int64, client string, messageType int, message string, clearText string, store bool) {
}
func (s stubTeamserver) TsAgentUpdateData(data adaptix.AgentData) error          { return nil }
func (s stubTeamserver) TsAgentUpdateDataPartial(agentId int64, data any) error  { return nil }
func (s stubTeamserver) TsConvertCpToUTF8(input string, codePage int) string     { return input }
func (s stubTeamserver) TsConvertUTF8toCp(input string, codePage int) string     { return input }
func (s stubTeamserver) TsFileGenID() int64                                      { return 1 }
func (s stubTeamserver) TsTaskGenID() int64                                      { return 1 }

// --- Phase 2a: CreateAgent tests ---

func TestCreateAgentPopulatesFromRegisterFrame(t *testing.T) {
	body := []byte{}
	body = append(body, 0x04, 0x00)
	body = append(body, []byte("HOST")...)
	body = append(body, 0x05, 0x00)
	body = append(body, []byte("alice")...)
	body = append(body, 0x01)
	body = append(body, 0x39, 0x05, 0x00, 0x00) // pid = 1337
	body = append(body, 0xe8, 0x03, 0x00, 0x00) // sleep_ms = 1000

	frame := naxwire.EncodeFrame(naxwire.WireTypeRegister, body)

	testKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	encrypted, err := naxwire.EncryptCBCRandomIV(testKey, frame)
	if err != nil {
		t.Fatalf("EncryptCBC: %v", err)
	}

	const fakeBeaconID = "deadbeef12345678"
	beat := append([]byte(fakeBeaconID), testKey...)
	beat = append(beat, encrypted...)

	p := &PluginAgent{}
	ad, fn, err := p.CreateAgent(beat)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if fn.ProcessData == nil {
		t.Error("AgentFunctions.ProcessData must not be nil")
	}
	if string(ad.UID) != fakeBeaconID {
		t.Errorf("UID: got %q, want %q", string(ad.UID), fakeBeaconID)
	}
	if ad.Computer != "HOST" {
		t.Errorf("Computer: got %q, want HOST", ad.Computer)
	}
	if ad.Username != "alice" {
		t.Errorf("Username: got %q, want alice", ad.Username)
	}
	if ad.Pid != "1337" {
		t.Errorf("Pid: got %q, want 1337", ad.Pid)
	}
	if ad.Arch != "x64" {
		t.Errorf("Arch: got %q, want x64", ad.Arch)
	}
	if ad.Sleep != 1 {
		// sleep_ms = 1000 → Sleep in seconds = 1
		t.Errorf("Sleep: got %d, want 1", ad.Sleep)
	}
}

func TestCreateAgentAcceptsHeartbeatAsReregister(t *testing.T) {
	frame := naxwire.EncodeFrame(naxwire.WireTypeHeartbeat, nil)

	testKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	encrypted, _ := naxwire.EncryptCBCRandomIV(testKey, frame)

	beat := append([]byte("deadbeef12345678"), testKey...)
	beat = append(beat, encrypted...)
	p := &PluginAgent{}
	ad, fn, err := p.CreateAgent(beat)
	if err != nil {
		t.Errorf("HEARTBEAT re-register must not return error, got: %v", err)
	}
	if string(ad.UID) != "deadbeef12345678" {
		t.Errorf("UID: got %q, want deadbeef12345678", string(ad.UID))
	}
	if fn.ProcessData == nil {
		t.Error("AgentFunctions.ProcessData must not be nil")
	}
}

// --- Phase 2a: ProcessData + identity crypto tests ---

func TestProcessDataAcceptsHeartbeat(t *testing.T) {
	frame := naxwire.EncodeFrame(naxwire.WireTypeHeartbeat, nil)
	if err := naxProcessData(adaptix.AgentData{}, frame); err != nil {
		t.Errorf("HEARTBEAT should not error: %v", err)
	}
}

func TestProcessDataIgnoresDuplicateRegister(t *testing.T) {
	frame := naxwire.EncodeFrame(naxwire.WireTypeRegister, []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0})
	if err := naxProcessData(adaptix.AgentData{}, frame); err != nil {
		t.Errorf("duplicate REGISTER should be ignored, not errored: %v", err)
	}
}

func TestProcessDataAcceptsResultStub(t *testing.T) {
	frame := naxwire.EncodeFrame(naxwire.WireTypeResult, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err := naxProcessData(adaptix.AgentData{}, frame); err != nil {
		t.Errorf("RESULT is a no-op in Phase 2 (Phase 3 implements); got error: %v", err)
	}
}

func TestProcessDataRejectsUnknownType(t *testing.T) {
	// 0x55 is in the reserved range and not used by v0
	frame := naxwire.EncodeFrame(0x55, nil)
	if err := naxProcessData(adaptix.AgentData{}, frame); err == nil {
		t.Error("expected error for unknown message type")
	}
}

func TestProcessDataRejectsCorruptFrame(t *testing.T) {
	if err := naxProcessData(adaptix.AgentData{}, []byte{0x02, 0x00}); err == nil {
		t.Error("expected error for under-4-byte frame")
	}
}

func TestEncryptIsIdentity(t *testing.T) {
	data := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	got, err := naxEncrypt(data, []byte("ignored-key"))
	if err != nil {
		t.Fatalf("Encrypt should not error: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("Encrypt must be identity (listener owns AES): got %x, want %x", got, data)
	}
}

func TestDecryptIsIdentity(t *testing.T) {
	data := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	got, err := naxDecrypt(data, []byte("ignored-key"))
	if err != nil {
		t.Fatalf("Decrypt should not error: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("Decrypt must be identity (listener owns AES): got %x, want %x", got, data)
	}
}
