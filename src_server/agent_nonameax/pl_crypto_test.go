package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Golden vectors - generated with openssl enc -aes-128-cbc, see ADR-002.
// All hex below was produced by running the openssl command in
// docs/superpowers/plans/2026-05-29-phase-2a-server-side-register.md
// Task 2a.2 Step 1 against the project's pinned key/IV/plaintext.
var goldenKey = mustHex("000102030405060708090a0b0c0d0e0f")
var goldenIV = mustHex("101112131415161718191a1b1c1d1e1f")
var goldenPlain = mustHex("02000000")
var goldenCipher = mustHex("e4ef371bff385eece8fea125f86bbd77")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncryptCBCMatchesGolden(t *testing.T) {
	got, err := EncryptCBC(goldenKey, goldenIV, goldenPlain)
	if err != nil {
		t.Fatalf("EncryptCBC: %v", err)
	}
	if !bytes.Equal(got[:16], goldenIV) {
		t.Errorf("IV prefix mismatch: got %x, want %x", got[:16], goldenIV)
	}
	if !bytes.Equal(got[16:], goldenCipher) {
		t.Errorf("ciphertext mismatch: got %x, want %x", got[16:], goldenCipher)
	}
}

func TestDecryptCBCRoundTrip(t *testing.T) {
	envelope, err := EncryptCBC(goldenKey, goldenIV, goldenPlain)
	if err != nil {
		t.Fatalf("EncryptCBC: %v", err)
	}
	got, err := DecryptCBC(goldenKey, envelope)
	if err != nil {
		t.Fatalf("DecryptCBC: %v", err)
	}
	if !bytes.Equal(got, goldenPlain) {
		t.Errorf("round-trip mismatch: got %x, want %x", got, goldenPlain)
	}
}

func TestDecryptCBCRejectsTooShort(t *testing.T) {
	if _, err := DecryptCBC(goldenKey, []byte("short")); err == nil {
		t.Error("expected error for envelope shorter than IV")
	}
}

func TestDecryptCBCRejectsBadPadding(t *testing.T) {
	envelope, _ := EncryptCBC(goldenKey, goldenIV, goldenPlain)
	envelope[len(envelope)-1] ^= 0x01
	if _, err := DecryptCBC(goldenKey, envelope); err == nil {
		t.Error("expected error after corrupting last ciphertext byte (PKCS#7 padding will be invalid)")
	}
}

func TestEncryptCBCRandomIVDoesNotMatchGolden(t *testing.T) {
	a, err := EncryptCBCRandomIV(goldenKey, goldenPlain)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := EncryptCBCRandomIV(goldenKey, goldenPlain)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two random-IV encryptions of the same plaintext should differ")
	}
	pa, _ := DecryptCBC(goldenKey, a)
	pb, _ := DecryptCBC(goldenKey, b)
	if !bytes.Equal(pa, goldenPlain) || !bytes.Equal(pb, goldenPlain) {
		t.Error("round trip via random IV failed")
	}
}
