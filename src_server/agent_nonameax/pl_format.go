package main

import (
	"encoding/binary"
	"fmt"
)

// win32ErrorName returns the symbolic name of a common Win32 error code.
func win32ErrorName(code uint32) string {
	switch code {
	case 1:
		return "ERROR_INVALID_FUNCTION"
	case 2:
		return "ERROR_FILE_NOT_FOUND"
	case 3:
		return "ERROR_PATH_NOT_FOUND"
	case 4:
		return "ERROR_TOO_MANY_OPEN_FILES"
	case 5:
		return "ERROR_ACCESS_DENIED"
	case 6:
		return "ERROR_INVALID_HANDLE"
	case 15:
		return "ERROR_INVALID_DRIVE"
	case 17:
		return "ERROR_NOT_SAME_DEVICE"
	case 18:
		return "ERROR_NO_MORE_FILES"
	case 19:
		return "ERROR_WRITE_PROTECT"
	case 32:
		return "ERROR_SHARING_VIOLATION"
	case 33:
		return "ERROR_LOCK_VIOLATION"
	case 80:
		return "ERROR_FILE_EXISTS"
	case 87:
		return "ERROR_INVALID_PARAMETER"
	case 112:
		return "ERROR_DISK_FULL"
	case 123:
		return "ERROR_INVALID_NAME"
	case 145:
		return "ERROR_DIR_NOT_EMPTY"
	case 183:
		return "ERROR_ALREADY_EXISTS"
	case 206:
		return "ERROR_FILENAME_EXCED_RANGE"
	case 267:
		return "ERROR_DIRECTORY"
	default:
		return "unknown"
	}
}

/* ========= [ shared wire helpers ] ========= */

func readLenPrefixedStringGo(data []byte, cursor int) (string, int) {
	if cursor+2 > len(data) {
		return "", cursor
	}
	n := int(binary.LittleEndian.Uint16(data[cursor : cursor+2]))
	cursor += 2
	if cursor+n > len(data) {
		return "", cursor
	}
	s := string(data[cursor : cursor+n])
	cursor += n
	return s, cursor
}

// naxOsVersion maps PEB major/minor/build to a human-readable OS string.
func naxOsVersion(major, minor uint32, build uint16, arch string) string {
	ver := "unknown"
	b := uint32(build)
	switch {
	case major == 10 && minor == 0 && b >= 22000:
		ver = "Win 11"
	case major == 10 && minor == 0 && b >= 19045:
		ver = "Win 10"
	case major == 10 && minor == 0:
		ver = "Win 10"
	case major == 6 && minor == 3:
		ver = "Win 8.1"
	case major == 6 && minor == 2:
		ver = "Win 8"
	case major == 6 && minor == 1:
		ver = "Win 7"
	}
	return fmt.Sprintf("%s %s (Build %d)", ver, arch, build)
}

/* ========= [ BOF helpers ] ========= */

func packBofArgs(spec string) ([]byte, error) {
	if spec == "" {
		return nil, nil
	}
	packer := NewBofPacker()
	for _, part := range splitArgs(spec) {
		idx := 0
		for idx < len(part) && part[idx] != ':' {
			idx++
		}
		var typ, val string
		if idx >= len(part) {
			typ = "str"
			val = part
		} else {
			typ = part[:idx]
			val = part[idx+1:]
		}
		switch typ {
		case "str":
			packer.AddStr(val)
		case "wstr":
			packer.AddWStr(val)
		case "int":
			var n int64
			if _, err := fmt.Sscan(val, &n); err != nil {
				return nil, fmt.Errorf("int arg %q: %w", val, err)
			}
			packer.AddInt(int32(n))
		case "short":
			var n int64
			if _, err := fmt.Sscan(val, &n); err != nil {
				return nil, fmt.Errorf("short arg %q: %w", val, err)
			}
			packer.AddShort(int16(n))
		default:
			return nil, fmt.Errorf("unknown arg type %q", typ)
		}
	}
	return packer.Bytes(), nil
}

func splitArgs(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
