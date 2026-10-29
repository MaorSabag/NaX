package main

import (
	"encoding/binary"

	adaptix "github.com/Adaptix-Framework/axc2/v2"
)

/* ========= [ tunnel wire constants ] ========= */

const (
	tunnelCmdConnectTCP byte = 0x3E
	tunnelCmdWriteTCP   byte = 0x40
	tunnelCmdClose      byte = 0x42
	tunnelCmdReverse    byte = 0x43
	tunnelCmdAccept     byte = 0x44
	tunnelCmdPause      byte = 0x45
	tunnelCmdResume     byte = 0x46
	STATUS_TUNNEL byte = 0x20
)

/* ========= [ task builder ] ========= */

func tunnelTask(cmdId byte, args []byte, prio uint) adaptix.TaskData {
	buf := make([]byte, 5+len(args))
	buf[0] = cmdId
	binary.LittleEndian.PutUint32(buf[1:5], uint32(len(args)))
	copy(buf[5:], args)
	return adaptix.MakeProxyTask(buf, prio)
}

/* ========= [ TunnelCallbacks ] ========= */

func tunnelConnectTCP(channelId int64, tunnelType, addressType int, address string, port int) adaptix.TaskData {
	addrBytes := []byte(address)
	args := make([]byte, 4+4+4+len(addrBytes)+4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(tunnelType))
	binary.LittleEndian.PutUint32(args[8:12], uint32(len(addrBytes)))
	copy(args[12:12+len(addrBytes)], addrBytes)
	binary.LittleEndian.PutUint32(args[12+len(addrBytes):], uint32(port))
	return tunnelTask(tunnelCmdConnectTCP, args, priorityTunnelCreate)
}

func tunnelConnectUDP(channelId int64, tunnelType, addressType int, address string, port int) adaptix.TaskData {
	return adaptix.TaskData{}
}

func tunnelWriteTCP(channelId int64, data []byte) adaptix.TaskData {
	args := make([]byte, 4+4+len(data))
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(len(data)))
	copy(args[8:], data)
	return tunnelTask(tunnelCmdWriteTCP, args, priorityTunnelData)
}

func tunnelWriteUDP(channelId int64, data []byte) adaptix.TaskData {
	return adaptix.TaskData{}
}

func tunnelPause(channelId int64) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(tunnelCmdPause, args, priorityTunnelCreate)
}

func tunnelResume(channelId int64) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(tunnelCmdResume, args, priorityTunnelCreate)
}

func tunnelClose(channelId int64) adaptix.TaskData {
	args := make([]byte, 4)
	binary.LittleEndian.PutUint32(args[0:4], uint32(channelId))
	return tunnelTask(tunnelCmdClose, args, priorityTunnelClose)
}

func tunnelReverse(tunnelId int64, port int) adaptix.TaskData {
	args := make([]byte, 8)
	binary.LittleEndian.PutUint32(args[0:4], uint32(tunnelId))
	binary.LittleEndian.PutUint32(args[4:8], uint32(port))
	return tunnelTask(tunnelCmdReverse, args, priorityTunnelCreate)
}

/* ========= [ result parser ] ========= */

func processTunnelResult(agentId int64, data []byte) {
	off := 0
	for off+8 <= len(data) {
		entryLen := int(binary.LittleEndian.Uint32(data[off : off+4]))
		if entryLen < 4 || off+4+entryLen > len(data) {
			break
		}
		cmdId := binary.LittleEndian.Uint32(data[off+4 : off+8])
		payload := data[off+8 : off+4+entryLen]

		switch byte(cmdId) {

		case tunnelCmdConnectTCP:
			if len(payload) < 12 {
				break
			}
			channelId := int64(binary.LittleEndian.Uint32(payload[0:4]))
			result := binary.LittleEndian.Uint32(payload[8:12])
			if Ts != nil {
				if result == 0 {
					Ts.TsTunnelConnectionResume(agentId, channelId, false)
				} else {
					Ts.TsTunnelConnectionClose(channelId, false)
				}
			}

		case tunnelCmdWriteTCP:
			if len(payload) < 8 {
				break
			}
			channelId := int64(binary.LittleEndian.Uint32(payload[0:4]))
			dataLen := int(binary.LittleEndian.Uint32(payload[4:8]))
			if len(payload) < 8+dataLen {
				break
			}
			if Ts != nil {
				Ts.TsTunnelConnectionData(channelId, payload[8:8+dataLen])
			}

		case tunnelCmdClose:
			if len(payload) < 12 {
				break
			}
			channelId := int64(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelConnectionClose(channelId, false)
			}

		case tunnelCmdReverse:
			if len(payload) < 12 {
				break
			}
			tunnelId := int64(binary.LittleEndian.Uint32(payload[0:4]))
			result := binary.LittleEndian.Uint32(payload[8:12])
			if Ts != nil {
				Ts.TsTunnelUpdateRportfwd(tunnelId, result != 0)
			}

		case tunnelCmdAccept:
			if len(payload) < 8 {
				break
			}
			tunnelId := int64(binary.LittleEndian.Uint32(payload[0:4]))
			newChannelId := int64(binary.LittleEndian.Uint32(payload[4:8]))
			if Ts != nil {
				Ts.TsTunnelConnectionAccept(tunnelId, newChannelId)
			}

		case tunnelCmdPause:
			if len(payload) < 4 {
				break
			}
			channelId := int64(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelPause(channelId)
			}

		case tunnelCmdResume:
			if len(payload) < 4 {
				break
			}
			channelId := int64(binary.LittleEndian.Uint32(payload[0:4]))
			if Ts != nil {
				Ts.TsTunnelResume(channelId)
			}

		default:
			naxLogErr("tunnel: unknown cmdId 0x%02x", cmdId)
		}

		off += 4 + entryLen
	}

	if off < len(data) {
		naxLogErr("tunnel: %d trailing bytes in result", len(data)-off)
	}
}
