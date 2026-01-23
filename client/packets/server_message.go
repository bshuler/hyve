package packets

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ServerMessagePacketID = 210
)

type ServerMessage struct {
	Username string
	Message  string
}

// so many fields so im just extracting a simplified version with username and message only

func DecodeServerMessage(payload []byte) (msg *ServerMessage, ok bool, err error) {
	if len(payload) < 2 {
		return nil, false, errors.New("ServerMessage: too short")
	}

	nullBits := payload[0]
	off := 2

	// message present?
	if (nullBits & 0x01) == 0 {
		return nil, false, nil
	}

	// ---- FormattedMessage header (34 bytes) ----
	if off+34 > len(payload) {
		return nil, false, errors.New("FormattedMessage: too short")
	}

	fNull := payload[off]
	varBase := off + 34

	out := &ServerMessage{}

	// rawText fallback (rare for chat, but cheap to try)
	if (fNull & 0x01) != 0 {
		rawOff := int(int32(binary.LittleEndian.Uint32(payload[off+6 : off+10])))
		p := varBase + rawOff
		s, _, ok := readVarString(payload, p)
		if ok && s != "" {
			out.Message = s
			return out, true, nil
		}
	}

	// messageId (needed for normal chat)
	var msgID string
	if (fNull & 0x02) != 0 {
		msgOff := int(int32(binary.LittleEndian.Uint32(payload[off+10 : off+14])))
		p := varBase + msgOff
		s, _, ok := readVarString(payload, p)
		if !ok {
			return nil, false, fmt.Errorf("FormattedMessage: bad messageId")
		}
		msgID = s
	}

	if msgID != "server.chat.playerMessage" && msgID != "server.chat.broadcastMessage" {
		return nil, false, nil
	}

	// params dict (bit3)
	if (fNull & 0x08) == 0 {
		return nil, false, errors.New("FormattedMessage: expected params for chat messageId")
	}
	paramsOff := int(int32(binary.LittleEndian.Uint32(payload[off+18 : off+22])))
	pos := varBase + paramsOff
	if pos < 0 || pos > len(payload) {
		return nil, false, errors.New("FormattedMessage: bad params offset")
	}

	dictLen, pos2, ok := readVarInt(payload, pos)
	if !ok || dictLen < 0 {
		return nil, false, errors.New("FormattedMessage: bad params count")
	}
	pos = pos2

	var gotUser, gotMsg bool

	for i := 0; i < dictLen; i++ {
		key, pos2, ok := readVarString(payload, pos)
		if !ok {
			return nil, false, errors.New("FormattedMessage: bad params key")
		}
		pos = pos2

		typeID, pos2, ok := readVarInt(payload, pos)
		if !ok || typeID < 0 {
			return nil, false, errors.New("FormattedMessage: bad ParamValue typeId")
		}
		pos = pos2

		switch typeID {
		case 0: // StringParamValue: [nullBits u8][value? varstring]
			if pos+1 > len(payload) {
				return nil, false, errors.New("StringParamValue: too short")
			}
			nb := payload[pos]
			pos++

			val := ""
			if (nb & 0x01) != 0 {
				val, pos2, ok = readVarString(payload, pos)
				if !ok {
					return nil, false, errors.New("StringParamValue: bad value")
				}
				pos = pos2
			}

			if key == "username" {
				out.Username = val
				gotUser = true
			} else if key == "message" {
				out.Message = val
				gotMsg = true
			}

		case 1: // BoolParamValue: 1 byte
			if pos+1 > len(payload) {
				return nil, false, errors.New("BoolParamValue: too short")
			}
			pos += 1

		case 2: // DoubleParamValue: 8 bytes LE
			if pos+8 > len(payload) {
				return nil, false, errors.New("DoubleParamValue: too short")
			}
			pos += 8

		case 3: // IntParamValue: 4 bytes LE
			if pos+4 > len(payload) {
				return nil, false, errors.New("IntParamValue: too short")
			}
			pos += 4

		case 4: // LongParamValue: 8 bytes LE
			if pos+8 > len(payload) {
				return nil, false, errors.New("LongParamValue: too short")
			}
			pos += 8

		default:
			return nil, false, fmt.Errorf("ParamValue: unknown typeId=%d", typeID)
		}

		if gotUser && gotMsg {
			return out, true, nil
		}
	}

	return out, gotUser || gotMsg, nil
}
