package packets

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/google/uuid"
)

const (
	ClientTypeGame = iota
	ClientTypeEditor
)

const (
	ProtocolHash = "6708f121966c1c443f4b0eb525b2f81d0a8dc61f5003a692a8fa157e5e02cea9"
)

type Connect struct {
	uuid          uuid.UUID
	username      string
	identityToken string
}

func NewConnectPacket(
	uuid uuid.UUID,
	identityToken string,
	username string,
) *Connect {
	return &Connect{
		uuid:          uuid,
		username:      username,
		identityToken: identityToken,
	}
}

func (c *Connect) Encode() ([]byte, error) {
	const fixedSize = 102

	var variable bytes.Buffer
	var fixed bytes.Buffer

	identityTokenOffset := uint32(variable.Len())
	writeVarInt(&variable, len(c.identityToken))
	variable.WriteString(c.identityToken)

	usernameOffset := uint32(variable.Len())
	writeVarInt(&variable, len(c.username))
	variable.WriteString(c.username)

	fixed.WriteByte(0b0010)

	var ph [64]byte
	copy(ph[:], ProtocolHash)
	fixed.Write(ph[:])

	fixed.WriteByte(ClientTypeGame)
	fixed.Write(c.uuid[:])

	binary.Write(&fixed, binary.LittleEndian, int32(-1))
	binary.Write(&fixed, binary.LittleEndian, identityTokenOffset)
	binary.Write(&fixed, binary.LittleEndian, usernameOffset)
	binary.Write(&fixed, binary.LittleEndian, int32(-1))
	binary.Write(&fixed, binary.LittleEndian, int32(-1))

	if fixed.Len() != fixedSize {
		return nil, fmt.Errorf("fixed block must be %d bytes, got %d", fixedSize, fixed.Len())
	}

	payload := append(fixed.Bytes(), variable.Bytes()...)

	var frame bytes.Buffer

	binary.Write(&frame, binary.LittleEndian, uint32(len(payload)))
	binary.Write(&frame, binary.LittleEndian, uint32(ConnectPacketId))
	frame.Write(payload)

	return frame.Bytes(), nil
}
