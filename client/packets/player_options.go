package packets

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	PlayerOptionsPacketId = 33
)

type PlayerOptions struct {
	// TODO: Assets
}

func NewPlayerOptionsPacket() *PlayerOptions {
	return &PlayerOptions{}
}

func (c *PlayerOptions) Encode() ([]byte, error) {
	const fixedSize = 1

	var variable bytes.Buffer
	var fixed bytes.Buffer

	fixed.WriteByte(0b0000)

	if fixed.Len() != fixedSize {
		return nil, fmt.Errorf("fixed block must be %d bytes, got %d", fixedSize, fixed.Len())
	}

	payload := append(fixed.Bytes(), variable.Bytes()...)

	var frame bytes.Buffer

	binary.Write(&frame, binary.LittleEndian, uint32(len(payload)))
	binary.Write(&frame, binary.LittleEndian, uint32(PlayerOptionsPacketId))
	frame.Write(payload)

	return frame.Bytes(), nil
}
