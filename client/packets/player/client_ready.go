package player

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const ClientReadyPacketId = 105

type ClientReady struct {
	ReadyForChunks   bool
	ReadyForGameplay bool
}

func NewClientReadyPacket(readyForChunks, readyForGameplay bool) *ClientReady {
	return &ClientReady{ReadyForChunks: readyForChunks, ReadyForGameplay: readyForGameplay}
}

func (c *ClientReady) Encode() ([]byte, error) {
	const fixedSize = 2

	var payload bytes.Buffer
	if c.ReadyForChunks {
		payload.WriteByte(0x01)
	} else {
		payload.WriteByte(0x00)
	}
	if c.ReadyForGameplay {
		payload.WriteByte(0x01)
	} else {
		payload.WriteByte(0x00)
	}

	if payload.Len() != fixedSize {
		return nil, fmt.Errorf("payload must be %d bytes, got %d", fixedSize, payload.Len())
	}

	var frame bytes.Buffer
	_ = binary.Write(&frame, binary.LittleEndian, uint32(payload.Len()))
	_ = binary.Write(&frame, binary.LittleEndian, uint32(ClientReadyPacketId))
	_, _ = frame.Write(payload.Bytes())
	return frame.Bytes(), nil
}
