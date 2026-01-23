package packets

import (
	"bytes"
	"encoding/binary"
)

type Disconnect struct{}

func NewDisconnectPacket() *Connect {
	return &Connect{}
}

func (c *Disconnect) Encode() ([]byte, error) {
	var payload bytes.Buffer
	payload.WriteByte(0x00) // no reason
	payload.WriteByte(0x00) // disconnect

	var frame bytes.Buffer

	binary.Write(&frame, binary.LittleEndian, uint32(payload.Len()))
	binary.Write(&frame, binary.LittleEndian, uint32(DisconnectPacketId))
	frame.Write(payload.Bytes())

	return frame.Bytes(), nil
}
