package connection

import (
	"bytes"
	"encoding/binary"
	"github.com/bshuler/hyve/client/packets"
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
	binary.Write(&frame, binary.LittleEndian, uint32(packets.DisconnectPacketId))
	frame.Write(payload.Bytes())

	return frame.Bytes(), nil
}
