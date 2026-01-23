package packets

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Pong struct {
	Id int32
}

func NewPongPacket(id int32) *Pong {
	return &Pong{Id: id}
}

func (p *Pong) Encode() ([]byte, error) {
	var payload bytes.Buffer
	payload.WriteByte(0x00)
	if err := binary.Write(&payload, binary.LittleEndian, p.Id); err != nil {
		return nil, err
	}

	payload.Write(make([]byte, 12)) // time
	payload.WriteByte(0x00)
	if err := binary.Write(&payload, binary.LittleEndian, int16(0)); err != nil {
		return nil, err
	}
	if payload.Len() != 20 {
		return nil, fmt.Errorf("pong payload must be 20 bytes, got %d", payload.Len())
	}

	var frame bytes.Buffer
	if err := binary.Write(&frame, binary.LittleEndian, uint32(payload.Len())); err != nil {
		return nil, err
	}
	if err := binary.Write(&frame, binary.LittleEndian, uint32(PongPacketId)); err != nil {
		return nil, err
	}
	if _, err := frame.Write(payload.Bytes()); err != nil {
		return nil, err
	}

	return frame.Bytes(), nil
}
