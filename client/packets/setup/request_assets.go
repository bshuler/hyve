package setup

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hypot/client/packets"
)

const (
	RequestAssetsPacketId = 23
)

type RequestAssets struct {
	// TODO: Assets
}

func NewRequestAssetsPacket() *RequestAssets {
	return &RequestAssets{}
}

func (c *RequestAssets) Encode() ([]byte, error) {
	const fixedSize = 1

	var variable bytes.Buffer
	var fixed bytes.Buffer

	fixed.WriteByte(0b0000)

	if fixed.Len() != fixedSize {
		return nil, fmt.Errorf("fixed block must be %d bytes, got %d", fixedSize, fixed.Len())
	}

	payload := append(fixed.Bytes(), variable.Bytes()...)

	compressed := packets.CompressZstd(payload)
	if len(compressed) == 0 {
		return nil, fmt.Errorf("zstd produced empty payload")
	}

	var frame bytes.Buffer

	binary.Write(&frame, binary.LittleEndian, uint32(len(compressed)))
	binary.Write(&frame, binary.LittleEndian, uint32(RequestAssetsPacketId))
	frame.Write(compressed)

	return frame.Bytes(), nil
}
