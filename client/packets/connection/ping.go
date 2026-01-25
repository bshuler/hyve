package connection

import (
	"encoding/binary"
)

type InstantData [12]byte

type Ping struct {
	Id                int32
	Time              *InstantData
	LastPingValueRaw  int32
	LastPingValueDir  int32
	LastPingValueTick int32
}

func DecodePing(data []byte) (*Ping, error) {
	out := &Ping{}
	nullBits := data[0]

	out.Id = int32(binary.LittleEndian.Uint32(data[1:5]))
	if (nullBits & 0x01) != 0 {
		t := new(InstantData)
		copy(t[:], data[5:17])
		out.Time = t
	}

	out.LastPingValueRaw = int32(binary.LittleEndian.Uint32(data[17:21]))
	out.LastPingValueDir = int32(binary.LittleEndian.Uint32(data[21:25]))
	out.LastPingValueTick = int32(binary.LittleEndian.Uint32(data[25:29]))

	return out, nil
}
