package interface_

import (
	"encoding/binary"
	"errors"
	"hypot/client/packets"

	"github.com/google/uuid"
)

const (
	AddToServerPlayerListPacketId = 224
)

type ServerListPlayer struct {
	Id       uuid.UUID
	WorldId  *uuid.UUID // optional
	Ping     int32
	Username string
}

type AddToServerPlayerList struct {
	PlayerCount uint32
	Players     []ServerListPlayer
}

func DecodeAddToServerPlayerList(data []byte) (*AddToServerPlayerList, error) {
	nullBits := data[0]
	off := 1

	out := &AddToServerPlayerList{}

	if (nullBits & 0x1) == 0 {
		return out, nil
	}

	playerCount, newoff, ok := packets.ReadVarInt(data, off)
	if !ok || playerCount < 0 {
		return nil, errors.New("packets were decoding: invalid packet count")
	}
	off = newoff
	out.PlayerCount = uint32(playerCount)

	out.Players = make([]ServerListPlayer, 0, playerCount)
	for i := 0; i < playerCount; i++ {
		if off+37 > len(data) {
			return nil, errors.New("packets were decoding: invalid packet length")
		}

		pn := data[off] // null bits
		off++

		id, newoff, ok := packets.ReadUUID16(data, off)
		if !ok {
			return nil, errors.New("packets were decoding: invalid packet uuid")
		}
		off = newoff

		wr, newoff, ok := packets.ReadUUID16(data, off) // world
		if !ok {
			return nil, errors.New("packets were decoding: invalid packet uuid")
		}
		off = newoff

		ping := int32(binary.LittleEndian.Uint32(data[off : off+4]))
		off += 4

		player := ServerListPlayer{
			Id:   id,
			Ping: ping,
		}

		if (pn & 0x02) != 0 {
			tmp := uuid.UUID(wr)
			player.WorldId = &tmp
		}

		if (pn & 0x01) != 0 {
			u, newoff, ok := packets.ReadVarString(data, off)
			if !ok {
				return nil, errors.New("packets were decoding: invalid packet uuid")
			}
			off = newoff
			player.Username = u
		}

		out.Players = append(out.Players, player)
	}

	return out, nil
}
