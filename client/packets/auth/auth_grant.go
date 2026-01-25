package auth

import (
	"encoding/binary"
	"errors"
	"hypot/client/packets"
)

type AuthGrant struct {
	AuthorizationGrant  *string
	ServerIdentityToken *string
}

func DecodeAuthGrant(data []byte) (*AuthGrant, error) {
	nullBits := data[0]

	authOff := int(int32(binary.LittleEndian.Uint32(data[1:5])))
	srvOff := int(int32(binary.LittleEndian.Uint32(data[5:9])))

	base := 9
	out := &AuthGrant{}

	if (nullBits&0x01) != 0 && authOff != -1 {
		s, _, ok := packets.ReadVarString(data, base+authOff)
		if !ok {
			return nil, errors.New("invalid auth grant")
		}
		out.AuthorizationGrant = &s
	}

	if (nullBits&0x02) != 0 && srvOff != -1 {
		s, _, ok := packets.ReadVarString(data, base+srvOff)
		if !ok {
			return nil, errors.New("invalid server identity")
		}
		out.ServerIdentityToken = &s
	}

	return out, nil
}
