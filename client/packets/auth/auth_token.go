package auth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hypot/client/packets"
)

const (
	AuthPacketId = 12
)

type AuthToken struct {
	AccessToken              string
	ServerAuthorizationGrant string
}

func NewAuthTokenPacket(
	accessToken string,
	serverAuthorizationGrant string,
) *AuthToken {
	return &AuthToken{
		AccessToken:              accessToken,
		ServerAuthorizationGrant: serverAuthorizationGrant,
	}
}

func (c *AuthToken) Encode() ([]byte, error) {
	const fixedSize = 9

	var variable bytes.Buffer
	var fixed bytes.Buffer

	accessTokenOffset := uint32(variable.Len())
	packets.WriteVarInt(&variable, len(c.AccessToken))
	variable.WriteString(c.AccessToken)

	serverAuthorizationGrantOffset := uint32(variable.Len())
	packets.WriteVarInt(&variable, len(c.ServerAuthorizationGrant))
	variable.WriteString(c.ServerAuthorizationGrant)

	fixed.WriteByte(0b0011)
	binary.Write(&fixed, binary.LittleEndian, accessTokenOffset)
	binary.Write(&fixed, binary.LittleEndian, serverAuthorizationGrantOffset)

	if fixed.Len() != fixedSize {
		return nil, fmt.Errorf("fixed block must be %d bytes, got %d", fixedSize, fixed.Len())
	}

	payload := append(fixed.Bytes(), variable.Bytes()...)

	var frame bytes.Buffer

	binary.Write(&frame, binary.LittleEndian, uint32(len(payload)))
	binary.Write(&frame, binary.LittleEndian, uint32(AuthPacketId))
	frame.Write(payload)

	return frame.Bytes(), nil
}
