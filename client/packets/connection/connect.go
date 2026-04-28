package connection

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/bshuler/hyve/client/packets"

	"github.com/google/uuid"
)

const (
	ClientTypeGame   = 0
	ClientTypeEditor = 1
)

const (
	ProtocolCRC         = 1789265863
	ProtocolBuildNumber = 2
)

type HostAddress struct {
	Host string
	Port uint16
}

func (h *HostAddress) Encode() []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, h.Port)
	packets.WriteVarInt(&buf, len(h.Host))
	buf.WriteString(h.Host)
	return buf.Bytes()
}

type Connect struct {
	uuid           uuid.UUID
	username       string
	identityToken  *string
	language       string
	referralData   []byte
	referralSource *HostAddress
}

func NewConnectPacket(
	uuid uuid.UUID,
	username string,
	identityToken *string,
	language string,
	referralData []byte,
	referralSource *HostAddress,
) *Connect {
	if language == "" {
		language = "en"
	}
	return &Connect{
		uuid:           uuid,
		username:       username,
		identityToken:  identityToken,
		language:       language,
		referralData:   referralData,
		referralSource: referralSource,
	}
}

func (c *Connect) Encode() ([]byte, error) {
	var variable bytes.Buffer
	var fixed bytes.Buffer

	var nullBits byte = 0
	if c.identityToken != nil {
		nullBits |= 0x01
	}
	if c.referralData != nil {
		nullBits |= 0x02
	}
	if c.referralSource != nil {
		nullBits |= 0x04
	}

	fixed.WriteByte(nullBits)
	binary.Write(&fixed, binary.LittleEndian, int32(ProtocolCRC))
	binary.Write(&fixed, binary.LittleEndian, int32(ProtocolBuildNumber))

	clientVersion := make([]byte, 20)
	copy(clientVersion, "bot")
	fixed.Write(clientVersion)

	fixed.WriteByte(ClientTypeGame)

	binary.Write(&fixed, binary.BigEndian, c.uuid[0:8])
	binary.Write(&fixed, binary.BigEndian, c.uuid[8:16])

	usernameOffset := int32(variable.Len())
	packets.WriteVarInt(&variable, len(c.username))
	variable.WriteString(c.username)

	identityTokenOffset := int32(-1)
	if c.identityToken != nil {
		identityTokenOffset = int32(variable.Len())
		tokenBytes := []byte(*c.identityToken)
		packets.WriteVarInt(&variable, len(tokenBytes))
		variable.Write(tokenBytes)
	}

	languageOffset := int32(variable.Len())
	packets.WriteVarInt(&variable, len(c.language))
	variable.WriteString(c.language)

	referralDataOffset := int32(-1)
	if c.referralData != nil {
		referralDataOffset = int32(variable.Len())
		packets.WriteVarInt(&variable, len(c.referralData))
		variable.Write(c.referralData)
	}

	referralSourceOffset := int32(-1)
	if c.referralSource != nil {
		referralSourceOffset = int32(variable.Len())
		variable.Write(c.referralSource.Encode())
	}

	binary.Write(&fixed, binary.LittleEndian, usernameOffset)
	binary.Write(&fixed, binary.LittleEndian, identityTokenOffset)
	binary.Write(&fixed, binary.LittleEndian, languageOffset)
	binary.Write(&fixed, binary.LittleEndian, referralDataOffset)
	binary.Write(&fixed, binary.LittleEndian, referralSourceOffset)

	if fixed.Len() != 66 {
		return nil, fmt.Errorf("fixed block must be 66 bytes, got %d", fixed.Len())
	}

	payload := append(fixed.Bytes(), variable.Bytes()...)

	var frame bytes.Buffer
	binary.Write(&frame, binary.LittleEndian, uint32(len(payload)))
	binary.Write(&frame, binary.LittleEndian, uint32(packets.ConnectPacketId))
	frame.Write(payload)

	return frame.Bytes(), nil
}
