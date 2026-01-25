package interface_

import (
	"bytes"
	"encoding/binary"
	"hypot/client/packets"
)

const ChatMessagePacketId = 211

type ChatMessage struct {
	Message string
}

func NewChatMessagePacket(message string) *ChatMessage {
	return &ChatMessage{Message: message}
}

func (c *ChatMessage) Encode() ([]byte, error) {
	msgBytes := []byte(c.Message)

	var payload bytes.Buffer
	payload.WriteByte(0x01) // msg exists

	packets.WriteVarInt(&payload, len(msgBytes))
	if _, err := payload.Write(msgBytes); err != nil {
		return nil, err
	}

	var frame bytes.Buffer
	_ = binary.Write(&frame, binary.LittleEndian, uint32(payload.Len()))
	_ = binary.Write(&frame, binary.LittleEndian, uint32(ChatMessagePacketId))
	_, _ = frame.Write(payload.Bytes())
	return frame.Bytes(), nil
}
