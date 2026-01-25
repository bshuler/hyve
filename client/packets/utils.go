package packets

import (
	"bytes"

	"github.com/klauspost/compress/zstd"
)

var zstdEnc, _ = zstd.NewWriter(nil,
	zstd.WithSingleSegment(true),
	zstd.WithEncoderConcurrency(1),
)

func CompressZstd(b []byte) []byte {
	return zstdEnc.EncodeAll(b, nil)
}

func WriteVarInt(buf *bytes.Buffer, value int) {
	for value >= 0x80 {
		buf.WriteByte(byte(value&0x7F) | 0x80)
		value >>= 7
	}
	buf.WriteByte(byte(value))
}

func ReadVarInt(b []byte, off int) (val int, newOff int, ok bool) {
	shift := 0
	v := 0
	for {
		if off >= len(b) {
			return 0, off, false
		}
		x := int(b[off])
		off++
		v |= (x & 0x7f) << shift
		if (x & 0x80) == 0 {
			break
		}
		shift += 7
		if shift > 28 {
			return 0, off, false
		} // sanity
	}
	return v, off, true
}

func ReadVarString(b []byte, off int) (s string, newOff int, ok bool) {
	n, off2, ok := ReadVarInt(b, off)
	if !ok || n < 0 || off2+n > len(b) {
		return "", off, false
	}
	return string(b[off2 : off2+n]), off2 + n, true
}

func ReadUUID16(b []byte, off int) (u [16]byte, newOff int, ok bool) {
	if off+16 > len(b) {
		return u, off, false
	}
	copy(u[:], b[off:off+16])
	return u, off + 16, true
}
