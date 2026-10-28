package dns

import (
	"encoding/binary"
	"errors"
	"strings"
)

const MaxJumps = 10

var (
	ErrBufferOverflow = errors.New("buffer overflow")
	ErrPointerCycle   = errors.New("pointer cycle detected")
	ErrLabelTooLong   = errors.New("label exceeds 63 bytes limit")
)

type Buffer struct {
	Buf         []byte
	Offset      int
	compression map[string]uint16
}

func NewBuffer(data []byte) *Buffer {
	return &Buffer{
		Buf:         data,
		Offset:      0,
		compression: make(map[string]uint16),
	}
}

func NewEmptyBuffer() *Buffer {
	return &Buffer{
		Buf:         make([]byte, 0, 512),
		Offset:      0,
		compression: make(map[string]uint16),
	}
}

func (b *Buffer) ReadUint8() (uint8, error) {
	if b.Offset >= len(b.Buf) {
		return 0, ErrBufferOverflow
	}
	val := b.Buf[b.Offset]
	b.Offset++
	return val, nil
}

func (b *Buffer) ReadUint16() (uint16, error) {
	if b.Offset+2 > len(b.Buf) {
		return 0, ErrBufferOverflow
	}
	val := binary.BigEndian.Uint16(b.Buf[b.Offset : b.Offset+2])
	b.Offset += 2
	return val, nil
}

func (b *Buffer) ReadUint32() (uint32, error) {
	if b.Offset+4 > len(b.Buf) {
		return 0, ErrBufferOverflow
	}
	val := binary.BigEndian.Uint32(b.Buf[b.Offset : b.Offset+4])
	b.Offset += 4
	return val, nil
}

func (b *Buffer) ReadBytes(length int) ([]byte, error) {
	if b.Offset+length > len(b.Buf) {
		return nil, ErrBufferOverflow
	}
	out := make([]byte, length)
	copy(out, b.Buf[b.Offset:b.Offset+length])
	b.Offset += length
	return out, nil
}

func (b *Buffer) ReadName() (string, error) {
	pos := b.Offset
	jumped := false
	maxJumps := MaxJumps
	jumps := 0

	var labels []string

	for {
		if jumps > maxJumps {
			return "", ErrPointerCycle
		}

		if pos >= len(b.Buf) {
			return "", ErrBufferOverflow
		}

		lengthByte := b.Buf[pos]
		if (lengthByte & 0xC0) == 0xC0 { // 0xC0: 11000000 (проверяем, что встретили указатель)
			if pos+1 >= len(b.Buf) {
				return "", ErrBufferOverflow
			}

			if !jumped {
				b.Offset = pos + 2
				jumped = true
			}

			pointerVal := binary.BigEndian.Uint16(b.Buf[pos : pos+2])
			targetOffset := int(pointerVal & 0x3FFF) // 0x3FFF: 00111111 11111111 (убираем первые два бита)

			pos = targetOffset
			jumps++
			continue
		}

		pos++

		if lengthByte == 0 {
			break
		}

		labelLen := int(lengthByte)
		if pos+labelLen > len(b.Buf) {
			return "", ErrBufferOverflow
		}

		labels = append(labels, string(b.Buf[pos:pos+labelLen]))
		pos += labelLen
	}

	if !jumped {
		b.Offset = pos
	}

	return strings.Join(labels, "."), nil
}

func (b *Buffer) WriteUint8(val uint8) {
	b.Buf = append(b.Buf, val)
	b.Offset++
}

func (b *Buffer) WriteUint16(val uint16) {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, val)
	b.Buf = append(b.Buf, bytes...)
	b.Offset += 2
}

func (b *Buffer) WriteUint32(val uint32) {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, val)
	b.Buf = append(b.Buf, bytes...)
	b.Offset += 4
}

func (b *Buffer) WriteBytes(data []byte) {
	b.Buf = append(b.Buf, data...)
	b.Offset += len(data)
}

func (b *Buffer) WriteName(name string) error {
	normalized := strings.Trim(strings.ToLower(name), ".")
	if normalized == "" {
		b.WriteUint8(0)
		return nil
	}

	parts := strings.Split(normalized, ".")

	for i := 0; i < len(parts); i++ {
		subDomain := strings.Join(parts[i:], ".")

		if offset, exists := b.compression[subDomain]; exists { // Идем по суффиксам
			pointer := 0xC000 | offset // Выставляем первые два бита 11 и пишем указатель
			b.WriteUint16(pointer)
			return nil
		}

		if len(b.Buf) < 0x3FFF { // Проверяем, что смещение укладывается в 14 бит
			b.compression[subDomain] = uint16(len(b.Buf))
		}

		label := parts[i]
		if len(label) > 63 { // Метка не должна превышать 63 байта
			return ErrLabelTooLong
		}

		b.WriteUint8(uint8(len(label)))
		b.WriteBytes([]byte(label))
	}

	b.WriteUint8(0)
	return nil
}

func (b *Buffer) Bytes() []byte {
	return b.Buf
}
