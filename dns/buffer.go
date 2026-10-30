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
	Buffer         []byte
	Offset      int
	compression map[string]uint16
}

func NewBuffer(data []byte) *Buffer {
	return &Buffer{
		Buffer:         data,
		Offset:      0,
		compression: make(map[string]uint16),
	}
}

func NewEmptyBuffer() *Buffer {
	return &Buffer{
		Buffer:         make([]byte, 0, 512),
		Offset:      0,
		compression: make(map[string]uint16),
	}
}

func (buffer *Buffer) ReadUint8() (uint8, error) {
	if buffer.Offset >= len(buffer.Buffer) {
		return 0, ErrBufferOverflow
	}
	value := buffer.Buffer[buffer.Offset]
	buffer.Offset++
	return value, nil
}

func (buffer *Buffer) ReadUint16() (uint16, error) {
	if buffer.Offset+2 > len(buffer.Buffer) {
		return 0, ErrBufferOverflow
	}
	value := binary.BigEndian.Uint16(buffer.Buffer[buffer.Offset : buffer.Offset+2])
	buffer.Offset += 2
	return value, nil
}

func (buffer *Buffer) ReadUint32() (uint32, error) {
	if buffer.Offset+4 > len(buffer.Buffer) {
		return 0, ErrBufferOverflow
	}
	value := binary.BigEndian.Uint32(buffer.Buffer[buffer.Offset : buffer.Offset+4])
	buffer.Offset += 4
	return value, nil
}

func (buffer *Buffer) ReadBytes(length int) ([]byte, error) {
	if buffer.Offset+length > len(buffer.Buffer) {
		return nil, ErrBufferOverflow
	}
	out := make([]byte, length)
	copy(out, buffer.Buffer[buffer.Offset:buffer.Offset+length])
	buffer.Offset += length
	return out, nil
}

func (buffer *Buffer) ReadName() (string, error) {
	position := buffer.Offset
	jumped := false
	maxJumps := MaxJumps
	jumps := 0

	var labels []string

	for {
		if jumps > maxJumps {
			return "", ErrPointerCycle
		}

		if position >= len(buffer.Buffer) {
			return "", ErrBufferOverflow
		}

		lengthByte := buffer.Buffer[position]
		if (lengthByte & 0xC0) == 0xC0 { // 0xC0: 11000000 (проверяем, что встретили указатель)
			if position+1 >= len(buffer.Buffer) {
				return "", ErrBufferOverflow
			}

			if !jumped {
				buffer.Offset = position + 2
				jumped = true
			}

			pointerVal := binary.BigEndian.Uint16(buffer.Buffer[position : position+2])
			targetOffset := int(pointerVal & 0x3FFF) // 0x3FFF: 00111111 11111111 (убираем первые два бита)

			position = targetOffset
			jumps++
			continue
		}

		position++

		if lengthByte == 0 {
			break
		}

		labelLen := int(lengthByte)
		if position+labelLen > len(buffer.Buffer) {
			return "", ErrBufferOverflow
		}

		labels = append(labels, string(buffer.Buffer[position:position+labelLen]))
		position += labelLen
	}

	if !jumped {
		buffer.Offset = position
	}

	return strings.Join(labels, "."), nil
}

func (buffer *Buffer) WriteUint8(val uint8) {
	buffer.Buffer = append(buffer.Buffer, val)
	buffer.Offset++
}

func (buffer *Buffer) WriteUint16(val uint16) {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, val)
	buffer.Buffer = append(buffer.Buffer, bytes...)
	buffer.Offset += 2
}

func (buffer *Buffer) WriteUint32(val uint32) {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, val)
	buffer.Buffer = append(buffer.Buffer, bytes...)
	buffer.Offset += 4
}

func (buffer *Buffer) WriteBytes(data []byte) {
	buffer.Buffer = append(buffer.Buffer, data...)
	buffer.Offset += len(data)
}

func (buffer *Buffer) WriteName(name string) error {
	normalized := strings.Trim(strings.ToLower(name), ".")
	if normalized == "" {
		buffer.WriteUint8(0)
		return nil
	}

	parts := strings.Split(normalized, ".")

	for i := 0; i < len(parts); i++ {
		subDomain := strings.Join(parts[i:], ".")

		if offset, exists := buffer.compression[subDomain]; exists { // Идем по суффиксам
			pointer := 0xC000 | offset // Выставляем первые два бита 11 и пишем указатель
			buffer.WriteUint16(pointer)
			return nil
		}

		if len(buffer.Buffer) < 0x3FFF { // Проверяем, что смещение укладывается в 14 бит
			buffer.compression[subDomain] = uint16(len(buffer.Buffer))
		}

		label := parts[i]
		if len(label) > 63 { // Метка не должна превышать 63 байта
			return ErrLabelTooLong
		}

		buffer.WriteUint8(uint8(len(label)))
		buffer.WriteBytes([]byte(label))
	}

	buffer.WriteUint8(0)
	return nil
}

func (buffer *Buffer) Bytes() []byte {
	return buffer.Buffer
}
