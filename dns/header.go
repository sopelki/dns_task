package dns

import (
	"encoding/binary"
	"errors"
)

var (
	ErrPacketTooShort = errors.New("packet is too short for header")
)

type Header struct {
	ID      uint16
	QR      bool
	Opcode  uint8
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCode   RCode
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

/*
ID      - Уникальный 16-битный номер транзакции. Сервер возвращает его без изменений.
QR      - 0: входящий запрос (Query), 1: исходящий ответ (Response).
Opcode  - Код операции (0: стандартный запрос QUERY).
AA      - Authoritative Answer. 1: ответ получен от владельца зоны, а не из кэша.
TC      - Truncated. 1: пакет не влез в лимит UDP (512 байт), клиенту нужно перейти на TCP.
RD      - Recursion Desired. 1: клиент просит сервер найти всё самому; 0: клиент резолвит итеративно сам.
RA      - Recursion Available. 1: сервер сообщает клиенту, что поддерживает рекурсию.
Z       - Зарезервировано (3 бита). Должно быть 0.
RCode   - Код ошибки/статуса ответа (младшие 4 бита).
QDCount - Количество вопросов в секции Question.
ANCount - Количество найденных записей в секции Answer.
NSCount - Количество записей о серверах имен в секции Authority.
ARCount - Количество дополнительных записей в секции Additional (например, IP-адреса для NS).
*/

func ParseHeader(data []byte) (*Header, error) {
	// Заголовок должен ровно 12 байт
	if len(data) < 12 { 
		return nil, ErrPacketTooShort
	}

	flags := binary.BigEndian.Uint16(data[2:4])

	h := &Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		QR:      (flags & (1 << 15)) != 0,
		Opcode:  uint8((flags >> 11) & 0b1111),
		AA:      (flags & (1 << 10)) != 0,
		TC:      (flags & (1 << 9)) != 0,
		RD:      (flags & (1 << 8)) != 0,
		RA:      (flags & (1 << 7)) != 0,
		Z:       uint8((flags >> 4) & 0b111),
		RCode:   RCode(flags & 0b1111),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	return h, nil
}

func (header *Header) Bytes() []byte {
	buffer := make([]byte, 12)

	binary.BigEndian.PutUint16(buffer[0:2], header.ID)

	var flags uint16
	if header.QR {
		flags |= 1 << 15
	}
	flags |= (uint16(header.Opcode) & 0b1111) << 11
	if header.AA {
		flags |= 1 << 10
	}
	if header.TC {
		flags |= 1 << 9
	}
	if header.RD {
		flags |= 1 << 8
	}
	if header.RA {
		flags |= 1 << 7
	}
	flags |= (uint16(header.Z) & 0b111) << 4
	flags |= uint16(header.RCode) & 0b1111

	binary.BigEndian.PutUint16(buffer[2:4], flags)
	binary.BigEndian.PutUint16(buffer[4:6], header.QDCount)
	binary.BigEndian.PutUint16(buffer[6:8], header.ANCount)
	binary.BigEndian.PutUint16(buffer[8:10], header.NSCount)
	binary.BigEndian.PutUint16(buffer[10:12], header.ARCount)

	return buffer
}
