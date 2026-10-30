package dns

import (
	"encoding/binary"
	"net"
	"strings"
)

type Question struct {
	Name  string
	Type  Type
	Class Class
}

/*
Name  - Запрашиваемое доменное имя (например, "google.com").
Type  - Тип запрашиваемой записи (1 для IPv4-адреса, 28 для IPv6, 15 для MX и т.д.).
Class - Сетевой класс (1 - IN / Internet).
*/

type Record struct {
	Name  string
	Type  Type
	Class Class
	TTL   uint32
	Data  []byte
	Text  string
}

/*
 Name  - Имя домена, к которому относится данная запись.
 Type  - Тип записи (A, NS, CNAME, TXT и др.).
 Class - Класс сети (IN).
 TTL   - Time To Live (время жизни записи в секундах).
 Data  - Сырые бинарные данные RDATA (используется для IP-адресов: 4 байта для IPv4, 16 байт для IPv6).
 Text  - Текстовое доменное имя из RDATA для записей типа NS, CNAME, PTR (хранится в распакованном виде).
*/

func (record *Record) IP() net.IP {
	if record.Type == TypeA || record.Type == TypeAAAA {
		return net.IP(record.Data)
	}
	return nil
}

type Message struct {
	Header      Header
	Questions   []Question
	Answers     []Record
	Authorities []Record
	Additionals []Record
}

/*
Header      - 12-байтный заголовок с ID, флагами и счетчиками секций.
Questions   - Секция QD: список вопросов (обычно один вопрос).
Answers     - Секция AN: ответы на вопрос (готовые IP-адреса или CNAME).
Authorities - Секция NS: список имен серверов, ответственных за доменную зону.
Additionals - Секция AR: дополнительные записи (IP-адреса серверов из секции Authorities).
*/

func NewMessage() *Message {
	return &Message{
		Header:      Header{},
		Questions:   make([]Question, 0, 1),
		Answers:     make([]Record, 0),
		Authorities: make([]Record, 0),
		Additionals: make([]Record, 0),
	}
}

func encodeName(name string) []byte { // имя без сжатия
	var out []byte
	for _, l := range strings.Split(strings.Trim(name, "."), ".") {
		if l == "" {
			continue
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0)
}

func (buffer *Buffer) ReadQuestion() (*Question, error) {
	name, err := buffer.ReadName()
	if err != nil {
		return nil, err
	}

	qtype, err := buffer.ReadUint16()
	if err != nil {
		return nil, err
	}

	qclass, err := buffer.ReadUint16()
	if err != nil {
		return nil, err
	}

	return &Question{
		Name:  name,
		Type:  Type(qtype),
		Class: Class(qclass),
	}, nil
}

func (buffer *Buffer) WriteQuestion(question *Question) error {
	if err := buffer.WriteName(question.Name); err != nil {
		return err
	}
	buffer.WriteUint16(uint16(question.Type))
	buffer.WriteUint16(uint16(question.Class))
	return nil
}

func (buffer *Buffer) ReadRecord() (*Record, error) {
	name, err := buffer.ReadName()
	if err != nil {
		return nil, err
	}

	rtype, err := buffer.ReadUint16()
	if err != nil {
		return nil, err
	}

	rclass, err := buffer.ReadUint16()
	if err != nil {
		return nil, err
	}

	ttl, err := buffer.ReadUint32()
	if err != nil {
		return nil, err
	}

	rdLength, err := buffer.ReadUint16()
	if err != nil {
		return nil, err
	}

	record := &Record{
		Name:  name,
		Type:  Type(rtype),
		Class: Class(rclass),
		TTL:   ttl,
	}

	switch record.Type {
	case TypeNS, TypeCNAME, TypePTR:
		target, err := buffer.ReadName()
		if err != nil {
			return nil, err
		}
		record.Text = target
	case TypeMX:
		pref, err := buffer.ReadUint16()
		if err != nil {
			return nil, err
		}
		name, err := buffer.ReadName()
		if err != nil {
			return nil, err
		}
		record.Data = append([]byte{byte(pref >> 8), byte(pref)}, encodeName(name)...)
	case TypeSOA:
		mname, err := buffer.ReadName()
		if err != nil {
			return nil, err
		}
		rname, err := buffer.ReadName()
		if err != nil {
			return nil, err
		}
		tail, err := buffer.ReadBytes(20) // serial, refresh, retry, expire, minimum
		if err != nil {
			return nil, err
		}
		record.Data = append(append(encodeName(mname), encodeName(rname)...), tail...)
	default:
		data, err := buffer.ReadBytes(int(rdLength))
		if err != nil {
			return nil, err
		}
		record.Data = data
	}

	return record, nil
}

func (buffer *Buffer) WriteRecord(r *Record) error {
	if err := buffer.WriteName(r.Name); err != nil {
		return err
	}

	buffer.WriteUint16(uint16(r.Type))
	buffer.WriteUint16(uint16(r.Class))
	buffer.WriteUint32(r.TTL)

	rdLenPos := len(buffer.Buffer)
	buffer.WriteUint16(0)

	dataStart := len(buffer.Buffer)

	switch r.Type {
	case TypeNS, TypeCNAME, TypePTR:
		if err := buffer.WriteName(r.Text); err != nil {
			return err
		}
	default:
		buffer.WriteBytes(r.Data)
	}

	dataLen := len(buffer.Buffer) - dataStart
	binary.BigEndian.PutUint16(buffer.Buffer[rdLenPos:rdLenPos+2], uint16(dataLen))

	return nil
}

func ParseMessage(data []byte) (*Message, error) {
	header, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}

	buffer := NewBuffer(data)
	buffer.Offset = 12

	message := &Message{
		Header:      *header,
		Questions:   make([]Question, 0),
		Answers:     make([]Record, 0),
		Authorities: make([]Record, 0),
		Additionals: make([]Record, 0),
	}

	for i := 0; i < int(header.QDCount); i++ {
		question, err := buffer.ReadQuestion()
		if err != nil {
			return nil, err
		}
		message.Questions = append(message.Questions, *question)
	}

	for i := 0; i < int(header.ANCount); i++ {
		record, err := buffer.ReadRecord()
		if err != nil {
			return nil, err
		}
		message.Answers = append(message.Answers, *record)
	}

	for i := 0; i < int(header.NSCount); i++ {
		record, err := buffer.ReadRecord()
		if err != nil {
			return nil, err
		}
		message.Authorities = append(message.Authorities, *record)
	}

	for i := 0; i < int(header.ARCount); i++ {
		record, err := buffer.ReadRecord()
		if err != nil {
			return nil, err
		}
		message.Additionals = append(message.Additionals, *record)
	}

	return message, nil
}

func (message *Message) Bytes() ([]byte, error) {
	buffer := NewEmptyBuffer()

	message.Header.QDCount = uint16(len(message.Questions))
	message.Header.ANCount = uint16(len(message.Answers))
	message.Header.NSCount = uint16(len(message.Authorities))
	message.Header.ARCount = uint16(len(message.Additionals))

	buffer.WriteBytes(message.Header.Bytes())

	for i := range message.Questions {
		if err := buffer.WriteQuestion(&message.Questions[i]); err != nil {
			return nil, err
		}
	}

	for i := range message.Answers {
		if err := buffer.WriteRecord(&message.Answers[i]); err != nil {
			return nil, err
		}
	}

	for i := range message.Authorities {
		if err := buffer.WriteRecord(&message.Authorities[i]); err != nil {
			return nil, err
		}
	}

	for i := range message.Additionals {
		if err := buffer.WriteRecord(&message.Additionals[i]); err != nil {
			return nil, err
		}
	}

	return buffer.Bytes(), nil
}
