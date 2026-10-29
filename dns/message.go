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

func (r *Record) IP() net.IP {
	if r.Type == TypeA || r.Type == TypeAAAA {
		return net.IP(r.Data)
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

func (b *Buffer) ReadQuestion() (*Question, error) {
	name, err := b.ReadName()
	if err != nil {
		return nil, err
	}

	qtype, err := b.ReadUint16()
	if err != nil {
		return nil, err
	}

	qclass, err := b.ReadUint16()
	if err != nil {
		return nil, err
	}

	return &Question{
		Name:  name,
		Type:  Type(qtype),
		Class: Class(qclass),
	}, nil
}

func (b *Buffer) WriteQuestion(q *Question) error {
	if err := b.WriteName(q.Name); err != nil {
		return err
	}
	b.WriteUint16(uint16(q.Type))
	b.WriteUint16(uint16(q.Class))
	return nil
}

func (b *Buffer) ReadRecord() (*Record, error) {
	name, err := b.ReadName()
	if err != nil {
		return nil, err
	}

	rtype, err := b.ReadUint16()
	if err != nil {
		return nil, err
	}

	rclass, err := b.ReadUint16()
	if err != nil {
		return nil, err
	}

	ttl, err := b.ReadUint32()
	if err != nil {
		return nil, err
	}

	rdLength, err := b.ReadUint16()
	if err != nil {
		return nil, err
	}

	rec := &Record{
		Name:  name,
		Type:  Type(rtype),
		Class: Class(rclass),
		TTL:   ttl,
	}

	switch rec.Type {
	case TypeNS, TypeCNAME, TypePTR:
		target, err := b.ReadName()
		if err != nil {
			return nil, err
		}
		rec.Text = target
	case TypeMX:
		pref, err := b.ReadUint16()
		if err != nil {
			return nil, err
		}
		name, err := b.ReadName()
		if err != nil {
			return nil, err
		}
		rec.Data = append([]byte{byte(pref >> 8), byte(pref)}, encodeName(name)...)
	case TypeSOA:
		mname, err := b.ReadName()
		if err != nil {
			return nil, err
		}
		rname, err := b.ReadName()
		if err != nil {
			return nil, err
		}
		tail, err := b.ReadBytes(20) // serial, refresh, retry, expire, minimum
		if err != nil {
			return nil, err
		}
		rec.Data = append(append(encodeName(mname), encodeName(rname)...), tail...)
	default:
		data, err := b.ReadBytes(int(rdLength))
		if err != nil {
			return nil, err
		}
		rec.Data = data
	}

	return rec, nil
}

func (b *Buffer) WriteRecord(r *Record) error {
	if err := b.WriteName(r.Name); err != nil {
		return err
	}

	b.WriteUint16(uint16(r.Type))
	b.WriteUint16(uint16(r.Class))
	b.WriteUint32(r.TTL)

	rdLenPos := len(b.Buf)
	b.WriteUint16(0)

	dataStart := len(b.Buf)

	switch r.Type {
	case TypeNS, TypeCNAME, TypePTR:
		if err := b.WriteName(r.Text); err != nil {
			return err
		}
	default:
		b.WriteBytes(r.Data)
	}

	dataLen := len(b.Buf) - dataStart
	binary.BigEndian.PutUint16(b.Buf[rdLenPos:rdLenPos+2], uint16(dataLen))

	return nil
}

func ParseMessage(data []byte) (*Message, error) {
	header, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}

	buf := NewBuffer(data)
	buf.Offset = 12

	m := &Message{
		Header:      *header,
		Questions:   make([]Question, 0),
		Answers:     make([]Record, 0),
		Authorities: make([]Record, 0),
		Additionals: make([]Record, 0),
	}

	for i := 0; i < int(header.QDCount); i++ {
		q, err := buf.ReadQuestion()
		if err != nil {
			return nil, err
		}
		m.Questions = append(m.Questions, *q)
	}

	for i := 0; i < int(header.ANCount); i++ {
		r, err := buf.ReadRecord()
		if err != nil {
			return nil, err
		}
		m.Answers = append(m.Answers, *r)
	}

	for i := 0; i < int(header.NSCount); i++ {
		r, err := buf.ReadRecord()
		if err != nil {
			return nil, err
		}
		m.Authorities = append(m.Authorities, *r)
	}

	for i := 0; i < int(header.ARCount); i++ {
		r, err := buf.ReadRecord()
		if err != nil {
			return nil, err
		}
		m.Additionals = append(m.Additionals, *r)
	}

	return m, nil
}

func (m *Message) Bytes() ([]byte, error) {
	buf := NewEmptyBuffer()

	m.Header.QDCount = uint16(len(m.Questions))
	m.Header.ANCount = uint16(len(m.Answers))
	m.Header.NSCount = uint16(len(m.Authorities))
	m.Header.ARCount = uint16(len(m.Additionals))

	buf.WriteBytes(m.Header.Bytes())

	for i := range m.Questions {
		if err := buf.WriteQuestion(&m.Questions[i]); err != nil {
			return nil, err
		}
	}

	for i := range m.Answers {
		if err := buf.WriteRecord(&m.Answers[i]); err != nil {
			return nil, err
		}
	}

	for i := range m.Authorities {
		if err := buf.WriteRecord(&m.Authorities[i]); err != nil {
			return nil, err
		}
	}

	for i := range m.Additionals {
		if err := buf.WriteRecord(&m.Additionals[i]); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
