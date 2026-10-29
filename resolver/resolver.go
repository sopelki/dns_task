package resolver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"dns_task/dns"
)

const (
	maxDepth   = 8  // глубина вложенных Resolve (CNAME, NS без glue)
	maxQueries = 30 // всего запросов к серверам на один клиентский вызов
)


var (
	ErrNoAnswers       = errors.New("no answers and no authority records found")
	ErrMaxHopsExceeded = errors.New("maximum iterative hops exceeded")
)

var RootServers = []string{
	"198.41.0.4",
	"170.247.170.2",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
}

type lookup struct {
	queries int
}

type Resolver struct {
	Timeout time.Duration
}

func NewResolver(timeout time.Duration) *Resolver {
	return &Resolver{
		Timeout: timeout,
	}
}

func (r *Resolver) Query(server string, question dns.Question) (*dns.Message, error) {
	var id uint16
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		id = 1234 // На всякий случай, если не получилось взять рандомное число.
	}

	m := dns.NewMessage()
	m.Header.ID = id
	m.Header.RD = false
	m.Questions = append(m.Questions, question)

	data, err := m.Bytes()
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(server, "53")
	conn, err := net.DialTimeout("udp", addr, r.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(r.Timeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(data); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	resp, err := dns.ParseMessage(buf[:n])
	if err != nil {
		return nil, err
	}
	if resp.Header.ID != id || !resp.Header.QR {
		return nil, errors.New("unexpected response")
	}
	return resp, nil
}

func (r *Resolver) Resolve(domain string, qtype dns.Type) (*dns.Message, error) {
	return r.resolve(domain, qtype, 0, &lookup{})
}

func (r *Resolver) resolve(domain string, qtype dns.Type, depth int, lk *lookup) (*dns.Message, error) {
	if depth > maxDepth {
		return nil, ErrMaxHopsExceeded
	}

	currentServer := RootServers[0]
	question := dns.Question{Name: domain, Type: qtype, Class: dns.ClassINET}

	for {
		lk.queries++
		if lk.queries > maxQueries {
			return nil, ErrMaxHopsExceeded
		}

		resp, err := r.Query(currentServer, question)
		if err != nil {
			return nil, err
		}

		if resp.Header.RCode != dns.RCodeNoError && resp.Header.RCode != dns.RCodeNameError {
			return resp, nil
		}

		if len(resp.Answers) > 0 {
			var cnameTarget string
			for _, ans := range resp.Answers {
				if ans.Type == qtype {
					return resp, nil
				}
				if ans.Type == dns.TypeCNAME {
					cnameTarget = ans.Text
				}
			}

			if cnameTarget != "" {
				cnameResp, err := r.resolve(cnameTarget, qtype, depth+1, lk)
				if err != nil {
					return nil, err
				}
				resp.Answers = append(resp.Answers, cnameResp.Answers...)
				resp.Authorities = cnameResp.Authorities
				resp.Header.RCode = cnameResp.Header.RCode // NXDOMAIN цели не должен стать NOERROR
				return resp, nil
			}
		}

		if resp.Header.RCode == dns.RCodeNameError {
			return resp, nil
		}

		var nsRecords []dns.Record
		for _, a := range resp.Authorities {
			if a.Type == dns.TypeNS {
				nsRecords = append(nsRecords, a)
			}
		}
		if len(nsRecords) == 0 {
			return resp, nil // NODATA
		}

		// Сначала glue из Additional.
		nextIP := ""
		for _, add := range resp.Additionals {
			if add.Type == dns.TypeA {
				if ip := add.IP(); ip != nil {
					nextIP = ip.String()
					break
				}
			}
		}

		// Glue нет, резолвим имя первого NS.
		if nextIP == "" {
			nsResp, err := r.resolve(nsRecords[0].Text, dns.TypeA, depth+1, lk)
			if err != nil {
				return nil, err
			}
			for _, ans := range nsResp.Answers {
				if ans.Type == dns.TypeA {
					if ip := ans.IP(); ip != nil {
						nextIP = ip.String()
						break
					}
				}
			}
		}

		if nextIP == "" {
			return nil, ErrNoAnswers
		}
		currentServer = nextIP
	}
}