package resolver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"dns_task/dns"
)

const (
	maxDepth   = 8  // глубина вложенных Resolve (CNAME, NS без glue)
	maxQueries = 30 // всего запросов к серверам на один клиентский вызов
)

var (
	ErrNoAnswers        = errors.New("no answers and no authority records found")
	ErrMaxHopsExceeded  = errors.New("maximum iterative hops exceeded")
	ErrAllServersFailed = errors.New("all DNS servers failed")
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
		return nil, err
	}

	message := dns.NewMessage()
	message.Header.ID = id
	message.Header.RD = false
	message.Questions = append(message.Questions, question)

	data, err := message.Bytes()
	if err != nil {
		return nil, err
	}

	address := net.JoinHostPort(server, "53")
	conn, err := net.Dial("udp", address)
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

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	resp, err := dns.ParseMessage(buffer[:n])
	if err != nil {
		return nil, err
	}
	if resp.Header.ID != id || !resp.Header.QR {
		return nil, errors.New("unexpected response")
	}
	return resp, nil
}
func (r *Resolver) queryAny(servers []string, question dns.Question, lk *lookup) (*dns.Message, error) {
	var lastErr error
	for _, server := range servers {
		if lk.queries >= maxQueries {
			return nil, ErrMaxHopsExceeded
		}
		lk.queries++

		resp, err := r.Query(server, question)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no DNS servers to query")
	}
	return nil, fmt.Errorf("%w: %v", ErrAllServersFailed, lastErr)
}

func (r *Resolver) Resolve(domain string, qtype dns.Type) (*dns.Message, error) {
	return r.resolve(domain, qtype, 0, &lookup{})
}

func (r *Resolver) resolve(domain string, qtype dns.Type, depth int, lk *lookup) (*dns.Message, error) {
	if depth > maxDepth {
		return nil, ErrMaxHopsExceeded
	}

	servers := RootServers
	question := dns.Question{Name: domain, Type: qtype, Class: dns.ClassINET}

	for {
		resp, err := r.queryAny(servers, question, lk)
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
				resp.Header.RCode = cnameResp.Header.RCode
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

		// glue для всех NS из Authority
		var ips []string
		for _, ns := range nsRecords {
			for _, add := range resp.Additionals {
				if add.Type == dns.TypeA && strings.EqualFold(add.Name, ns.Text) {
					if ip := add.IP(); ip != nil {
						ips = append(ips, ip.String())
					}
				}
			}
		}

		// glue нет, резолвим имена NS по очереди, пока кто-то не даст адрес
		if len(ips) == 0 {
			for _, ns := range nsRecords {
				nsResp, err := r.resolve(ns.Text, dns.TypeA, depth+1, lk)
				if err != nil {
					continue
				}
				for _, ans := range nsResp.Answers {
					if ans.Type == dns.TypeA {
						if ip := ans.IP(); ip != nil {
							ips = append(ips, ip.String())
						}
					}
				}
				if len(ips) > 0 {
					break
				}
			}
		}

		if len(ips) == 0 {
			return nil, ErrNoAnswers
		}
		servers = ips
	}
}
