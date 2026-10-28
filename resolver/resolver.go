package resolver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"dns_task/dns"
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

	return dns.ParseMessage(buf[:n])
}

func (r *Resolver) Resolve(domain string, qtype dns.Type) (*dns.Message, error) {
	currentServer := RootServers[0]
	hops := 0
	maxHops := 25

	question := dns.Question{
		Name:  domain,
		Type:  qtype,
		Class: dns.ClassINET,
	}

	for {
		if hops > maxHops {
			return nil, ErrMaxHopsExceeded
		}
		hops++

		resp, err := r.Query(currentServer, question)
		if err != nil {
			return nil, err
		}

		if resp.Header.RCode != dns.RCodeNoError && resp.Header.RCode != dns.RCodeNameError {
			return resp, nil
		}

		if len(resp.Answers) > 0 {
			var cnameTarget string
			hasTargetType := false

			for _, ans := range resp.Answers {
				if ans.Type == qtype {
					hasTargetType = true
				}
				if ans.Type == dns.TypeCNAME {
					cnameTarget = ans.Text
				}
			}

			if hasTargetType {
				return resp, nil
			}

			if cnameTarget != "" {
				cnameResp, err := r.Resolve(cnameTarget, qtype)
				if err != nil {
					return nil, err
				}
				resp.Answers = append(resp.Answers, cnameResp.Answers...)
				return resp, nil
			}
		}

		if resp.Header.RCode == dns.RCodeNameError {
			return resp, nil
		}

		nextIP := ""
		for _, add := range resp.Additionals {
			if add.Type == dns.TypeA {
				ip := add.IP()
				if ip != nil {
					nextIP = ip.String()
					break
				}
			}
		}

		if nextIP != "" {
			currentServer = nextIP
			continue
		}

		if len(resp.Authorities) > 0 {
			var nsDomain string
			for _, auth := range resp.Authorities {
				if auth.Type == dns.TypeNS {
					nsDomain = auth.Text
					break
				}
			}

			if nsDomain != "" {
				nsResp, err := r.Resolve(nsDomain, dns.TypeA)
				if err != nil {
					return nil, err
				}

				for _, ans := range nsResp.Answers {
					if ans.Type == dns.TypeA {
						ip := ans.IP()
						if ip != nil {
							nextIP = ip.String()
							break
						}
					}
				}

				if nextIP != "" {
					currentServer = nextIP
					continue
				}
			}
		}

		return nil, ErrNoAnswers
	}
}
