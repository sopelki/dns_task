package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"dns_task/dns"
	"dns_task/resolver"
)

func main() {
	port := 1053 // 1053 вместо 53 для использования без sudo.
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"), // Слушает все порты.
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("failed to bind UDP port %d: %v", port, err)
	}
	defer conn.Close()

	fmt.Printf("DNS-сервер запущен на порту %d (udp)\n", port)
	// fmt.Printf("dig @127.0.0.1 -p %d google.com\n\n", port)

	r := resolver.NewResolver(3 * time.Second)

	for {
		buffer := make([]byte, 512)
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}

		packetData := make([]byte, n)
		copy(packetData, buffer[:n])

		go handlePacket(conn, clientAddr, packetData, r)
	}
}

func handlePacket(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, r *resolver.Resolver) {
	req, err := dns.ParseMessage(data)
	if err != nil {
		log.Printf("failed to parse message from %s: %v", clientAddr, err)
		return
	}

	if len(req.Questions) == 0 {
		return
	}

	q := req.Questions[0]
	log.Printf("Запрос от %s: %s (Type: %d)", clientAddr, q.Name, q.Type)

	if multiplyResp := handleMultiply(q); multiplyResp != nil {
		multiplyResp.Header.ID = req.Header.ID
		respBytes, err := multiplyResp.Bytes()
		if err != nil {
			log.Printf("failed to serialize synthetic response: %v", err)
			return
		}
		if _, err := conn.WriteToUDP(respBytes, clientAddr); err != nil {
			log.Printf("write error to %s: %v", clientAddr, err)
		}
		return
	}

	resp, err := r.Resolve(q.Name, q.Type)

	out := dns.NewMessage()
	out.Header.ID = req.Header.ID
	out.Header.QR = true
	out.Header.RA = true
	out.Questions = append(out.Questions, q)

	if err != nil {
		log.Printf("resolve error for %s: %v", q.Name, err)
		out.Header.RCode = dns.RCodeServerFailure
	} else {
		out.Header.RCode = resp.Header.RCode
		out.Answers = resp.Answers
		out.Authorities = resp.Authorities
	}

	respBytes, err := out.Bytes()
	if err != nil {
		log.Printf("failed to serialize response: %v", err)
		return
	}

	if _, err := conn.WriteToUDP(respBytes, clientAddr); err != nil {
		log.Printf("write error to %s: %v", clientAddr, err)
	}
}

func handleMultiply(q dns.Question) *dns.Message {
	name := strings.ToLower(q.Name)
	if !strings.Contains(name, ".multiply.") {
		return nil
	}

	parts := strings.Split(name, ".")
	multIdx := -1
	for i, part := range parts {
		if part == "multiply" {
			multIdx = i
			break
		}
	}

	if multIdx <= 0 {
		return nil
	}

	product := 1
	hasNumbers := false

	for i := 0; i < multIdx; i++ {
		val, err := strconv.Atoi(parts[i])
		if err != nil {
			continue
		}
		product = (product * val) % 256
		hasNumbers = true
	}

	if !hasNumbers {
		return nil
	}

	x := byte(product)

	m := dns.NewMessage()
	m.Header.QR = true
	m.Header.AA = true
	m.Header.RA = true
	m.Header.RCode = dns.RCodeNoError
	m.Questions = append(m.Questions, q)

	if q.Type == dns.TypeA {
		m.Answers = append(m.Answers, dns.Record{
			Name:  q.Name,
			Type:  dns.TypeA,
			Class: dns.ClassINET,
			TTL:   60,
			Data:  []byte{127, 0, 0, x},
		})
	}

	return m
}
