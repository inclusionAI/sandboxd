// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package networkacl

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsTimeout = 5 * time.Second

const (
	DefaultDNSProxyConcurrencyLimit           = 256
	DefaultDNSProxyPerSandboxConcurrencyLimit = 16
)

type dnsAuthorizer func(net.IP, []string) bool

type dnsProxy struct {
	udp       *net.UDPConn
	tcp       net.Listener
	upstreams []string
	authorize dnsAuthorizer
	limiter   *dnsConcurrencyLimiter
	stop      chan struct{}
	wg        sync.WaitGroup
}

type dnsConcurrencyLimiter struct {
	mu              sync.Mutex
	globalLimit     int
	perSandboxLimit int
	inFlight        int
	sandboxInFlight map[string]int
}

func newDNSConcurrencyLimiter(globalLimit, perSandboxLimit int) (*dnsConcurrencyLimiter, error) {
	if globalLimit <= 0 {
		return nil, fmt.Errorf("DNS proxy concurrency limit must be positive")
	}
	if perSandboxLimit <= 0 {
		return nil, fmt.Errorf("DNS proxy per-sandbox concurrency limit must be positive")
	}
	if perSandboxLimit > globalLimit {
		return nil, fmt.Errorf(
			"DNS proxy per-sandbox concurrency limit %d exceeds global limit %d",
			perSandboxLimit,
			globalLimit,
		)
	}
	return &dnsConcurrencyLimiter{
		globalLimit:     globalLimit,
		perSandboxLimit: perSandboxLimit,
		sandboxInFlight: make(map[string]int),
	}, nil
}

func (l *dnsConcurrencyLimiter) tryAcquire(source net.IP) (func(), bool) {
	key := source.String()
	l.mu.Lock()
	if l.inFlight >= l.globalLimit || l.sandboxInFlight[key] >= l.perSandboxLimit {
		l.mu.Unlock()
		return nil, false
	}
	l.inFlight++
	l.sandboxInFlight[key]++
	l.mu.Unlock()

	return func() {
		l.mu.Lock()
		l.inFlight--
		l.sandboxInFlight[key]--
		if l.sandboxInFlight[key] == 0 {
			delete(l.sandboxInFlight, key)
		}
		l.mu.Unlock()
	}, true
}

func newDNSProxy(
	bindIP net.IP,
	resolverPath string,
	globalConcurrencyLimit int,
	perSandboxConcurrencyLimit int,
	authorize dnsAuthorizer,
) (*dnsProxy, error) {
	upstreams, err := resolverUpstreams(resolverPath, bindIP)
	if err != nil {
		return nil, err
	}
	limiter, err := newDNSConcurrencyLimiter(globalConcurrencyLimit, perSandboxConcurrencyLimit)
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(bindIP.String(), "53")
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP.To4(), Port: 53})
	if err != nil {
		return nil, fmt.Errorf("listen DNS UDP on %s: %w", address, err)
	}
	tcp, err := net.Listen("tcp4", address)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("listen DNS TCP on %s: %w", address, err)
	}
	proxy := &dnsProxy{
		udp:       udp,
		tcp:       tcp,
		upstreams: upstreams,
		authorize: authorize,
		limiter:   limiter,
		stop:      make(chan struct{}),
	}
	proxy.wg.Add(2)
	go proxy.serveUDP()
	go proxy.serveTCP()
	return proxy, nil
}

func resolverUpstreams(path string, bindIP net.IP) ([]string, error) {
	if path == "" {
		path = "/etc/resolv.conf"
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open resolver source %s: %w", path, err)
	}
	defer file.Close()
	var upstreams []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(strings.Trim(fields[1], "[]"))
		if ip == nil || ip.Equal(bindIP) {
			continue
		}
		upstreams = append(upstreams, net.JoinHostPort(ip.String(), "53"))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read resolver source %s: %w", path, err)
	}
	if len(upstreams) == 0 {
		return nil, fmt.Errorf("resolver source %s has no usable nameserver", path)
	}
	return upstreams, nil
}

func (p *dnsProxy) close() error {
	if p == nil {
		return nil
	}
	select {
	case <-p.stop:
		return nil
	default:
		close(p.stop)
	}
	err := errors.Join(p.udp.Close(), p.tcp.Close())
	p.wg.Wait()
	return err
}

func (p *dnsProxy) serveUDP() {
	defer p.wg.Done()
	buffer := make([]byte, 65535)
	for {
		n, source, err := p.udp.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-p.stop:
				return
			default:
				continue
			}
		}
		release, ok := p.limiter.tryAcquire(source.IP)
		if !ok {
			response, responseErr := dnsErrorResponse(buffer[:n], dnsmessage.RCodeServerFailure)
			if responseErr == nil {
				_, _ = p.udp.WriteToUDP(response, source)
			}
			continue
		}
		request := append([]byte(nil), buffer[:n]...)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			response, err := p.handle(source.IP, request, "udp")
			release()
			if err == nil {
				_, _ = p.udp.WriteToUDP(response, source)
			}
		}()
	}
}

func (p *dnsProxy) serveTCP() {
	defer p.wg.Done()
	for {
		connection, err := p.tcp.Accept()
		if err != nil {
			select {
			case <-p.stop:
				return
			default:
				continue
			}
		}
		source, ok := connection.RemoteAddr().(*net.TCPAddr)
		if !ok {
			_ = connection.Close()
			continue
		}
		release, ok := p.limiter.tryAcquire(source.IP)
		if !ok {
			_ = connection.Close()
			continue
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer release()
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(dnsTimeout))
			for {
				request, err := readDNSFrame(connection)
				if err != nil {
					return
				}
				response, err := p.handle(source.IP, request, "tcp")
				if err != nil || writeDNSFrame(connection, response) != nil {
					return
				}
			}
		}()
	}
}

func (p *dnsProxy) handle(source net.IP, request []byte, network string) ([]byte, error) {
	header, questions, names, err := parseDNSQuestions(request)
	if err != nil {
		return nil, err
	}
	if p.authorize == nil || !p.authorize(source, names) {
		return dnsResponse(header, questions, dnsmessage.RCodeRefused)
	}
	var lastErr error
	for _, upstream := range p.upstreams {
		response, err := exchangeDNS(network, upstream, request)
		if err == nil {
			return response, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all DNS upstreams failed: %w", lastErr)
}

func parseDNSQuestions(payload []byte) (dnsmessage.Header, []dnsmessage.Question, []string, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(payload)
	if err != nil {
		return dnsmessage.Header{}, nil, nil, err
	}
	var questions []dnsmessage.Question
	var names []string
	for {
		question, err := parser.Question()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return dnsmessage.Header{}, nil, nil, err
		}
		questions = append(questions, question)
		names = append(names, question.Name.String())
	}
	if len(questions) == 0 {
		return dnsmessage.Header{}, nil, nil, fmt.Errorf("DNS request has no questions")
	}
	return header, questions, names, nil
}

func dnsErrorResponse(payload []byte, code dnsmessage.RCode) ([]byte, error) {
	header, questions, _, err := parseDNSQuestions(payload)
	if err != nil {
		return nil, err
	}
	return dnsResponse(header, questions, code)
}

func dnsResponse(
	request dnsmessage.Header,
	questions []dnsmessage.Question,
	code dnsmessage.RCode,
) ([]byte, error) {
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 request.ID,
			Response:           true,
			OpCode:             request.OpCode,
			RecursionDesired:   request.RecursionDesired,
			RecursionAvailable: true,
			RCode:              code,
		},
		Questions: questions,
	}
	return response.Pack()
}

func exchangeDNS(network, upstream string, request []byte) ([]byte, error) {
	connection, err := net.DialTimeout(network, upstream, dnsTimeout)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(dnsTimeout))
	if network == "tcp" {
		if err := writeDNSFrame(connection, request); err != nil {
			return nil, err
		}
		return readDNSFrame(connection)
	}
	if _, err := connection.Write(request); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	n, err := connection.Read(response)
	if err != nil {
		return nil, err
	}
	return response[:n], nil
}

func readDNSFrame(reader io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(length[:])
	if size == 0 {
		return nil, fmt.Errorf("empty DNS TCP frame")
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(reader, payload)
	return payload, err
}

func writeDNSFrame(writer io.Writer, payload []byte) error {
	if len(payload) > 65535 {
		return fmt.Errorf("DNS TCP frame is too large: %d", len(payload))
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)))
	if _, err := writer.Write(length[:]); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}
