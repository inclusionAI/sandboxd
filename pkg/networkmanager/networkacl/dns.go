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
type dnsObserver func(net.IP, []string, []string, []byte) ([]byte, error)

type dnsProxy struct {
	udp       *net.UDPConn
	tcp       net.Listener
	upstreams []string
	authorize dnsAuthorizer
	observe   dnsObserver
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
	observe dnsObserver,
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
		observe:   observe,
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
			if err = validateDNSResponse(response, header, questions); err != nil {
				lastErr = err
				continue
			}
			if p.observe != nil {
				grantNames := trafficGrantNames(questions)
				if len(grantNames) == 0 {
					return response, nil
				}
				observed, observeErr := p.observe(source, names, grantNames, response)
				if observeErr != nil {
					return dnsResponse(header, questions, dnsmessage.RCodeServerFailure)
				}
				return observed, nil
			}
			return response, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all DNS upstreams failed: %w", lastErr)
}

func validateDNSResponse(
	payload []byte, requestHeader dnsmessage.Header, requestQuestions []dnsmessage.Question,
) error {
	var response dnsmessage.Message
	if err := response.Unpack(payload); err != nil {
		return fmt.Errorf("unpack DNS response: %w", err)
	}
	if !response.Header.Response || response.Header.ID != requestHeader.ID ||
		response.Header.OpCode != requestHeader.OpCode {
		return fmt.Errorf("DNS response does not match the request header")
	}
	if len(response.Questions) != len(requestQuestions) {
		return fmt.Errorf("DNS response question count does not match the request")
	}
	for index, question := range requestQuestions {
		candidate := response.Questions[index]
		if canonicalDNSName(candidate.Name.String()) != canonicalDNSName(question.Name.String()) ||
			candidate.Type != question.Type || candidate.Class != question.Class {
			return fmt.Errorf("DNS response question %d does not match the request", index)
		}
	}
	return nil
}

// trafficGrantNames returns only questions whose answers can replace IPv4
// traffic grants. In particular, an ordinary resolver commonly sends A and
// AAAA queries in parallel. Treating an empty AAAA response as a replacement
// for the A response would immediately revoke a valid IPv4 grant.
func trafficGrantNames(questions []dnsmessage.Question) []string {
	names := make([]string, 0, len(questions))
	seen := make(map[string]struct{}, len(questions))
	for _, question := range questions {
		if question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeALL {
			continue
		}
		name := canonicalDNSName(question.Name.String())
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

const (
	minDomainGrantTTL = uint32(1)
	maxDomainGrantTTL = uint32(3600)
	maxDNSAddresses   = 64
	maxCNAMEChain     = 32
)

type resolvedAddress struct {
	IP  [4]byte
	TTL uint32
}

type cnameTarget struct {
	name string
	ttl  uint32
}

type addressRecord struct {
	ip  [4]byte
	ttl uint32
}

func resolveDNSResponse(payload []byte, questions []string) ([]byte, map[string][]resolvedAddress, error) {
	var message dnsmessage.Message
	if err := message.Unpack(payload); err != nil {
		return nil, nil, fmt.Errorf("unpack DNS response: %w", err)
	}
	if !message.Header.Response {
		return nil, nil, fmt.Errorf("DNS payload is not a response")
	}
	cnames := make(map[string][]cnameTarget)
	addresses := make(map[string][]addressRecord)
	collect := func(resources []dnsmessage.Resource) {
		for _, resource := range resources {
			owner := canonicalDNSName(resource.Header.Name.String())
			switch body := resource.Body.(type) {
			case *dnsmessage.CNAMEResource:
				cnames[owner] = append(cnames[owner], cnameTarget{
					name: canonicalDNSName(body.CNAME.String()), ttl: clampDomainTTL(resource.Header.TTL),
				})
			case *dnsmessage.AResource:
				addresses[owner] = append(addresses[owner], addressRecord{
					ip: body.A, ttl: clampDomainTTL(resource.Header.TTL),
				})
			}
		}
	}
	// Negative and truncated replies replace prior grants with an empty set.
	// Their record sections are not a complete affirmative answer and must not
	// be able to mint packet authorization.
	if message.Header.RCode == dnsmessage.RCodeSuccess && !message.Header.Truncated {
		collect(message.Answers)
		collect(message.Additionals)
	}

	resolved := make(map[string][]resolvedAddress, len(questions))
	effectiveA := make(map[string]uint32)
	for _, question := range questions {
		name := canonicalDNSName(question)
		results, err := followCNAMEs(name, cnames, addresses)
		if err != nil {
			return nil, nil, err
		}
		if len(results) > maxDNSAddresses {
			return nil, nil, fmt.Errorf("DNS response for %s has %d reachable A records; maximum is %d", name, len(results), maxDNSAddresses)
		}
		resolved[name] = results
		for _, result := range results {
			key := resultKey(result.IP)
			if previous, ok := effectiveA[key]; !ok || result.TTL < previous {
				effectiveA[key] = result.TTL
			}
		}
	}
	rewrite := func(resources []dnsmessage.Resource) {
		for index := range resources {
			resources[index].Header.TTL = clampDomainTTL(resources[index].Header.TTL)
			if body, ok := resources[index].Body.(*dnsmessage.AResource); ok {
				if ttl, found := effectiveA[resultKey(body.A)]; found && ttl < resources[index].Header.TTL {
					resources[index].Header.TTL = ttl
				}
			}
		}
	}
	rewrite(message.Answers)
	rewrite(message.Authorities)
	rewrite(message.Additionals)
	rewritten, err := message.Pack()
	if err != nil {
		return nil, nil, fmt.Errorf("repack DNS response: %w", err)
	}
	return rewritten, resolved, nil
}

func followCNAMEs(
	question string,
	cnames map[string][]cnameTarget,
	addresses map[string][]addressRecord,
) ([]resolvedAddress, error) {
	type pendingName struct {
		name  string
		ttl   uint32
		depth int
	}
	pending := []pendingName{{name: question, ttl: maxDomainGrantTTL}}
	// A malformed response can expose the same owner through multiple CNAME
	// paths. Revisit it only when the new path has a tighter TTL so a path
	// encountered first can never extend the derived authorization.
	bestNameTTL := make(map[string]uint32)
	results := make(map[[4]byte]uint32)
	for len(pending) != 0 {
		current := pending[0]
		pending = pending[1:]
		if current.depth > maxCNAMEChain {
			return nil, fmt.Errorf("DNS CNAME chain for %s exceeds %d links", question, maxCNAMEChain)
		}
		if previous, seen := bestNameTTL[current.name]; seen && previous <= current.ttl {
			continue
		}
		bestNameTTL[current.name] = current.ttl
		for _, record := range addresses[current.name] {
			ttl := minTTL(current.ttl, record.ttl)
			if previous, ok := results[record.ip]; !ok || ttl < previous {
				results[record.ip] = ttl
			}
		}
		for _, target := range cnames[current.name] {
			pending = append(pending, pendingName{
				name: target.name, ttl: minTTL(current.ttl, target.ttl), depth: current.depth + 1,
			})
		}
	}
	out := make([]resolvedAddress, 0, len(results))
	for ip, ttl := range results {
		out = append(out, resolvedAddress{IP: ip, TTL: ttl})
	}
	return out, nil
}

func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func clampDomainTTL(ttl uint32) uint32 {
	if ttl < minDomainGrantTTL {
		return minDomainGrantTTL
	}
	if ttl > maxDomainGrantTTL {
		return maxDomainGrantTTL
	}
	return ttl
}

func minTTL(left, right uint32) uint32 {
	if left < right {
		return left
	}
	return right
}

func resultKey(ip [4]byte) string {
	return string(ip[:])
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
