package common

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"rkn-cocat/internal/entity"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	reParen      = regexp.MustCompile(`\s*\([^)]*\)?\s*`)
	reTail       = regexp.MustCompile(`\s*\(_*\s*$`)
	reSpace      = regexp.MustCompile(`\s+`)
	reHTTPStatus = regexp.MustCompile(`^HTTP [23]\d\d$`)
	reProvider   = regexp.MustCompile(`[^\w\s\.-]`)
)

const (
	DNSTypeA     uint16 = 1
	DNSTypeCNAME uint16 = 5
	DNSTypeAAAA  uint16 = 28
	DNSTypeOPT   uint16 = 41
	DNSClassIN   uint16 = 1
	DNSOptionEDE uint16 = 15
)

func LimitItems[T any](items []T, max int) []T {
	if max <= 0 || max >= len(items) {
		return items
	}
	return items[:max]
}

func CleanHostname(urlOrDomain string) string {
	urlOrDomain = strings.TrimSpace(strings.ToLower(urlOrDomain))
	if !strings.Contains(urlOrDomain, "://") {
		urlOrDomain = "http://" + urlOrDomain
	}
	parsed, err := url.Parse(urlOrDomain)
	if err != nil {
		host := strings.TrimPrefix(strings.TrimPrefix(urlOrDomain, "http://"), "https://")
		if idx := strings.Index(host, "/"); idx >= 0 {
			host = host[:idx]
		}
		return strings.TrimSpace(host)
	}
	host := parsed.Host
	if host == "" {
		host = parsed.Path
	}
	if strings.Contains(host, "/") {
		host = strings.SplitN(host, "/", 2)[0]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.Count(host, ":") == 1 {
		host = strings.Split(host, ":")[0]
	}
	return host
}

func UniqueStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func ContainsAny(text string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

func BuildDNSQuery(domain string, qType uint16) ([]byte, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return nil, errors.New("empty domain")
	}

	msg := make([]byte, 12)
	idBytes := make([]byte, 2)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	copy(msg[0:2], idBytes)
	msg[2] = 0x01 // recursion desired
	msg[5] = 0x01 // QDCOUNT = 1

	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return nil, errors.New("invalid label")
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00) // end of qname

	qTypeBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(qTypeBuf, qType)
	msg = append(msg, qTypeBuf...)
	msg = append(msg, 0x00, 0x01) // QCLASS = IN
	return msg, nil
}

func SecondsToDuration(seconds float64) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds * float64(time.Second))
}

func DomainTimeout(cfg entity.GlobalConfig) time.Duration {
	return SecondsToDuration(cfg.TimeoutSec)
}

func TCP1620Timeout(cfg entity.GlobalConfig) time.Duration {
	return SecondsToDuration(cfg.TimeoutTCP1620Sec)
}

func DNSTimeout(cfg entity.GlobalConfig) time.Duration {
	return SecondsToDuration(cfg.DNSCheckTimeout)
}

func CleanDetail(detail string) string {
	if detail == "" || detail == StatusOK || detail == "Error" {
		return ""
	}
	detail = strings.ReplaceAll(detail, "The operation did not complete", "TLS Aborted")
	detail = reParen.ReplaceAllString(detail, " ")
	detail = reTail.ReplaceAllString(detail, "")
	detail = reSpace.ReplaceAllString(detail, " ")
	detail = strings.TrimSpace(detail)
	detail = strings.ReplaceAll(detail, "Err None: ", "")
	detail = strings.ReplaceAll(detail, "Conn failed: ", "")
	if reHTTPStatus.MatchString(detail) {
		return ""
	}
	return strings.TrimSpace(detail)
}

func ParseDNSWireMessage(msg []byte) (entity.DNSWireMessage, error) {
	if len(msg) < 12 {
		return entity.DNSWireMessage{}, errors.New("short dns message")
	}

	out := entity.DNSWireMessage{
		RCode: int(msg[3] & 0x0F),
	}

	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	arCount := int(binary.BigEndian.Uint16(msg[10:12]))

	offset := 12
	for i := 0; i < qdCount; i++ {
		_, next, err := readDNSName(msg, offset)
		if err != nil {
			return out, err
		}
		offset = next + 4 // qtype + qclass
		if offset > len(msg) {
			return out, errors.New("bad question section")
		}
	}

	for i := 0; i < anCount; i++ {
		rr, err := readDNSRR(msg, offset)
		if err != nil {
			return out, err
		}
		offset = rr.NextOffset

		switch rr.Type {
		case DNSTypeA:
			if rr.Class == DNSClassIN && len(rr.RData) == net.IPv4len {
				out.Answers = append(out.Answers, entity.DNSWireRecord{
					Type: rr.Type,
					Data: net.IP(rr.RData).String(),
					TTL:  rr.TTL,
				})
			}
		case DNSTypeAAAA:
			if rr.Class == DNSClassIN && len(rr.RData) == net.IPv6len {
				out.Answers = append(out.Answers, entity.DNSWireRecord{
					Type: rr.Type,
					Data: net.IP(rr.RData).String(),
					TTL:  rr.TTL,
				})
			}
		case DNSTypeCNAME:
			name, _, err := readDNSName(msg, rr.RDataOff)
			if err == nil {
				out.Answers = append(out.Answers, entity.DNSWireRecord{
					Type: rr.Type,
					Data: name,
					TTL:  rr.TTL,
				})
			}
		}
	}

	for i := 0; i < nsCount; i++ {
		rr, err := readDNSRR(msg, offset)
		if err != nil {
			return out, err
		}
		offset = rr.NextOffset
	}

	for i := 0; i < arCount; i++ {
		rr, err := readDNSRR(msg, offset)
		if err != nil {
			return out, err
		}
		offset = rr.NextOffset
		if rr.Type == DNSTypeOPT {
			out.EDE = append(out.EDE, parseEDEOptions(rr.RData)...)
		}
	}

	out.Answers = uniqueDNSWireRecords(out.Answers)
	out.EDE = uniqueDNSWireEDE(out.EDE)
	return out, nil
}

func readDNSRR(msg []byte, offset int) (entity.DNSRR, error) {
	_, next, err := readDNSName(msg, offset)
	if err != nil {
		return entity.DNSRR{}, err
	}
	offset = next
	if offset+10 > len(msg) {
		return entity.DNSRR{}, errors.New("bad rr header")
	}

	rrType := binary.BigEndian.Uint16(msg[offset : offset+2])
	rrClass := binary.BigEndian.Uint16(msg[offset+2 : offset+4])
	ttl := binary.BigEndian.Uint32(msg[offset+4 : offset+8])
	rdLen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
	offset += 10
	if offset+rdLen > len(msg) {
		return entity.DNSRR{}, errors.New("bad rr data size")
	}

	return entity.DNSRR{
		Type:       rrType,
		Class:      rrClass,
		TTL:        ttl,
		RData:      msg[offset : offset+rdLen],
		RDataOff:   offset,
		NextOffset: offset + rdLen,
	}, nil
}

func parseEDEOptions(rdata []byte) []entity.DNSEDEOption {
	items := make([]entity.DNSEDEOption, 0, 1)
	offset := 0
	for offset+4 <= len(rdata) {
		optCode := binary.BigEndian.Uint16(rdata[offset : offset+2])
		optLen := int(binary.BigEndian.Uint16(rdata[offset+2 : offset+4]))
		offset += 4
		if offset+optLen > len(rdata) {
			break
		}
		optionData := rdata[offset : offset+optLen]
		offset += optLen

		if optCode != DNSOptionEDE || len(optionData) < 2 {
			continue
		}
		infoCode := binary.BigEndian.Uint16(optionData[:2])
		extraText := strings.TrimSpace(string(optionData[2:]))
		items = append(items, entity.DNSEDEOption{
			Code: infoCode,
			Text: extraText,
		})
	}
	return items
}

func uniqueDNSWireRecords(items []entity.DNSWireRecord) []entity.DNSWireRecord {
	if len(items) == 0 {
		return items
	}
	out := make([]entity.DNSWireRecord, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		key := fmt.Sprintf("%d|%s|%d", item.Type, item.Data, item.TTL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func uniqueDNSWireEDE(items []entity.DNSEDEOption) []entity.DNSEDEOption {
	if len(items) == 0 {
		return items
	}
	out := make([]entity.DNSEDEOption, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		key := fmt.Sprintf("%d|%s", item.Code, strings.TrimSpace(item.Text))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func readDNSName(msg []byte, offset int) (string, int, error) {
	labels := make([]string, 0, 4)
	pos := offset
	nextOffset := -1
	jumps := 0

	for {
		if pos >= len(msg) {
			return "", 0, errors.New("name out of range")
		}

		labelLen := int(msg[pos])
		switch {
		case labelLen == 0:
			if nextOffset == -1 {
				nextOffset = pos + 1
			}
			return strings.Join(labels, "."), nextOffset, nil
		case labelLen&0xC0 == 0xC0:
			if pos+1 >= len(msg) {
				return "", 0, errors.New("bad compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3FFF)
			if ptr >= len(msg) {
				return "", 0, errors.New("compression pointer out of range")
			}
			if nextOffset == -1 {
				nextOffset = pos + 2
			}
			pos = ptr
			jumps++
			if jumps > 20 {
				return "", 0, errors.New("dns name compression loop")
			}
		default:
			pos++
			if pos+labelLen > len(msg) {
				return "", 0, errors.New("name label out of range")
			}
			labels = append(labels, string(msg[pos:pos+labelLen]))
			pos += labelLen
		}
	}
}

func NewConfiguredRequest(ctx context.Context, method string, rawURL string, body io.Reader, cfg entity.GlobalConfig) (*http.Request, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	applyRequestHeaders(req, cfg.UserAgent)
	return req, nil
}

func applyRequestHeaders(req *http.Request, userAgent string) {
	if req == nil {
		return
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "close")
}

func NewHTTPTransport(cfg entity.GlobalConfig, tlsCfg *tls.Config, timeout time.Duration) *http.Transport {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if cfg.UseIPv4Only {
			if strings.HasPrefix(network, "tcp") {
				network = "tcp4"
			}
			if strings.HasPrefix(network, "udp") {
				network = "udp4"
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContext,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     true,
	}
}

func NewNoRedirectHTTPClient(cfg entity.GlobalConfig, tlsCfg *tls.Config, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: NewHTTPTransport(cfg, tlsCfg, timeout),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func WithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func SleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func Acquire(ctx context.Context, sem chan struct{}) bool {
	if sem == nil {
		return true
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func Release(sem chan struct{}) {
	if sem == nil {
		return
	}
	<-sem
}

func RunParallelContext(ctx context.Context, count int, fn func(context.Context, int)) error {
	if count <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}
			fn(ctx, idx)
		}()
	}
	wg.Wait()
	return ctx.Err()
}

func TakeFirst(items []string, limit int) []string {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func ExtractIPs(value any) []string {
	switch typedValue := value.(type) {
	case []string:
		return typedValue
	case []any:
		out := make([]string, 0, len(typedValue))
		for _, x := range typedValue {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func StrVal(value any) string {
	stringValue, _ := value.(string)
	return stringValue
}

func SameSet(left []string, right []string) bool {
	leftSet := map[string]struct{}{}
	rightSet := map[string]struct{}{}
	for _, x := range left {
		leftSet[x] = struct{}{}
	}
	for _, x := range right {
		rightSet[x] = struct{}{}
	}
	if len(leftSet) != len(rightSet) {
		return false
	}
	for k := range leftSet {
		if _, ok := rightSet[k]; !ok {
			return false
		}
	}
	return true
}

func ExtractLocationDomain(loc string) string {
	if loc == "" {
		return ""
	}
	if !strings.HasPrefix(loc, "http://") && !strings.HasPrefix(loc, "https://") {
		loc = "https://" + loc
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func BuildResourceLabel(domain string, id string, provider string) string {
	base := strings.TrimSpace(domain)
	if base == "" {
		base = strings.TrimSpace(id)
	}
	if base == "" {
		base = strings.TrimSpace(provider)
	}
	if base == "" {
		base = "неизвестная цель"
	}
	cleanID := strings.TrimSpace(id)
	if cleanID != "" && cleanID != base {
		return fmt.Sprintf("%s [%s]", base, cleanID)
	}
	return base
}

func IsTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func ExtractTargetDomain(rawURL string) string {
	parsed, _ := url.Parse(rawURL)
	domain := parsed.Hostname()
	if domain == "" {
		domain = CleanHostname(rawURL)
	}
	return domain
}

func GetGroupName(provider string) string {
	clean := strings.TrimSpace(reProvider.ReplaceAllString(provider, ""))
	parts := strings.Fields(clean)
	if len(parts) == 0 {
		return clean
	}
	return parts[0]
}

func ExtractIDNum(id string) int {
	parts := strings.Split(id, "-")
	if len(parts) == 0 {
		return 99999
	}
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return 99999
	}
	return n
}
