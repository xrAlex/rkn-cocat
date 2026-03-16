package runner

import (
	"strings"
	"testing"
	"unicode/utf8"

	"rkn-cocat/internal/entity"
)

func TestBuildInitialConfigLinesIncludesAllConfigKeys(t *testing.T) {
	cfg := entity.GlobalConfig{
		UseIPv4Only:         true,
		MaxConcurrent:       70,
		TimeoutSec:          7,
		TimeoutTCP1620Sec:   12,
		DomainCheckRetries:  3,
		TCP1620CheckRetries: 2,
		DpiVarianceThresh:   10,
		TCPBlockMinKB:       16,
		TCPBlockMaxKB:       20,
		BodyInspectLimit:    8192,
		DataReadThreshold:   24576,
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ExampleBrowser/1.0",
		BlockMarkers: []string{
			"lawfilter",
			"warning.rt.ru",
			"blocked",
			"access-denied",
		},
		BodyBlockMarkers: []string{
			"blocked",
			"заблокирован",
			"единый реестр",
			"warning.rt.ru",
		},
		SNIDiffProbeDomains: 5,
		DNSEDEProbeDomains:  6,
		DNSTransportDomains: 7,
		SweepProbeTargets:   8,
		SweepMinKB:          9,
		SweepMaxKB:          40,
		OONIProbeCC:         "RU",
		OONISinceDays:       180,
		OONIConcurrency:     2,
		OONITimeoutSec:      10,
		OONIBaseURL:         "https://api.ooni.io/api/v1",
		OONIUserAgent:       "rkn-cocat/ooni-1.0 test-agent",
		OONITCPPorts:        []int{443, 80},
		DNSCheckTimeout:     3,
		DNSBlockIPs:         []string{"10.10.10.10", "0.0.0.0", "127.0.0.1"},
		Files: entity.ConfigFiles{
			Domains: "tests/domains.yaml",
			IPs:     "tests/ips.yaml",
			DNS:     "tests/dns.yaml",
			CDN:     "tests/cdn.yaml",
		},
		DomainsToCheck:       []string{"example.com", "example.org"},
		DNSEDEDomains:        []string{"example.com", "example.org"},
		DNSEDELocalResolvers: []entity.UDPServer{{Name: "local-1", IP: "192.0.2.1"}},
		DNSEDEDoHServers:     []entity.DoHServer{{Name: "doh-1", URL: "https://dns.example/dns-query"}},
		DNSEDEDoTServers:     []entity.DoTServer{{Name: "dot-1", Address: "tls://1.1.1.1:853", ServerName: "dns.example"}},
		DNSMatrixDomains:     []string{"example.com"},
		DNSMatrixUDPServers:  []entity.UDPServer{{Name: "udp-1", IP: "192.0.2.2"}},
		DNSMatrixDoHServers:  []entity.DoHServer{{Name: "doh-2", URL: "https://dns.example/resolve"}},
		DNSMatrixDoTServers:  []entity.DoTServer{{Name: "dot-2", Address: "tls://1.0.0.1:853", ServerName: "resolver.example"}},
		SweepTargets:         []entity.TCPTarget{{ID: "cdn-1"}},
		OONIDomains:          []string{"example.com"},
		OONIIPs:              []string{"203.0.113.1"},
	}

	got := strings.Join(buildInitialConfigLines(cfg), "\n")
	expectedKeys := []string{
		"use_ipv4_only=",
		"max_concurrent=",
		"timeout_sec=",
		"timeout_tcp_1620_sec=",
		"domain_check_retries=",
		"tcp_1620_check_retries=",
		"dpi_variance_thresh=",
		"tcp_block_min_kb=",
		"tcp_block_max_kb=",
		"body_inspect_limit=",
		"data_read_threshold=",
		"user_agent=",
		"block_markers=",
		"body_block_markers=",
		"sni_diff_probe_domains=",
		"dns_ede_probe_domains=",
		"dns_transport_domains=",
		"sweep_probe_targets=",
		"sweep_min_kb=",
		"sweep_max_kb=",
		"dns_check_timeout=",
		"dns_block_ips=",
		"ooni_probe_cc=",
		"ooni_since_days=",
		"ooni_concurrency=",
		"ooni_timeout_sec=",
		"ooni_base_url=",
		"ooni_user_agent=",
		"ooni_tcp_ports=",
		"files.domains=",
		"files.ips=",
		"files.dns=",
		"files.cdn=",
	}

	for _, key := range expectedKeys {
		if !strings.Contains(got, key) {
			t.Fatalf("startup config is missing key %q\n%s", key, got)
		}
	}
}

func TestBuildInitialConfigLinesWrapsLongValues(t *testing.T) {
	cfg := entity.GlobalConfig{
		UserAgent: "Mozilla/5.0 Example Very Long User Agent String For Startup Output Validation",
		BlockMarkers: []string{
			"marker-one",
			"marker-two",
			"marker-three",
			"marker-four",
			"marker-five",
			"marker-six",
			"marker-seven",
			"marker-eight",
			"marker-nine",
		},
		BodyBlockMarkers: []string{
			"body-marker-one",
			"body-marker-two",
			"body-marker-three",
			"body-marker-four",
			"body-marker-five",
			"body-marker-six",
		},
		OONIBaseURL:   "https://api.ooni.io/api/v1/measurements?really=long&with=query&parameters=enabled",
		OONIUserAgent: "rkn-cocat/ooni-1.0 with a very long suffix for wrapping validation",
		DNSBlockIPs:   []string{"10.10.10.10", "0.0.0.0", "127.0.0.1", "203.0.113.10", "203.0.113.11", "203.0.113.12"},
		Files: entity.ConfigFiles{
			Domains: "configs/tests/domains.yaml",
			IPs:     "configs/tests/ips.yaml",
			DNS:     "configs/tests/dns.yaml",
			CDN:     "configs/tests/cdn.yaml",
		},
	}

	for _, line := range buildInitialConfigLines(cfg) {
		if utf8.RuneCountInString(line) > startupConfigLineWidth {
			t.Fatalf("line exceeds configured width: %q", line)
		}
	}
}
