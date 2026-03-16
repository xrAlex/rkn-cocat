package entity

type FileConfig struct {
	UseIPv4Only         bool     `json:"use_ipv4_only" yaml:"use_ipv4_only"`
	MaxConcurrent       int      `json:"max_concurrent" yaml:"max_concurrent"`
	TimeoutSec          float64  `json:"timeout_sec" yaml:"timeout_sec"`
	TimeoutTCP1620Sec   float64  `json:"timeout_tcp_1620_sec" yaml:"timeout_tcp_1620_sec"`
	DomainCheckRetries  int      `json:"domain_check_retries" yaml:"domain_check_retries"`
	TCP1620CheckRetries int      `json:"tcp_1620_check_retries" yaml:"tcp_1620_check_retries"`
	DpiVarianceThresh   float64  `json:"dpi_variance_thresh" yaml:"dpi_variance_thresh"`
	TCPBlockMinKB       int      `json:"tcp_block_min_kb" yaml:"tcp_block_min_kb"`
	TCPBlockMaxKB       int      `json:"tcp_block_max_kb" yaml:"tcp_block_max_kb"`
	BodyInspectLimit    int      `json:"body_inspect_limit" yaml:"body_inspect_limit"`
	DataReadThreshold   int      `json:"data_read_threshold" yaml:"data_read_threshold"`
	UserAgent           string   `json:"user_agent" yaml:"user_agent"`
	BlockMarkers        []string `json:"block_markers" yaml:"block_markers"`
	BodyBlockMarkers    []string `json:"body_block_markers" yaml:"body_block_markers"`
	SNIDiffProbeDomains int      `json:"sni_diff_probe_domains" yaml:"sni_diff_probe_domains"`
	DNSEDEProbeDomains  int      `json:"dns_ede_probe_domains" yaml:"dns_ede_probe_domains"`
	DNSTransportDomains int      `json:"dns_transport_domains" yaml:"dns_transport_domains"`
	SweepProbeTargets   int      `json:"sweep_probe_targets" yaml:"sweep_probe_targets"`
	SweepMinKB          int      `json:"sweep_min_kb" yaml:"sweep_min_kb"`
	SweepMaxKB          int      `json:"sweep_max_kb" yaml:"sweep_max_kb"`
	OONISinceDays       int      `json:"ooni_since_days" yaml:"ooni_since_days"`
	OONIConcurrency     int      `json:"ooni_concurrency" yaml:"ooni_concurrency"`
	OONITimeoutSec      float64  `json:"ooni_timeout_sec" yaml:"ooni_timeout_sec"`
	OONIProbeCC         string   `json:"ooni_probe_cc" yaml:"ooni_probe_cc"`
	OONIBaseURL         string   `json:"ooni_base_url" yaml:"ooni_base_url"`
	OONIUserAgent       string   `json:"ooni_user_agent" yaml:"ooni_user_agent"`
	OONITCPPorts        []int    `json:"ooni_tcp_ports" yaml:"ooni_tcp_ports"`

	DNSCheckTimeout float64  `json:"dns_check_timeout" yaml:"dns_check_timeout"`
	DNSBlockIPs     []string `json:"dns_block_ips" yaml:"dns_block_ips"`

	Files ConfigFiles `json:"files" yaml:"files"`
}
