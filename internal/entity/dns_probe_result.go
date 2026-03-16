package entity

type DNSProbeResult struct {
	OK      int
	Timeout int
	Error   int
	Blocked int
	Results map[string]any
}
