package entity

type DomainStats struct {
	Total            int
	OK               int
	Blocked          int
	Timeout          int
	DNSFail          int
	BlockedResources []string
	TimeoutResources []string
	DNSFailResources []string
}
