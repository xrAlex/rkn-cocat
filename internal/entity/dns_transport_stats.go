package entity

type DNSTransportStats struct {
	Total             int
	AllOK             int
	Partial           int
	Blocked           int
	Diverged          int
	BlockedResources  []string
	PartialResources  []string
	DivergedResources []string
}
