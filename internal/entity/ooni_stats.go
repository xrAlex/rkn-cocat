package entity

type OONIStats struct {
	Total             int
	OK                int
	Blocked           int
	NoData            int
	Unknown           int
	TCPFail           int
	TCPReachable      int
	BlockedResources  []string
	TCPFailResources  []string
	UnknownResources  []string
	NoDataResources   []string
	TCPReachResources []string
}
