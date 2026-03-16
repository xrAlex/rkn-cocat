package entity

type DNSEDEStats struct {
	Total               int
	Valid               int
	NXDOMAIN            int
	SERVFAIL            int
	Timeout             int
	Error               int
	BlockHint           int
	EDEBlocked          int
	NXDOMAINResources   []string
	SERVFAILResources   []string
	TimeoutResources    []string
	BlockHintResources  []string
	EDEBlockedResources []string
}
