package entity

type SweepStats struct {
	Total                  int
	Pass                   int
	BreakInRange           int
	BreakOutRange          int
	DNSFail                int
	Error                  int
	BreakInRangeResources  []string
	BreakOutRangeResources []string
	DNSFailResources       []string
	ErrorResources         []string
}
