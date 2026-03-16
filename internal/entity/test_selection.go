package entity

import "strings"

const (
	TestSelectionDNSEDE    = "dns_ede"
	TestSelectionResolve   = "resolve"
	TestSelectionTLS13     = "tls13"
	TestSelectionTLS12     = "tls12"
	TestSelectionHTTP      = "http_injection"
	TestSelectionSNIDiff   = "sni_diff"
	TestSelectionDNSMatrix = "dns_matrix"
	TestSelectionSweep     = "size_sweep"
	TestSelectionOONI      = "ooni_blocking"
	TestSelectionSaveFile  = "save_report"
)

const DefaultTestSelection = TestSelectionDNSEDE + "," +
	TestSelectionResolve + "," +
	TestSelectionTLS13 + "," +
	TestSelectionTLS12 + "," +
	TestSelectionHTTP + "," +
	TestSelectionSNIDiff + "," +
	TestSelectionDNSMatrix + "," +
	TestSelectionSweep

func ParseTestSelectionSet(selection string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, token := range strings.Split(selection, ",") {
		id := strings.TrimSpace(token)
		if id == "" {
			continue
		}
		set[id] = struct{}{}
	}
	return set
}
