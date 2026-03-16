package entity

type DomainEntry struct {
	Domain     string
	ResolvedIP string
	DNSState   int
	T13Res     TLSResult
	T12Res     TLSResult
	HTTPRes    HTTPResult
}
