package entity

type DNSRR struct {
	Type       uint16
	Class      uint16
	TTL        uint32
	RData      []byte
	RDataOff   int
	NextOffset int
}
