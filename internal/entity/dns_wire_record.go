package entity

type DNSWireRecord struct {
	Type uint16
	Data string
	TTL  uint32
}
