package entity

type DNSWireMessage struct {
	RCode   int
	Answers []DNSWireRecord
	EDE     []DNSEDEOption
}
