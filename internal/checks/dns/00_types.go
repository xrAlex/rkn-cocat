package dns

import (
	"context"

	"rkn-cocat/internal/entity"
)

type dnsService struct {
	ctx    context.Context
	cfg    entity.GlobalConfig
	dnsEDE *dnsEDEService
}

type dohJSONAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}

type dohJSONResponse struct {
	Status int             `json:"Status"`
	Answer []dohJSONAnswer `json:"Answer"`
}

type dnsWireResult struct {
	Status  string
	Detail  string
	Message entity.DNSWireMessage
}

type dnsEDEEndpoint struct {
	Name      string
	Transport string
	Query     func(domain string, qType uint16) dnsWireResult
}

type dnsEDEProbeRow struct {
	Domain     string
	Resolver   string
	Transport  string
	A          string
	AAAA       string
	TTL        string
	RCode      string
	EDE        string
	Verdict    string
	Detail     string
	BlockHint  bool
	EDEBlocked bool
	Resource   string
}

type dnsEDEService struct {
	ctx        context.Context
	cfg        entity.GlobalConfig
	classifier *errorClassifier
}

type dnsEDEProbeJob struct {
	index    int
	domain   string
	endpoint dnsEDEEndpoint
}

type dnsTransportOutcome struct {
	Status string
	Detail string
	Server string
	IPs    []string
}

type dnsTransportMatrixService struct {
	ctx        context.Context
	cfg        entity.GlobalConfig
	dns        *dnsService
	classifier *errorClassifier
}

type dnsTransportMatrixRow struct {
	Domain   string
	UDP      dnsTransportOutcome
	TCP      dnsTransportOutcome
	DoH      dnsTransportOutcome
	DoT      dnsTransportOutcome
	Final    string
	Diverged bool
}

type transportProbeState struct {
	blocked    int
	timeouts   int
	lastDetail string
}
