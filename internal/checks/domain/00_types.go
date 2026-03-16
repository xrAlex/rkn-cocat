package domain

import (
	"context"

	"rkn-cocat/internal/checks/classifier"
	checksdns "rkn-cocat/internal/checks/dns"
	"rkn-cocat/internal/entity"
)

const (
	dnsStateOK = iota
	dnsStateFail
	dnsStateFake
)

type Pipeline struct {
	ctx     context.Context
	sem     chan struct{}
	stubIPs map[string]struct{}
	checks  *transportCheckService
	dns     *checksdns.Service
}

type transportCheckService struct {
	ctx        context.Context
	cfg        entity.GlobalConfig
	sem        chan struct{}
	classifier *classifier.ErrorClassifier
}

type transportAttemptResult struct {
	Status  string
	Detail  string
	Elapsed float64
}

type domainPhaseRow struct {
	Domain string
	Status string
	Detail string
}

type sniDiffRow struct {
	Domain       string
	IP           string
	TCPStatus    string
	TargetSNI    string
	NoSNI        string
	Verdict      string
	Detail       string
	TargetDetail string
	NoSNIDetail  string
}

type sniDiffService struct {
	ctx        context.Context
	cfg        entity.GlobalConfig
	sem        chan struct{}
	classifier *classifier.ErrorClassifier
}

var tlsLegitRedirectMarkers = []string{
	"cloudflare", "akamai", "fastly", "cdn", "cloudfront",
	"auth", "login", "accounts", "id.", "sso.",
}
