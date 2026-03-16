package ooni

import (
	"context"
	"net/http"

	"rkn-cocat/internal/entity"
)

type ooniMeasurementsResponse struct {
	Metadata any                  `json:"metadata"`
	Results  []ooniMeasurementRow `json:"results"`
}

type ooniMeasurementRow struct {
	MeasurementURL string `json:"measurement_url"`
	MeasurementUID string `json:"measurement_uid"`
	ReportID       string `json:"report_id"`
	ProbeCC        string `json:"probe_cc"`
	ProbeASN       string `json:"probe_asn"`
	TestName       string `json:"test_name"`
	StartTime      string `json:"measurement_start_time"`
	Input          any    `json:"input"`
	Anomaly        bool   `json:"anomaly"`
	Confirmed      bool   `json:"confirmed"`
	Failure        bool   `json:"failure"`
	Scores         any    `json:"scores"`
}

type ooniService struct {
	ctx    context.Context
	client *http.Client
	cfg    entity.OONIRuntimeConfig
}

type progressFunc func(done int, total int, target string)

type ooniJob struct {
	Target     string
	TargetType string
}

const (
	ooniVerdictOK       string = statusOK
	ooniVerdictBlocked  string = statusBlocked
	ooniVerdictNoData   string = statusNoData
	ooniVerdictUnknown  string = statusUnknown
	ooniVerdictTCPFail  string = statusOONITCPFail
	ooniVerdictTCPReach string = statusOONITCPReachable
)

const (
	ooniTargetDomain = "domain"
	ooniTargetIP     = "ip"
	ooniTestWeb      = "web_connectivity"
	ooniTestTCP      = "tcp_connect"
)

const ooniMaxSinceDays = 180
