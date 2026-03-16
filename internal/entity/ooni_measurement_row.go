package entity

type OONIMeasurementRow struct {
	MeasurementURL string `json:"measurement_url"`
	ReportID       string `json:"report_id"`
	ProbeCC        string `json:"probe_cc"`
	ProbeASN       string `json:"probe_asn"`
	TestName       string `json:"test_name"`
	StartTime      string `json:"measurement_start_time"`
	Input          any    `json:"input"`
	Anomaly        bool   `json:"anomaly"`
	Confirmed      bool   `json:"confirmed"`
	Failure        bool   `json:"failure"`
}
