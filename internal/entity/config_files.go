package entity

type ConfigFiles struct {
	Domains string `json:"domains" yaml:"domains"`
	IPs     string `json:"ips" yaml:"ips"`
	DNS     string `json:"dns" yaml:"dns"`
	CDN     string `json:"cdn" yaml:"cdn"`
}
