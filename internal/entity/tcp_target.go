package entity

type TCPTarget struct {
	ID       string `json:"id" yaml:"id"`
	ASN      string `json:"asn" yaml:"asn"`
	Provider string `json:"provider" yaml:"provider"`
	URL      string `json:"url" yaml:"url"`
	Resource string `json:"resource" yaml:"resource"`
	IP       string `json:"ip" yaml:"ip"`
}
