package entity

type DNSDataFile struct {
	LocalResolvers []UDPServer `json:"local_resolvers" yaml:"local_resolvers"`
	UDPServers     []UDPServer `json:"udp_servers" yaml:"udp_servers"`
	DoHServers     []DoHServer `json:"doh_servers" yaml:"doh_servers"`
	DoTServers     []DoTServer `json:"dot_servers" yaml:"dot_servers"`
}
