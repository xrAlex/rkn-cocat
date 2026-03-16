package entity

type DoTServer struct {
	Address    string `json:"address" yaml:"address"`         // endpoint в формате host:port.
	Name       string `json:"name" yaml:"name"`               // Отображаемое имя сервиса.
	ServerName string `json:"server_name" yaml:"server_name"` // SNI/имя для TLS-проверки сертификата.
}
