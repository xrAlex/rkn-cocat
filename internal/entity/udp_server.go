package entity

type UDPServer struct {
	IP   string `json:"ip" yaml:"ip"`     // IP адрес DNS-сервера (без порта, порт 53 добавляется в коде).
	Name string `json:"name" yaml:"name"` // Человекочитаемое название провайдера DNS.
}
