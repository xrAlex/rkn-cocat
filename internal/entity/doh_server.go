package entity

type DoHServer struct {
	URL  string `json:"url" yaml:"url"`   // Полный URL DoH endpoint.
	Name string `json:"name" yaml:"name"` // Отображаемое имя сервиса.
}
