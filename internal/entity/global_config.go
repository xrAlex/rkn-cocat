package entity

type GlobalConfig struct {
	UseIPv4Only         bool     // Принудительное использование IPv4 в сетевых dial/lookup.
	MaxConcurrent       int      // Лимит параллельных сетевых операций (через семафор-канал).
	TimeoutSec          float64  // Таймаут для проверок доменов (TLS/HTTP), в секундах.
	TimeoutTCP1620Sec   float64  // Отдельный таймаут для TCP 16-20KB теста, в секундах.
	DomainCheckRetries  int      // Количество повторов TLS/HTTP-проверки домена.
	TCP1620CheckRetries int      // Количество повторов TCP 16-20KB-проверки.
	DpiVarianceThresh   float64  // Порог процента "смешанных" результатов, после которого считаем DPI вариативным.
	TCPBlockMinKB       int      // Нижняя граница диапазона KB, где считаем обрыв признаком TCP16-20 типа блокировки.
	TCPBlockMaxKB       int      // Верхняя граница диапазона KB для детекта TCP16-20.
	BodyInspectLimit    int      // Максимум байт тела ответа для проверки маркеров блок-страницы.
	DataReadThreshold   int      // Порог байт "устойчивого чтения" в TCP16-20 тесте: если достигнут, цель считаем условно доступной.
	UserAgent           string   // User-Agent для HTTP(S) запросов.
	BlockMarkers        []string //
	BodyBlockMarkers    []string //

	SNIDiffProbeDomains int // Сколько доменов проверять в TLS SNI differential test (0 = все).

	DNSEDEProbeDomains  int     // Сколько доменов проверять в DNS EDE diagnostics (0 = все).
	DNSTransportDomains int     // Сколько доменов брать в матрицу DNS-транспортов (0 = все).
	SweepProbeTargets   int     // Сколько TCP-целей брать в size-sweep (0 = все).
	SweepMinKB          int     // Нижняя граница диапазона size-sweep.
	SweepMaxKB          int     // Верхняя граница диапазона size-sweep.
	OONIProbeCC         string  //
	OONISinceDays       int     //
	OONIConcurrency     int     //
	OONITimeoutSec      float64 //
	OONIBaseURL         string  //
	OONIUserAgent       string  //
	OONITCPPorts        []int   //

	DNSCheckTimeout float64  // Таймаут запроса к DNS/DoH/DoT в секундах.
	DNSBlockIPs     []string // Список IP-адресов блок-страниц/заглушек для DNS-диагностики.
	Files           ConfigFiles

	// Наборы данных, загружаемые из общих YAML-файлов.
	DNSEDEDomains        []string    // DNS EDE diagnostics.
	DNSEDELocalResolvers []UDPServer // DNS EDE diagnostics.
	DNSEDEDoHServers     []DoHServer // DNS EDE diagnostics.
	DNSEDEDoTServers     []DoTServer // DNS EDE diagnostics.

	DomainsToCheck []string // Тесты 2-6.

	DNSMatrixDomains    []string    // DNS matrix.
	DNSMatrixUDPServers []UDPServer // DNS matrix.
	DNSMatrixDoHServers []DoHServer // DNS matrix.
	DNSMatrixDoTServers []DoTServer // DNS matrix.

	SweepTargets []TCPTarget // Size sweep.

	OONIDomains []string // OONI blocking check (domains) !Есть лдимит на количество запросов.
	OONIIPs     []string // OONI blocking check (ips) !Есть лдимит на количество запросов.
}
