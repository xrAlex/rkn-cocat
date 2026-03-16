package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	entity "rkn-cocat/internal/entity"
	"strings"

	"gopkg.in/yaml.v3"
)

type configService struct{}

func newConfigService() *configService {
	return &configService{}
}

func LoadConfig() (entity.GlobalConfig, error) {
	return newConfigService().load()
}

func (s *configService) load() (entity.GlobalConfig, error) {
	configPath := strings.TrimSpace(os.Getenv("CONFIG_FILE"))
	if configPath == "" {
		return s.loadFromFile(filepath.Join("configs", "config.yaml"))
	}

	return s.loadFromFile(configPath)
}

func (s *configService) loadFromFile(configPath string) (entity.GlobalConfig, error) {
	resolvedConfigPath := getResourcePath(configPath)
	b, err := os.ReadFile(resolvedConfigPath)
	if err != nil {
		return entity.GlobalConfig{}, fmt.Errorf("файл конфигурации %s не найден (%s)", configPath, resolvedConfigPath)
	}

	var raw entity.FileConfig
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return entity.GlobalConfig{}, fmt.Errorf("некорректный YAML в %s: %w", configPath, err)
	}

	files := entity.ConfigFiles{
		Domains: strings.TrimSpace(raw.Files.Domains),
		IPs:     strings.TrimSpace(raw.Files.IPs),
		DNS:     strings.TrimSpace(raw.Files.DNS),
		CDN:     strings.TrimSpace(raw.Files.CDN),
	}

	cfg := entity.GlobalConfig{
		UseIPv4Only:         raw.UseIPv4Only,
		MaxConcurrent:       raw.MaxConcurrent,
		TimeoutSec:          raw.TimeoutSec,
		TimeoutTCP1620Sec:   raw.TimeoutTCP1620Sec,
		DomainCheckRetries:  raw.DomainCheckRetries,
		TCP1620CheckRetries: raw.TCP1620CheckRetries,
		DpiVarianceThresh:   raw.DpiVarianceThresh,
		TCPBlockMinKB:       raw.TCPBlockMinKB,
		TCPBlockMaxKB:       raw.TCPBlockMaxKB,
		BodyInspectLimit:    raw.BodyInspectLimit,
		DataReadThreshold:   raw.DataReadThreshold,
		UserAgent:           raw.UserAgent,
		BlockMarkers:        raw.BlockMarkers,
		BodyBlockMarkers:    raw.BodyBlockMarkers,
		SNIDiffProbeDomains: raw.SNIDiffProbeDomains,

		DNSEDEProbeDomains:  raw.DNSEDEProbeDomains,
		DNSTransportDomains: raw.DNSTransportDomains,
		SweepProbeTargets:   raw.SweepProbeTargets,
		SweepMinKB:          raw.SweepMinKB,
		SweepMaxKB:          raw.SweepMaxKB,
		OONISinceDays:       raw.OONISinceDays,
		OONIConcurrency:     raw.OONIConcurrency,
		OONITimeoutSec:      raw.OONITimeoutSec,
		OONIProbeCC:         strings.ToUpper(strings.TrimSpace(raw.OONIProbeCC)),
		OONIBaseURL:         strings.TrimSpace(raw.OONIBaseURL),
		OONIUserAgent:       strings.TrimSpace(raw.OONIUserAgent),
		OONITCPPorts:        normalizePortList(raw.OONITCPPorts),

		DNSCheckTimeout: raw.DNSCheckTimeout,
		DNSBlockIPs:     normalizeIPList(raw.DNSBlockIPs),
		Files:           files,
	}

	if err := s.validateScalars(cfg); err != nil {
		return entity.GlobalConfig{}, err
	}
	if err := s.validateFiles(files); err != nil {
		return entity.GlobalConfig{}, err
	}

	domainsPath := s.resolveDataPath(resolvedConfigPath, files.Domains)
	ipsPath := s.resolveDataPath(resolvedConfigPath, files.IPs)
	dnsPath := s.resolveDataPath(resolvedConfigPath, files.DNS)
	cdnPath := s.resolveDataPath(resolvedConfigPath, files.CDN)

	domains, err := s.loadDomainsData(domainsPath)
	if err != nil {
		return entity.GlobalConfig{}, fmt.Errorf("domains: %w", err)
	}
	cfg.DomainsToCheck = append([]string(nil), domains...)
	cfg.DNSEDEDomains = append([]string(nil), domains...)
	cfg.DNSMatrixDomains = append([]string(nil), domains...)
	cfg.OONIDomains = append([]string(nil), domains...)

	cfg.OONIIPs, err = s.loadIPsData(ipsPath)
	if err != nil {
		return entity.GlobalConfig{}, fmt.Errorf("ips: %w", err)
	}

	cfg.DNSEDELocalResolvers, cfg.DNSEDEDoHServers, cfg.DNSEDEDoTServers, cfg.DNSMatrixUDPServers, cfg.DNSMatrixDoHServers, cfg.DNSMatrixDoTServers, err = s.loadDNSData(dnsPath)
	if err != nil {
		return entity.GlobalConfig{}, fmt.Errorf("dns: %w", err)
	}

	cfg.SweepTargets, err = loadTCPTargets(cdnPath)
	if err != nil {
		return entity.GlobalConfig{}, fmt.Errorf("cdn: %w", err)
	}

	if len(cfg.OONIDomains) == 0 && len(cfg.OONIIPs) == 0 {
		return entity.GlobalConfig{}, fmt.Errorf("набор OONI целей пуст: добавьте domains в %s или ips в %s", domainsPath, ipsPath)
	}

	return cfg, nil
}

func (s *configService) resolveDataPath(configFilePath string, filePath string) string {
	trimmed := strings.TrimSpace(filePath)
	if trimmed == "" {
		return trimmed
	}
	if filepath.IsAbs(trimmed) {
		return trimmed
	}
	return filepath.Join(filepath.Dir(configFilePath), trimmed)
}

func (s *configService) validateScalars(cfg entity.GlobalConfig) error {
	if cfg.MaxConcurrent <= 0 {
		return fmt.Errorf("в конфиге max_concurrent должен быть > 0")
	}
	if cfg.TimeoutSec <= 0 || cfg.TimeoutTCP1620Sec <= 0 {
		return fmt.Errorf("в конфиге timeout_sec и timeout_tcp_1620_sec должны быть > 0")
	}
	if cfg.DomainCheckRetries <= 0 || cfg.TCP1620CheckRetries <= 0 {
		return fmt.Errorf("в конфиге retries должны быть >= 1")
	}
	if cfg.TCPBlockMinKB <= 0 || cfg.TCPBlockMaxKB < cfg.TCPBlockMinKB {
		return fmt.Errorf("в конфиге tcp_block_min_kb/tcp_block_max_kb заданы некорректно")
	}
	if cfg.DNSCheckTimeout <= 0 {
		return fmt.Errorf("в конфиге dns_check_timeout должен быть > 0")
	}
	if cfg.SNIDiffProbeDomains < 0 || cfg.DNSEDEProbeDomains < 0 || cfg.DNSTransportDomains < 0 || cfg.SweepProbeTargets < 0 {
		return fmt.Errorf("в конфиге sni_diff_probe_domains/dns_ede_probe_domains/dns_transport_domains/sweep_probe_targets не могут быть < 0")
	}
	if cfg.OONISinceDays < 0 {
		return fmt.Errorf("в конфиге ooni_since_days не может быть < 0")
	}
	if cfg.OONIConcurrency <= 0 {
		return fmt.Errorf("в конфиге ooni_concurrency должен быть > 0")
	}
	if cfg.OONITimeoutSec <= 0 {
		return fmt.Errorf("в конфиге ooni_timeout_sec должен быть > 0")
	}
	if strings.TrimSpace(cfg.OONIProbeCC) == "" {
		return fmt.Errorf("в конфиге ooni_probe_cc не должен быть пустым")
	}
	if strings.TrimSpace(cfg.OONIBaseURL) == "" {
		return fmt.Errorf("в конфиге ooni_base_url не должен быть пустым")
	}
	if strings.TrimSpace(cfg.OONIUserAgent) == "" {
		return fmt.Errorf("в конфиге ooni_user_agent не должен быть пустым")
	}
	if len(cfg.OONITCPPorts) == 0 {
		return fmt.Errorf("в конфиге ooni_tcp_ports должен содержать хотя бы один порт")
	}
	for _, port := range cfg.OONITCPPorts {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("в конфиге ooni_tcp_ports содержит некорректный порт %d", port)
		}
	}
	if cfg.SweepMinKB <= 0 || cfg.SweepMaxKB < cfg.SweepMinKB {
		return fmt.Errorf("в конфиге sweep_min_kb/sweep_max_kb заданы некорректно")
	}
	if strings.TrimSpace(cfg.UserAgent) == "" {
		return fmt.Errorf("в конфиге user_agent не должен быть пустым")
	}
	return nil
}

func (s *configService) validateFiles(files entity.ConfigFiles) error {
	required := map[string]string{
		"files.domains": files.Domains,
		"files.ips":     files.IPs,
		"files.dns":     files.DNS,
		"files.cdn":     files.CDN,
	}
	for key, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("в конфиге не задан обязательный путь %s", key)
		}
	}
	return nil
}

func (s *configService) loadYAMLFile(filePath string, out any) error {
	fullPath := getResourcePath(filePath)
	b, err := os.ReadFile(fullPath)
	if err != nil {
		return fmt.Errorf("файл %s не найден (%s)", filePath, fullPath)
	}
	if err := yaml.Unmarshal(b, out); err != nil {
		return fmt.Errorf("некорректный YAML в %s: %w", filePath, err)
	}
	return nil
}

func (s *configService) loadDomainsData(filePath string) ([]string, error) {
	var data entity.DomainsDataFile
	if err := s.loadYAMLFile(filePath, &data); err != nil {
		return nil, err
	}

	return s.normalizeDomains(data.Domains, filePath, "domains")
}

func (s *configService) loadIPsData(filePath string) ([]string, error) {
	var data entity.IPsDataFile
	if err := s.loadYAMLFile(filePath, &data); err != nil {
		return nil, err
	}

	ips := make([]string, 0, len(data.IPs))
	for i, item := range data.IPs {
		ip := strings.TrimSpace(item)
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf("секция ips в %s содержит некорректный IP %q (индекс %d)", filePath, ip, i)
		}
		ips = append(ips, ip)
	}
	return uniqueStrings(ips), nil
}

func (s *configService) loadDNSData(filePath string) ([]entity.UDPServer, []entity.DoHServer, []entity.DoTServer, []entity.UDPServer, []entity.DoHServer, []entity.DoTServer, error) {
	var data entity.DNSDataFile
	if err := s.loadYAMLFile(filePath, &data); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	localResolvers, err := s.normalizeUDPServers(data.LocalResolvers, filePath, "local_resolvers")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	udpServers, err := s.normalizeUDPServers(data.UDPServers, filePath, "udp_servers")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	dohServers, err := s.normalizeDoHServers(data.DoHServers, filePath, "doh_servers")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	dotServers, err := s.normalizeDoTServers(data.DoTServers, filePath, "dot_servers")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	return localResolvers, dohServers, dotServers, udpServers, append([]entity.DoHServer(nil), dohServers...), append([]entity.DoTServer(nil), dotServers...), nil
}

func (s *configService) normalizeDomains(items []string, filePath string, section string) ([]string, error) {
	domains := make([]string, 0, len(items))
	for _, item := range items {
		domain := strings.TrimSpace(item)
		if domain == "" {
			continue
		}
		domains = append(domains, domain)
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("секция %s в %s пуста", section, filePath)
	}
	return domains, nil
}

func normalizeIPList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		clean := strings.TrimSpace(item)
		if clean == "" {
			continue
		}
		out = append(out, clean)
	}
	return uniqueStrings(out)
}

func normalizePortList(items []int) []int {
	out := make([]int, 0, len(items))
	seen := make(map[int]struct{}, len(items))
	for _, port := range items {
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	return out
}

func (s *configService) normalizeUDPServers(items []entity.UDPServer, filePath string, section string) ([]entity.UDPServer, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("секция %s в %s пуста", section, filePath)
	}
	for i := range items {
		items[i].IP = strings.TrimSpace(items[i].IP)
		items[i].Name = strings.TrimSpace(items[i].Name)
		if items[i].IP == "" || items[i].Name == "" {
			return nil, fmt.Errorf("некорректная запись UDP DNS в секции %s файла %s (индекс %d)", section, filePath, i)
		}
	}
	return items, nil
}

func (s *configService) normalizeDoHServers(items []entity.DoHServer, filePath string, section string) ([]entity.DoHServer, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("секция %s в %s пуста", section, filePath)
	}
	for i := range items {
		items[i].URL = strings.TrimSpace(items[i].URL)
		items[i].Name = strings.TrimSpace(items[i].Name)
		if items[i].URL == "" || items[i].Name == "" {
			return nil, fmt.Errorf("некорректная запись DoH в секции %s файла %s (индекс %d)", section, filePath, i)
		}
	}
	return items, nil
}

func (s *configService) normalizeDoTServers(items []entity.DoTServer, filePath string, section string) ([]entity.DoTServer, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("секция %s в %s пуста", section, filePath)
	}
	for i := range items {
		items[i].Address = strings.TrimSpace(items[i].Address)
		items[i].Name = strings.TrimSpace(items[i].Name)
		items[i].ServerName = strings.TrimSpace(items[i].ServerName)
		if items[i].Address == "" || items[i].Name == "" || items[i].ServerName == "" {
			return nil, fmt.Errorf("некорректная запись DoT в секции %s файла %s (индекс %d)", section, filePath, i)
		}
	}
	return items, nil
}
