package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	entity "rkn-cocat/internal/entity"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	reProvider = regexp.MustCompile(`[^\w\s\.-]`)
)

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func getResourcePath(relativePath string) string {
	if filepath.IsAbs(relativePath) {
		return relativePath
	}

	exeDir := getExeDir()
	cwd, _ := os.Getwd()
	candidates := []string{
		filepath.Join(exeDir, relativePath),
		filepath.Join(cwd, relativePath),
		filepath.Join(cwd, "GO", relativePath),
		filepath.Join(filepath.Dir(exeDir), "GO", relativePath),
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c
		}
	}
	return filepath.Join(exeDir, relativePath)
}

func getExeDir() string {
	exe, err := os.Executable()
	if err != nil {
		cwd, _ := os.Getwd()
		return cwd
	}
	return filepath.Dir(exe)
}

func loadTCPTargets(filepathName string) ([]entity.TCPTarget, error) {
	fullPath := getResourcePath(filepathName)
	b, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("файл %s не найден (%s)", filepathName, fullPath)
	}
	var targets []entity.TCPTarget
	if err := yaml.Unmarshal(b, &targets); err != nil {
		return nil, fmt.Errorf("некорректный YAML в %s: %w", filepathName, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("файл %s пуст", filepathName)
	}

	providerCounters := make(map[string]int, len(targets))
	usedIDs := make(map[string]struct{}, len(targets))
	for i := range targets {
		targets[i].ID = strings.TrimSpace(targets[i].ID)
		targets[i].ASN = strings.TrimSpace(targets[i].ASN)
		targets[i].Provider = strings.TrimSpace(targets[i].Provider)
		targets[i].URL = normalizeTargetURL(targets[i].URL, targets[i].Resource)
		targets[i].Resource = strings.TrimSpace(targets[i].Resource)
		targets[i].IP = strings.TrimSpace(targets[i].IP)

		if targets[i].URL == "" {
			return nil, fmt.Errorf("некорректная запись TCP цели в %s (индекс %d): не задан url/resource", filepathName, i)
		}
		if targets[i].IP != "" && net.ParseIP(targets[i].IP) == nil {
			return nil, fmt.Errorf("некорректная запись TCP цели в %s (индекс %d): неверный ip %q", filepathName, i, targets[i].IP)
		}
		if targets[i].Provider == "" {
			targets[i].Provider = extractTargetDomain(targets[i].URL)
			if targets[i].Provider == "" {
				targets[i].Provider = "unknown"
			}
		}
		if targets[i].ID == "" {
			group := strings.ToLower(getGroupName(targets[i].Provider))
			if group == "" {
				group = "target"
			}
			providerCounters[group]++
			targets[i].ID = fmt.Sprintf("%s-%d", group, providerCounters[group])
		}
		targets[i].ID = makeUniqueTargetID(targets[i].ID, usedIDs)
		usedIDs[targets[i].ID] = struct{}{}
	}
	return targets, nil
}

func normalizeTargetURL(rawURL string, resource string) string {
	targetURL := strings.TrimSpace(rawURL)
	if targetURL == "" {
		targetURL = strings.TrimSpace(resource)
	}
	if strings.HasPrefix(targetURL, "ttps://") {
		targetURL = "h" + targetURL
	}
	if targetURL != "" && !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}
	return strings.TrimSpace(targetURL)
}

func makeUniqueTargetID(id string, used map[string]struct{}) string {
	cleanID := strings.TrimSpace(id)
	if cleanID == "" {
		cleanID = "target"
	}
	if _, exists := used[cleanID]; !exists {
		return cleanID
	}
	base := cleanID
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s-%d", base, suffix)
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
}

func extractTargetDomain(rawURL string) string {
	parsed, _ := url.Parse(rawURL)
	domain := parsed.Hostname()
	if domain == "" {
		domain = cleanHostname(rawURL)
	}
	return domain
}

func uniqueStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func cleanHostname(urlOrDomain string) string {
	urlOrDomain = strings.TrimSpace(strings.ToLower(urlOrDomain))
	if !strings.Contains(urlOrDomain, "://") {
		urlOrDomain = "http://" + urlOrDomain
	}
	parsed, err := url.Parse(urlOrDomain)
	if err != nil {
		host := strings.TrimPrefix(strings.TrimPrefix(urlOrDomain, "http://"), "https://")
		if idx := strings.Index(host, "/"); idx >= 0 {
			host = host[:idx]
		}
		return strings.TrimSpace(host)
	}
	host := parsed.Host
	if host == "" {
		host = parsed.Path
	}
	if strings.Contains(host, "/") {
		host = strings.SplitN(host, "/", 2)[0]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.Count(host, ":") == 1 {
		host = strings.Split(host, ":")[0]
	}
	return host
}

func getGroupName(provider string) string {
	clean := strings.TrimSpace(reProvider.ReplaceAllString(provider, ""))
	parts := strings.Fields(clean)
	if len(parts) == 0 {
		return clean
	}
	return parts[0]
}
