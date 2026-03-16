package ooni

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"rkn-cocat/internal/entity"
)

func newOONIService(ctx context.Context, client *http.Client, cfg entity.OONIRuntimeConfig) *ooniService {
	if ctx == nil {
		ctx = context.Background()
	}
	return &ooniService{
		ctx:    ctx,
		client: client,
		cfg:    cfg,
	}
}

func ooniNormalizedSinceDays(days int) int {
	switch {
	case days < 0:
		return 0
	case days > ooniMaxSinceDays:
		return ooniMaxSinceDays
	default:
		return days
	}
}

func ooniMeasurementFetchURL(baseURL string, brief *ooniMeasurementRow) string {
	if brief == nil {
		return ""
	}
	if strings.TrimSpace(brief.MeasurementURL) != "" {
		return strings.TrimSpace(brief.MeasurementURL)
	}
	if strings.TrimSpace(brief.MeasurementUID) == "" || strings.TrimSpace(baseURL) == "" {
		return ""
	}
	return strings.TrimRight(baseURL, "/") + "/measurement/" + url.PathEscape(strings.TrimSpace(brief.MeasurementUID))
}

func ooniSinceRFC3339(days int) string {
	days = ooniNormalizedSinceDays(days)
	ts := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	return ts.Format(time.RFC3339)
}

func ooniNormalizeTime(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}

	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}
	return value
}

func ooniStripIPv6Brackets(value string) string {
	clean := strings.TrimSpace(value)
	clean = strings.TrimPrefix(clean, "[")
	clean = strings.TrimSuffix(clean, "]")
	return clean
}

func ooniFormatEndpoint(ip string, port int) string {
	clean := strings.TrimSpace(ip)
	if strings.Contains(clean, ":") && !strings.HasPrefix(clean, "[") {
		return fmt.Sprintf("[%s]:%d", clean, port)
	}
	return fmt.Sprintf("%s:%d", ooniStripIPv6Brackets(clean), port)
}
