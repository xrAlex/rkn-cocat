package ooni

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (s *ooniService) latestMeasurementWithFallback(withSince url.Values, withoutSince url.Values) (*ooniMeasurementRow, error) {
	return s.latestMeasurementWithFallbackPolicy(withSince, withoutSince, true)
}

func (s *ooniService) latestMeasurementBestEffort(withSince url.Values, withoutSince url.Values) *ooniMeasurementRow {
	brief, _ := s.latestMeasurementWithFallbackPolicy(withSince, withoutSince, false)
	return brief
}

func (s *ooniService) latestMeasurementWithFallbackPolicy(
	withSince url.Values,
	withoutSince url.Values,
	stopOnFirstError bool,
) (*ooniMeasurementRow, error) {
	withSinceResult, withSinceErr := s.latestMeasurement(withSince)
	if withSinceResult != nil {
		return withSinceResult, nil
	}

	withoutSinceResult, withoutSinceErr := s.latestMeasurement(withoutSince)
	if withoutSinceResult != nil {
		return withoutSinceResult, nil
	}
	if !stopOnFirstError {
		return nil, nil
	}
	switch {
	case withSinceErr == nil && withoutSinceErr == nil:
		return nil, nil
	case withSinceErr != nil && withoutSinceErr == nil:
		return nil, nil
	case withSinceErr == nil && withoutSinceErr != nil:
		return nil, withoutSinceErr
	default:
		return nil, fmt.Errorf("recent query failed: %w; fallback query failed: %v", withSinceErr, withoutSinceErr)
	}
}

func (s *ooniService) webMeasurementQuery(domain string, includeSince bool) url.Values {
	query := s.measurementQueryBase(ooniTestWeb)
	query.Set("domain", domain)
	if includeSince {
		query.Set("since", ooniSinceRFC3339(s.cfg.SinceDays))
	}
	return query
}

func (s *ooniService) tcpMeasurementQuery(endpoint string, includeSince bool) url.Values {
	query := s.measurementQueryBase(ooniTestTCP)
	query.Set("input", endpoint)
	if includeSince {
		query.Set("since", ooniSinceRFC3339(s.cfg.SinceDays))
	}
	return query
}

func (s *ooniService) measurementQueryBase(testName string) url.Values {
	return url.Values{
		"probe_cc":  []string{s.cfg.ProbeCC},
		"test_name": []string{testName},
		"order_by":  []string{"measurement_start_time"},
		"order":     []string{"desc"},
		"limit":     []string{"1"},
		"offset":    []string{"0"},
	}
}

func (s *ooniService) latestMeasurement(queryParams url.Values) (*ooniMeasurementRow, error) {
	endpoint := strings.TrimRight(s.cfg.BaseURL, "/") + "/measurements?" + queryParams.Encode()
	body, err := s.httpGet(endpoint)
	if err != nil {
		return nil, err
	}

	var response ooniMeasurementsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if len(response.Results) == 0 {
		return nil, nil
	}
	return &response.Results[0], nil
}

func (s *ooniService) fetchJSON(endpoint string) (map[string]any, error) {
	body, err := s.httpGet(endpoint)
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (s *ooniService) fetchMeasurementBody(brief *ooniMeasurementRow) (map[string]any, error) {
	endpoint := ooniMeasurementFetchURL(s.cfg.BaseURL, brief)
	if endpoint == "" {
		return nil, fmt.Errorf("measurement fetch URL is missing")
	}
	return s.fetchJSON(endpoint)
}

func (s *ooniService) httpGet(endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(resp.Body)
}
