/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package support

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// PortForwardPrometheus exposes a Prometheus pod's local API to the test process.
// It works with both the test Prometheus on Kind and OpenShift's prometheus-k8s.
func (c *Client) PortForwardPrometheus(ctx context.Context, namespace, podName string) (string, func(), error) {
	transport, upgrader, err := spdy.RoundTripperFor(c.Config)
	if err != nil {
		return "", nil, err
	}
	address := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/portforward",
		strings.TrimRight(c.Config.Host, "/"), namespace, podName)
	parsedURL, err := url.Parse(address)
	if err != nil {
		return "", nil, err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, parsedURL)
	stop := make(chan struct{})
	ready := make(chan struct{})
	done := make(chan error, 1)
	var output bytes.Buffer
	forwarder, err := portforward.New(dialer, []string{":9090"}, stop, ready, &output, &output)
	if err != nil {
		return "", nil, err
	}
	go func() { done <- forwarder.ForwardPorts() }()
	select {
	case <-ready:
	case err := <-done:
		return "", nil, fmt.Errorf("forwarding Prometheus API: %w: %s", err, output.String())
	case <-ctx.Done():
		close(stop)
		return "", nil, ctx.Err()
	}
	ports, err := forwarder.GetPorts()
	if err != nil || len(ports) != 1 {
		close(stop)
		return "", nil, fmt.Errorf("finding Prometheus API port: %v", err)
	}
	return fmt.Sprintf("http://127.0.0.1:%d", ports[0].Local), func() {
		close(stop)
		<-done
	}, nil
}

// PrometheusHasServiceMonitorTarget checks discovery only, not scrape health.
func PrometheusHasServiceMonitorTarget(
	ctx context.Context, address, namespace, monitorName, serviceName string,
) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address+"/api/v1/targets?state=active", nil)
	if err != nil {
		return false, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("prometheus targets API returned %s", response.Status)
	}
	var targets struct {
		Status string `json:"status"`
		Data   struct {
			Active []struct {
				ScrapePool string            `json:"scrapePool"`
				Labels     map[string]string `json:"labels"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&targets); err != nil {
		return false, err
	}
	if targets.Status != "success" {
		return false, fmt.Errorf("prometheus targets API returned status %q", targets.Status)
	}
	pool := fmt.Sprintf("serviceMonitor/%s/%s/0", namespace, monitorName)
	for _, target := range targets.Data.Active {
		if target.ScrapePool == pool && target.Labels["namespace"] == namespace && target.Labels["service"] == serviceName {
			return true, nil
		}
	}
	return false, nil
}
