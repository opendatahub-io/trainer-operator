/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"context"
	cryptotls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestTLSVersionFromString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint16
	}{
		{"TLS 1.2", "VersionTLS12", cryptotls.VersionTLS12},
		{"TLS 1.3", "VersionTLS13", cryptotls.VersionTLS13},
		{"empty string defaults to TLS 1.2", "", cryptotls.VersionTLS12},
		{"unknown version defaults to TLS 1.2", "VersionTLS10", cryptotls.VersionTLS12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TLSVersionFromString(tt.input)
			if got != tt.expected {
				t.Errorf("TLSVersionFromString(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseTLSProfile(t *testing.T) {
	makeAPIServer := func(profileType string, custom map[string]interface{}) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
		spec := map[string]interface{}{}
		if profileType != "" {
			profile := map[string]interface{}{"type": profileType}
			if custom != nil {
				profile["custom"] = custom
			}
			spec["tlsSecurityProfile"] = profile
		}
		obj.Object["spec"] = spec
		return obj
	}

	t.Run("nil profile returns Intermediate defaults", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{
			"spec": map[string]interface{}{},
		}}
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if len(ciphers) != len(IntermediateCiphers) {
			t.Errorf("expected %d Intermediate ciphers, got %d", len(IntermediateCiphers), len(ciphers))
		}
	})

	t.Run("Intermediate returns Intermediate defaults", func(t *testing.T) {
		obj := makeAPIServer("Intermediate", nil)
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if len(ciphers) != len(IntermediateCiphers) {
			t.Errorf("expected %d ciphers, got %d", len(IntermediateCiphers), len(ciphers))
		}
	})

	t.Run("Modern returns TLS 1.3 with nil ciphers", func(t *testing.T) {
		obj := makeAPIServer("Modern", nil)
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS13 {
			t.Errorf("expected TLS 1.3, got %d", minVer)
		}
		if ciphers != nil {
			t.Errorf("expected nil ciphers for Modern, got %v", ciphers)
		}
	})

	t.Run("Old returns TLS 1.2 with nil ciphers", func(t *testing.T) {
		obj := makeAPIServer("Old", nil)
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if ciphers != nil {
			t.Errorf("expected nil ciphers for Old, got %v", ciphers)
		}
	})

	t.Run("Custom with valid ciphers", func(t *testing.T) {
		obj := makeAPIServer("Custom", map[string]interface{}{
			"minTLSVersion": "VersionTLS12",
			"ciphers":       []interface{}{"ECDHE-RSA-AES128-GCM-SHA256"},
		})
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if len(ciphers) != 1 || ciphers[0] != cryptotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			t.Errorf("expected 1 cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, got %v", ciphers)
		}
	})

	t.Run("Custom with unsupported cipher logs and skips", func(t *testing.T) {
		obj := makeAPIServer("Custom", map[string]interface{}{
			"minTLSVersion": "VersionTLS12",
			"ciphers":       []interface{}{"DHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256"},
		})
		_, ciphers, _ := ParseTLSProfile(obj)
		if len(ciphers) != 1 {
			t.Errorf("expected 1 cipher (DHE dropped), got %d", len(ciphers))
		}
	})

	t.Run("Custom with nil custom block returns Intermediate", func(t *testing.T) {
		obj := makeAPIServer("Custom", nil)
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if len(ciphers) != len(IntermediateCiphers) {
			t.Errorf("expected Intermediate ciphers, got %d", len(ciphers))
		}
	})

	t.Run("Unknown profile type returns Intermediate with warning", func(t *testing.T) {
		obj := makeAPIServer("SomeFutureType", nil)
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if len(ciphers) != len(IntermediateCiphers) {
			t.Errorf("expected Intermediate ciphers, got %d", len(ciphers))
		}
	})

	t.Run("Custom with empty ciphers list returns empty slice", func(t *testing.T) {
		obj := makeAPIServer("Custom", map[string]interface{}{
			"minTLSVersion": "VersionTLS13",
			"ciphers":       []interface{}{},
		})
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS13 {
			t.Errorf("expected TLS 1.3, got %d", minVer)
		}
		if len(ciphers) != 0 {
			t.Errorf("expected empty ciphers, got %d", len(ciphers))
		}
	})

	t.Run("Custom with TLS 1.3 minVersion", func(t *testing.T) {
		obj := makeAPIServer("Custom", map[string]interface{}{
			"minTLSVersion": "VersionTLS13",
			"ciphers":       []interface{}{"ECDHE-ECDSA-AES256-GCM-SHA384"},
		})
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS13 {
			t.Errorf("expected TLS 1.3, got %d", minVer)
		}
		if len(ciphers) != 1 {
			t.Errorf("expected 1 cipher, got %d", len(ciphers))
		}
	})

	t.Run("Custom with all unsupported ciphers returns empty", func(t *testing.T) {
		obj := makeAPIServer("Custom", map[string]interface{}{
			"minTLSVersion": "VersionTLS12",
			"ciphers":       []interface{}{"DHE-RSA-AES128-GCM-SHA256", "FAKE-CIPHER"},
		})
		_, ciphers, _ := ParseTLSProfile(obj)
		if len(ciphers) != 0 {
			t.Errorf("expected 0 ciphers (all unsupported), got %d", len(ciphers))
		}
	})

	t.Run("Custom with multiple valid ciphers", func(t *testing.T) {
		obj := makeAPIServer("Custom", map[string]interface{}{
			"minTLSVersion": "VersionTLS12",
			"ciphers": []interface{}{
				"ECDHE-RSA-AES128-GCM-SHA256",
				"ECDHE-RSA-AES256-GCM-SHA384",
				"ECDHE-ECDSA-CHACHA20-POLY1305",
			},
		})
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if len(ciphers) != 3 {
			t.Errorf("expected 3 ciphers, got %d", len(ciphers))
		}
	})

	t.Run("empty type string treated as Intermediate", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"tlsSecurityProfile": map[string]interface{}{
					"type": "",
				},
			},
		}}
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if len(ciphers) != len(IntermediateCiphers) {
			t.Errorf("expected Intermediate ciphers, got %d", len(ciphers))
		}
	})

	t.Run("no spec at all returns Intermediate", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
		minVer, ciphers, _ := ParseTLSProfile(obj)
		if minVer != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", minVer)
		}
		if len(ciphers) != len(IntermediateCiphers) {
			t.Errorf("expected Intermediate ciphers, got %d", len(ciphers))
		}
	})
}

func TestFetchTLSProfileWithClient(t *testing.T) {
	t.Run("NoMatch returns hardened default with APIAvailable=false", func(t *testing.T) {
		c := fake.NewClientBuilder().Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if result.Fetched {
			t.Error("expected Fetched=false for NoMatch")
		}
		if result.APIAvailable {
			t.Error("expected APIAvailable=false for NoMatch (non-OpenShift)")
		}
		if result.RawSpec != nil {
			t.Error("expected nil RawSpec for NoMatch")
		}
		cfg := &cryptotls.Config{}
		for _, opt := range result.TLSOpts {
			opt(cfg)
		}
		if cfg.MinVersion != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2 default, got %d", cfg.MinVersion)
		}
	})

	t.Run("NotFound returns hardened default with APIAvailable=false", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
					return apierrors.NewNotFound(schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"}, "cluster")
				},
			}).Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if result.Fetched {
			t.Error("expected Fetched=false for NotFound")
		}
		if result.APIAvailable {
			t.Error("expected APIAvailable=false for NotFound")
		}
	})

	t.Run("successful fetch returns profile with Fetched=true and APIAvailable=true", func(t *testing.T) {
		apiServer := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "config.openshift.io/v1",
			"kind":       "APIServer",
			"metadata":   map[string]interface{}{"name": "cluster"},
			"spec": map[string]interface{}{
				"tlsSecurityProfile": map[string]interface{}{
					"type": "Modern",
				},
				"tlsAdherence": "StrictAllComponents",
			},
		}}
		c := fake.NewClientBuilder().WithObjects(apiServer).Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if !result.Fetched {
			t.Error("expected Fetched=true for successful fetch")
		}
		if !result.APIAvailable {
			t.Error("expected APIAvailable=true for successful fetch")
		}
		cfg := &cryptotls.Config{}
		for _, opt := range result.TLSOpts {
			opt(cfg)
		}
		if cfg.MinVersion != cryptotls.VersionTLS13 {
			t.Errorf("expected TLS 1.3 for Modern, got %d", cfg.MinVersion)
		}
	})

	t.Run("successful fetch populates RawSpec", func(t *testing.T) {
		apiServer := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "config.openshift.io/v1",
			"kind":       "APIServer",
			"metadata":   map[string]interface{}{"name": "cluster"},
			"spec": map[string]interface{}{
				"tlsSecurityProfile": map[string]interface{}{
					"type": "Intermediate",
				},
			},
		}}
		c := fake.NewClientBuilder().WithObjects(apiServer).Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if result.RawSpec == nil {
			t.Fatal("expected non-nil RawSpec")
		}
		profileType, _ := result.RawSpec["type"].(string)
		if profileType != "Intermediate" {
			t.Errorf("expected profile type Intermediate, got %q", profileType)
		}
	})

	t.Run("APIServer with no tlsSecurityProfile returns Intermediate", func(t *testing.T) {
		apiServer := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": "config.openshift.io/v1",
			"kind":       "APIServer",
			"metadata":   map[string]interface{}{"name": "cluster"},
			"spec":       map[string]interface{}{},
		}}
		c := fake.NewClientBuilder().WithObjects(apiServer).Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if !result.Fetched {
			t.Error("expected Fetched=true")
		}
		cfg := &cryptotls.Config{}
		for _, opt := range result.TLSOpts {
			opt(cfg)
		}
		if cfg.MinVersion != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", cfg.MinVersion)
		}
	})
}

func TestFetchTLSProfileWithClient_ErrorPaths(t *testing.T) {
	t.Run("transient error returns Intermediate with Fetched=false but APIAvailable=true", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
					return apierrors.NewServiceUnavailable("maintenance")
				},
			}).Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if result.Fetched {
			t.Error("expected Fetched=false for transient error")
		}
		if !result.APIAvailable {
			t.Error("expected APIAvailable=true for transient error (API exists, just temporarily unavailable)")
		}
		cfg := &cryptotls.Config{}
		for _, opt := range result.TLSOpts {
			opt(cfg)
		}
		if cfg.MinVersion != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", cfg.MinVersion)
		}
		if len(cfg.CipherSuites) != len(IntermediateCiphers) {
			t.Errorf("expected %d Intermediate ciphers, got %d", len(IntermediateCiphers), len(cfg.CipherSuites))
		}
	})

	t.Run("Forbidden returns Fetched=false but APIAvailable=true", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
					return apierrors.NewForbidden(schema.GroupResource{Group: "config.openshift.io", Resource: "apiservers"}, "cluster", fmt.Errorf("forbidden"))
				},
			}).Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if result.Fetched {
			t.Error("expected Fetched=false for Forbidden")
		}
		if !result.APIAvailable {
			t.Error("expected APIAvailable=true for Forbidden (API exists, RBAC is wrong)")
		}
	})

	t.Run("Unauthorized returns Fetched=false but APIAvailable=true", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
					return apierrors.NewUnauthorized("unauthenticated")
				},
			}).Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if result.Fetched {
			t.Error("expected Fetched=false for Unauthorized")
		}
		if !result.APIAvailable {
			t.Error("expected APIAvailable=true for Unauthorized (API exists, auth is wrong)")
		}
	})

	t.Run("unknown non-transient error returns Intermediate fallback with APIAvailable=true", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
					return apierrors.NewInternalError(fmt.Errorf("something broke"))
				},
			}).Build()
		result := FetchTLSProfileWithClient(context.Background(), c)
		if result.Fetched {
			t.Error("expected Fetched=false for non-transient error")
		}
		if !result.APIAvailable {
			t.Error("expected APIAvailable=true so watcher can retry")
		}
		cfg := &cryptotls.Config{}
		for _, opt := range result.TLSOpts {
			opt(cfg)
		}
		if cfg.MinVersion != cryptotls.VersionTLS12 {
			t.Errorf("expected TLS 1.2, got %d", cfg.MinVersion)
		}
		if len(cfg.CipherSuites) != len(IntermediateCiphers) {
			t.Errorf("expected %d Intermediate ciphers, got %d", len(IntermediateCiphers), len(cfg.CipherSuites))
		}
	})
}

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"ServiceUnavailable", apierrors.NewServiceUnavailable("down"), true},
		{"Timeout", apierrors.NewTimeoutError("timeout", 5), true},
		{"ServerTimeout", apierrors.NewServerTimeout(schema.GroupResource{}, "get", 5), true},
		{"TooManyRequests", apierrors.NewTooManyRequestsError("throttled"), true},
		{"NotFound", apierrors.NewNotFound(schema.GroupResource{}, "cluster"), false},
		{"Forbidden", apierrors.NewForbidden(schema.GroupResource{}, "cluster", fmt.Errorf("forbidden")), false},
		{"generic error", fmt.Errorf("something broke"), false},
		{"net.Error (timeout)", &net.OpError{Op: "read", Err: fmt.Errorf("timeout")}, true},
		{"DNS error", &net.DNSError{Name: "api.cluster.local", Err: "no such host"}, true},
		{"wrapped net error", fmt.Errorf("connection failed: %w", &net.OpError{Op: "dial", Err: fmt.Errorf("refused")}), true},
		{"wrapped DNS error", fmt.Errorf("lookup failed: %w", &net.DNSError{Name: "api.cluster.local", Err: "no such host"}), true},
		{"plain error", errors.New("plain error"), false},
		{"nil error", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTransient(tt.err)
			if got != tt.expected {
				t.Errorf("isTransient(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestShouldHonorClusterTLSProfile(t *testing.T) {
	tests := []struct {
		name      string
		adherence TLSAdherence
		want      bool
	}{
		{"StrictAllComponents", AdherenceStrictAllComponents, true},
		{"NoOpinion (empty)", AdherenceNoOpinion, false},
		{"LegacyAdheringComponentsOnly", AdherenceLegacyAdheringComponentsOnly, false},
		{"Unknown future policy", TLSAdherence("FuturePolicy"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldHonorClusterTLSProfile(tt.adherence); got != tt.want {
				t.Errorf("ShouldHonorClusterTLSProfile(%q) = %v, want %v", tt.adherence, got, tt.want)
			}
		})
	}
}

func TestReadAdherence(t *testing.T) {
	t.Run("missing field returns NoOpinion", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{
			"spec": map[string]interface{}{},
		}}
		if got := readAdherence(obj); got != AdherenceNoOpinion {
			t.Errorf("expected NoOpinion, got %q", got)
		}
	})

	t.Run("StrictAllComponents", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"tlsAdherence": "StrictAllComponents",
			},
		}}
		if got := readAdherence(obj); got != AdherenceStrictAllComponents {
			t.Errorf("expected StrictAllComponents, got %q", got)
		}
	})

	t.Run("no spec at all returns NoOpinion", func(t *testing.T) {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
		if got := readAdherence(obj); got != AdherenceNoOpinion {
			t.Errorf("expected NoOpinion, got %q", got)
		}
	})
}

func TestFetchTLSProfileWithClient_AdherenceNoOpinion_ForcesIntermediate(t *testing.T) {
	apiServer := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "config.openshift.io/v1",
		"kind":       "APIServer",
		"metadata":   map[string]interface{}{"name": "cluster"},
		"spec": map[string]interface{}{
			"tlsSecurityProfile": map[string]interface{}{
				"type": "Old",
			},
			"tlsAdherence": "",
		},
	}}
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	result := FetchTLSProfileWithClient(context.Background(), c)

	if !result.Fetched {
		t.Fatal("expected Fetched=true")
	}
	if result.Adherence != AdherenceNoOpinion {
		t.Errorf("expected AdherenceNoOpinion, got %q", result.Adherence)
	}
	cfg := &cryptotls.Config{}
	for _, opt := range result.TLSOpts {
		opt(cfg)
	}
	if cfg.MinVersion != cryptotls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 (Intermediate fallback), got %d", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) != len(IntermediateCiphers) {
		t.Errorf("expected %d Intermediate ciphers, got %d", len(IntermediateCiphers), len(cfg.CipherSuites))
	}
}

func TestFetchTLSProfileWithClient_AdherenceStrict_HonorsOldProfile(t *testing.T) {
	apiServer := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "config.openshift.io/v1",
		"kind":       "APIServer",
		"metadata":   map[string]interface{}{"name": "cluster"},
		"spec": map[string]interface{}{
			"tlsSecurityProfile": map[string]interface{}{
				"type": "Old",
			},
			"tlsAdherence": "StrictAllComponents",
		},
	}}
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	result := FetchTLSProfileWithClient(context.Background(), c)

	if !result.Fetched {
		t.Fatal("expected Fetched=true")
	}
	if result.Adherence != AdherenceStrictAllComponents {
		t.Errorf("expected StrictAllComponents, got %q", result.Adherence)
	}
	cfg := &cryptotls.Config{}
	for _, opt := range result.TLSOpts {
		opt(cfg)
	}
	if cfg.MinVersion != cryptotls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 for Old, got %d", cfg.MinVersion)
	}
}

func TestFetchTLSProfileWithClient_AdherenceLegacy_ForcesIntermediate(t *testing.T) {
	apiServer := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "config.openshift.io/v1",
		"kind":       "APIServer",
		"metadata":   map[string]interface{}{"name": "cluster"},
		"spec": map[string]interface{}{
			"tlsSecurityProfile": map[string]interface{}{
				"type": "Modern",
			},
			"tlsAdherence": "LegacyAdheringComponentsOnly",
		},
	}}
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	result := FetchTLSProfileWithClient(context.Background(), c)

	if !result.Fetched {
		t.Fatal("expected Fetched=true")
	}
	cfg := &cryptotls.Config{}
	for _, opt := range result.TLSOpts {
		opt(cfg)
	}
	if cfg.MinVersion != cryptotls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 (Intermediate) under Legacy adherence, got %d", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) != len(IntermediateCiphers) {
		t.Errorf("expected %d Intermediate ciphers, got %d", len(IntermediateCiphers), len(cfg.CipherSuites))
	}
}

func TestFetchTLSProfileWithClient_MissingAdherence_DefaultsNoOpinion(t *testing.T) {
	apiServer := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "config.openshift.io/v1",
		"kind":       "APIServer",
		"metadata":   map[string]interface{}{"name": "cluster"},
		"spec": map[string]interface{}{
			"tlsSecurityProfile": map[string]interface{}{
				"type": "Modern",
			},
		},
	}}
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	result := FetchTLSProfileWithClient(context.Background(), c)

	if result.Adherence != AdherenceNoOpinion {
		t.Errorf("expected NoOpinion when field absent, got %q", result.Adherence)
	}
	cfg := &cryptotls.Config{}
	for _, opt := range result.TLSOpts {
		opt(cfg)
	}
	if cfg.MinVersion != cryptotls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 (Intermediate fallback), got %d", cfg.MinVersion)
	}
}
