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
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestShouldHonorProfile(t *testing.T) {
	tests := []struct {
		name      string
		adherence configv1.TLSAdherencePolicy
		want      bool
	}{
		{"StrictAllComponents", configv1.TLSAdherencePolicyStrictAllComponents, true},
		{"NoOpinion", configv1.TLSAdherencePolicyNoOpinion, false},
		{"LegacyAdheringComponentsOnly", configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly, false},
		{"Unknown future policy", configv1.TLSAdherencePolicy("FuturePolicy"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldHonorProfile(tt.adherence); got != tt.want {
				t.Errorf("shouldHonorProfile(%q) = %v, want %v", tt.adherence, got, tt.want)
			}
		})
	}
}

func TestBuildResult_Strict_HonorsProfile(t *testing.T) {
	profile := *configv1.TLSProfiles[configv1.TLSProfileModernType]
	result := buildResult(profile, configv1.TLSAdherencePolicyStrictAllComponents)

	if !result.OnOpenShift {
		t.Error("expected OnOpenShift=true")
	}
	cfg := &tls.Config{}
	for _, opt := range result.TLSOpts {
		opt(cfg)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 for Modern profile under Strict adherence, got %d", cfg.MinVersion)
	}
}

func TestBuildResult_NoOpinion_ForcesIntermediate(t *testing.T) {
	profile := *configv1.TLSProfiles[configv1.TLSProfileModernType]
	result := buildResult(profile, configv1.TLSAdherencePolicyNoOpinion)

	cfg := &tls.Config{}
	for _, opt := range result.TLSOpts {
		opt(cfg)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 (Intermediate) under NoOpinion, got %d", cfg.MinVersion)
	}
}

func TestBuildResult_Legacy_ForcesIntermediate(t *testing.T) {
	profile := *configv1.TLSProfiles[configv1.TLSProfileModernType]
	result := buildResult(profile, configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly)

	cfg := &tls.Config{}
	for _, opt := range result.TLSOpts {
		opt(cfg)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 (Intermediate) under Legacy, got %d", cfg.MinVersion)
	}
}

func TestDefaultResult(t *testing.T) {
	result := defaultResult()
	if result.OnOpenShift {
		t.Error("expected OnOpenShift=false for default")
	}
	cfg := &tls.Config{}
	for _, opt := range result.TLSOpts {
		opt(cfg)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2 for default, got %d", cfg.MinVersion)
	}
}

func TestIntermediateTLSOpts(t *testing.T) {
	opts := intermediateTLSOpts()
	if len(opts) != 1 {
		t.Fatalf("expected 1 TLS opt, got %d", len(opts))
	}
	cfg := &tls.Config{}
	opts[0](cfg)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got %d", cfg.MinVersion)
	}
}
