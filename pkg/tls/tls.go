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

// Package tls provides TLS profile integration for trainer-operator using the
// shared openshift/controller-runtime-common library.
package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var setupLog = ctrl.Log.WithName("tls-setup")

// FetchResult holds the outcome of a startup-time TLS profile fetch.
type FetchResult struct {
	TLSOpts     []func(*tls.Config)
	Profile     configv1.TLSProfileSpec
	Adherence   configv1.TLSAdherencePolicy
	OnOpenShift bool
}

// FetchTLSProfile performs a one-shot TLS profile fetch at startup.
// On non-OpenShift clusters (NoMatchError, NotFound) it returns safe defaults.
// On transient errors it logs and returns safe defaults so the watcher can retry.
// On auth/forbidden errors it terminates the process (fail-closed).
func FetchTLSProfile(cfg *rest.Config, scheme *runtime.Scheme) FetchResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "Failed to create bootstrap client for TLS profile, using defaults")
		return defaultResult()
	}

	return fetchWithClient(ctx, c)
}

func fetchWithClient(ctx context.Context, c client.Client) FetchResult {
	profile, err := openshifttls.FetchAPIServerTLSProfile(ctx, c)
	if err != nil {
		return handleFetchError(err)
	}

	adherence, err := openshifttls.FetchAPIServerTLSAdherencePolicy(ctx, c)
	if err != nil {
		setupLog.Error(err, "Failed to fetch TLS adherence policy, defaulting to NoOpinion")
		adherence = configv1.TLSAdherencePolicyNoOpinion
	}

	return buildResult(profile, adherence)
}

func handleFetchError(err error) FetchResult {
	if meta.IsNoMatchError(err) {
		setupLog.Info("APIServer CRD not registered (non-OpenShift cluster), using defaults")
		return defaultResult()
	}
	if errors.IsNotFound(err) {
		setupLog.Info("APIServer 'cluster' not found, using defaults")
		return defaultResult()
	}
	if errors.IsForbidden(err) || errors.IsUnauthorized(err) {
		setupLog.Error(err, "Permission denied reading APIServer TLS profile — fail-closed")
		os.Exit(1)
	}

	setupLog.Error(err, "Unexpected error reading APIServer TLS profile, using defaults; watcher will retry")
	return FetchResult{
		TLSOpts:     intermediateTLSOpts(),
		Profile:     *configv1.TLSProfiles[configv1.TLSProfileIntermediateType],
		Adherence:   configv1.TLSAdherencePolicyNoOpinion,
		OnOpenShift: true,
	}
}

func buildResult(
	profile configv1.TLSProfileSpec, adherence configv1.TLSAdherencePolicy,
) FetchResult {
	if !shouldHonorProfile(adherence) {
		setupLog.Info("TLS adherence policy does not require strict compliance, using Intermediate defaults",
			"adherence", adherence)
		return FetchResult{
			TLSOpts:     intermediateTLSOpts(),
			Profile:     *configv1.TLSProfiles[configv1.TLSProfileIntermediateType],
			Adherence:   adherence,
			OnOpenShift: true,
		}
	}

	tlsConfig, unsupported := openshifttls.NewTLSConfigFromProfile(profile)
	if len(unsupported) > 0 {
		setupLog.Info("Some TLS profile entries not supported by Go runtime", "unsupported", unsupported)
	}
	setupLog.Info("Applying cluster TLS profile",
		"minTLSVersion", profile.MinTLSVersion, "adherence", adherence)

	return FetchResult{
		TLSOpts:     []func(*tls.Config){tlsConfig},
		Profile:     profile,
		Adherence:   adherence,
		OnOpenShift: true,
	}
}

// shouldHonorProfile returns true when the adherence policy requires components
// to enforce the cluster TLS profile exactly.
func shouldHonorProfile(adherence configv1.TLSAdherencePolicy) bool {
	switch adherence {
	case configv1.TLSAdherencePolicyNoOpinion, configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly:
		return false
	default:
		return true
	}
}

func defaultResult() FetchResult {
	return FetchResult{
		TLSOpts: intermediateTLSOpts(),
		Profile: *configv1.TLSProfiles[configv1.TLSProfileIntermediateType],
	}
}

func intermediateTLSOpts() []func(*tls.Config) {
	tlsConfig, _ := openshifttls.NewTLSConfigFromProfile(
		*configv1.TLSProfiles[configv1.TLSProfileIntermediateType],
	)
	return []func(*tls.Config){tlsConfig}
}

// SetupProfileWatcherRestart registers the SecurityProfileWatcher with the manager.
// If the TLS profile or adherence policy changes at runtime the manager context is
// cancelled, causing a graceful restart.
// Fails closed: setup errors terminate the process.
func SetupProfileWatcherRestart(
	ctx context.Context, mgr ctrl.Manager, result FetchResult,
) context.Context {
	if !result.OnOpenShift {
		return ctx
	}

	ctx, cancel := context.WithCancel(ctx)

	watcher := &openshifttls.SecurityProfileWatcher{
		Client:                    mgr.GetClient(),
		InitialTLSProfileSpec:     result.Profile,
		InitialTLSAdherencePolicy: result.Adherence,
		OnProfileChange: func(_ context.Context, old, new configv1.TLSProfileSpec) {
			setupLog.Info("TLS security profile changed, shutting down for restart",
				"oldMinVersion", old.MinTLSVersion, "newMinVersion", new.MinTLSVersion)
			cancel()
		},
		OnAdherencePolicyChange: func(_ context.Context, old, new configv1.TLSAdherencePolicy) {
			setupLog.Info("TLS adherence policy changed, shutting down for restart",
				"oldAdherence", old, "newAdherence", new)
			cancel()
		},
	}

	if err := watcher.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to set up TLS security profile watcher — fail-closed")
		fmt.Fprintf(os.Stderr, "FATAL: TLS security profile watcher setup failed: %v\n", err)
		os.Exit(1)
	}

	return ctx
}
