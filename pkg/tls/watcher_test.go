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
	"sync/atomic"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func makeAPIServerObj(profileType string) *unstructured.Unstructured {
	return makeAPIServerObjWithAdherence(profileType, "")
}

func makeAPIServerObjWithAdherence(profileType, adherence string) *unstructured.Unstructured {
	spec := map[string]interface{}{
		"tlsSecurityProfile": map[string]interface{}{
			"type": profileType,
		},
	}
	if adherence != "" {
		spec["tlsAdherence"] = adherence
	}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "config.openshift.io/v1",
		"kind":       "APIServer",
		"metadata": map[string]interface{}{
			"name": "cluster",
		},
		"spec": spec,
	}}
	return obj
}

func resultFromSpec(profile map[string]interface{}, adherence TLSAdherence) FetchResult {
	return FetchResult{
		RawSpec:   profile,
		Adherence: adherence,
		Fetched:   true,
	}
}

func TestProfileWatcher_NoChange(t *testing.T) {
	apiServer := makeAPIServerObj("Intermediate")
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Intermediate",
	}, AdherenceNoOpinion)

	var called atomic.Int32
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, func() {
		called.Add(1)
	})

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 0 {
		t.Error("callback should not be called when profile hasn't changed")
	}
}

func TestProfileWatcher_ProfileChanged(t *testing.T) {
	apiServer := makeAPIServerObj("Modern")
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Intermediate",
	}, AdherenceNoOpinion)

	var called atomic.Int32
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, func() {
		called.Add(1)
	})

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 1 {
		t.Error("callback should be called when profile changes")
	}
}

func TestProfileWatcher_NotFetchedRequeues(t *testing.T) {
	var called atomic.Int32
	c := fake.NewClientBuilder().Build()
	watcher := NewProfileWatcher(c, FetchResult{}, func() {
		called.Add(1)
	})

	result, err := watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 0 {
		t.Error("callback should not be called when profile fetch fails")
	}
	if result.RequeueAfter != profileRetryInterval {
		t.Errorf("expected RequeueAfter=%v, got %v", profileRetryInterval, result.RequeueAfter)
	}
}

func TestProfileWatcher_TransientThenSuccess(t *testing.T) {
	var called atomic.Int32

	c1 := fake.NewClientBuilder().Build()
	watcher := NewProfileWatcher(c1, FetchResult{}, func() {
		called.Add(1)
	})

	result, err := watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != profileRetryInterval {
		t.Fatalf("expected requeue on transient failure")
	}
	if called.Load() != 0 {
		t.Fatal("callback should not fire on failed fetch")
	}

	// Second reconcile: APIServer exists now, profile is fetched successfully
	apiServer := makeAPIServerObj("Modern")
	c2 := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher.Client = c2

	result, err = watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RequeueAfter != 0 {
		t.Errorf("expected no requeue on success, got %v", result.RequeueAfter)
	}
	if called.Load() != 1 {
		t.Errorf("expected callback to fire on successful profile fetch, got %d calls", called.Load())
	}
}

func TestProfileWatcher_NeedLeaderElection(t *testing.T) {
	c := fake.NewClientBuilder().Build()
	watcher := NewProfileWatcher(c, FetchResult{}, nil)
	if watcher.NeedLeaderElection() {
		t.Error("watcher should not need leader election")
	}
}

func TestProfileWatcher_NilCallbackDoesNotPanic(t *testing.T) {
	apiServer := makeAPIServerObj("Modern")
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Intermediate",
	}, AdherenceNoOpinion)

	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, nil)

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProfileWatcher_IdempotentOnSecondReconcile(t *testing.T) {
	apiServer := makeAPIServerObj("Modern")
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Intermediate",
	}, AdherenceNoOpinion)

	var called atomic.Int32
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, func() {
		called.Add(1)
	})

	// First reconcile: profile changed, callback fires
	if _, err := watcher.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 1 {
		t.Fatalf("expected 1 call after first reconcile, got %d", called.Load())
	}

	// Second reconcile: same profile, callback should NOT fire again
	if _, err := watcher.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("expected still 1 call after second reconcile (no change), got %d", called.Load())
	}
}

func TestProfileWatcher_DetectsChangeBackToOriginal(t *testing.T) {
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Intermediate",
	}, AdherenceNoOpinion)

	var called atomic.Int32

	apiServer := makeAPIServerObj("Modern")
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, func() {
		called.Add(1)
	})

	// First reconcile: Intermediate -> Modern, callback fires
	if _, err := watcher.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", called.Load())
	}

	// Now change the object back to Intermediate
	apiServer2 := makeAPIServerObj("Intermediate")
	c2 := fake.NewClientBuilder().WithObjects(apiServer2).Build()
	watcher.Client = c2

	// Second reconcile: Modern -> Intermediate, callback fires again
	if _, err := watcher.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 2 {
		t.Errorf("expected 2 calls after profile changed back, got %d", called.Load())
	}
}

func TestProfileWatcher_UpdatesLastProfile(t *testing.T) {
	apiServer := makeAPIServerObj("Modern")
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Intermediate",
	}, AdherenceNoOpinion)

	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, func() {})

	if _, err := watcher.Reconcile(context.Background(), reconcile.Request{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After reconcile, lastProfile should reflect the fetched profile
	profileType, _ := watcher.lastProfile["type"].(string)
	if profileType != "Modern" {
		t.Errorf("expected lastProfile type=Modern, got %q", profileType)
	}
}

func TestProfileWatcher_AdherenceChangeTriggersRestart(t *testing.T) {
	// Watcher state says StrictAllComponents; the cluster now reports Legacy adherence.
	apiServer := makeAPIServerObjWithAdherence("Old", string(AdherenceLegacyAdheringComponentsOnly))
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Old",
	}, AdherenceStrictAllComponents)

	var called atomic.Int32
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, func() {
		called.Add(1)
	})

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("expected callback when adherence changes from Strict to Legacy, got %d", called.Load())
	}
}

func TestProfileWatcher_AdherenceStrictToUnsetTriggersRestart(t *testing.T) {
	// Cluster had StrictAllComponents; now the field is absent (empty = NoOpinion).
	apiServer := makeAPIServerObj("Old") // no adherence field
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Old",
	}, AdherenceStrictAllComponents)

	var called atomic.Int32
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, func() {
		called.Add(1)
	})

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("expected callback when adherence changes from Strict to unset, got %d", called.Load())
	}
}

func TestProfileWatcher_SameAdherenceNoCallback(t *testing.T) {
	apiServer := makeAPIServerObjWithAdherence("Intermediate", "StrictAllComponents")
	initialResult := resultFromSpec(map[string]interface{}{
		"type": "Intermediate",
	}, AdherenceStrictAllComponents)

	var called atomic.Int32
	c := fake.NewClientBuilder().WithObjects(apiServer).Build()
	watcher := NewProfileWatcher(c, initialResult, func() {
		called.Add(1)
	})

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 0 {
		t.Errorf("expected no callback when neither profile nor adherence changed, got %d", called.Load())
	}
}
