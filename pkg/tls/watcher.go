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
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var watcherLog = ctrl.Log.WithName("tls-profile-watcher")

type ProfileWatcher struct {
	client.Client
	lastProfile     map[string]interface{}
	lastAdherence   TLSAdherence
	onProfileChange func()
}

func NewProfileWatcher(c client.Client, result FetchResult, onProfileChange func()) *ProfileWatcher {
	return &ProfileWatcher{
		Client:          c,
		lastProfile:     result.RawSpec,
		lastAdherence:   result.Adherence,
		onProfileChange: onProfileChange,
	}
}

const profileRetryInterval = 5 * time.Second

func (w *ProfileWatcher) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	result := FetchTLSProfileWithClient(ctx, w.Client)
	if !result.Fetched {
		watcherLog.Info("TLS profile fetch did not succeed, retrying", "retryAfter", profileRetryInterval)
		return reconcile.Result{RequeueAfter: profileRetryInterval}, nil
	}

	profileChanged := !reflect.DeepEqual(w.lastProfile, result.RawSpec)
	adherenceChanged := w.lastAdherence != result.Adherence

	if profileChanged || adherenceChanged {
		watcherLog.Info("TLS settings changed, triggering restart",
			"profileChanged", profileChanged, "adherenceChanged", adherenceChanged,
			"oldAdherence", string(w.lastAdherence), "newAdherence", string(result.Adherence))
		w.lastProfile = result.RawSpec
		w.lastAdherence = result.Adherence
		if w.onProfileChange != nil {
			w.onProfileChange()
		}
	}

	return reconcile.Result{}, nil
}

func (w *ProfileWatcher) NeedLeaderElection() bool {
	return false
}

func (w *ProfileWatcher) SetupWithManager(mgr ctrl.Manager) error {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(APIServerGVK)

	return ctrl.NewControllerManagedBy(mgr).
		Named("tls-profile-watcher").
		WithOptions(controller.Options{NeedLeaderElection: boolPtr(false)}).
		WatchesRawSource(source.Kind(mgr.GetCache(), obj,
			&handler.TypedEnqueueRequestForObject[*unstructured.Unstructured]{},
			predicate.TypedFuncs[*unstructured.Unstructured]{
				CreateFunc: func(e event.TypedCreateEvent[*unstructured.Unstructured]) bool {
					return e.Object.GetName() == "cluster"
				},
				UpdateFunc: func(e event.TypedUpdateEvent[*unstructured.Unstructured]) bool {
					return e.ObjectNew.GetName() == "cluster"
				},
				DeleteFunc: func(_ event.TypedDeleteEvent[*unstructured.Unstructured]) bool {
					return false
				},
				GenericFunc: func(_ event.TypedGenericEvent[*unstructured.Unstructured]) bool {
					return false
				},
			},
		)).
		Complete(w)
}

func boolPtr(b bool) *bool { return &b }

// SetupProfileWatcherRestart wraps the cancel-context + ProfileWatcher setup
// so that controller and webhook entry points share a single contract.
// Returns a cancellable context: if the TLS profile changes at runtime, the
// context is cancelled, causing the manager to shut down for restart.
func SetupProfileWatcherRestart(ctx context.Context, mgr ctrl.Manager, result FetchResult) context.Context {
	if !result.APIAvailable {
		return ctx
	}
	ctx, cancel := context.WithCancel(ctx)
	watcher := NewProfileWatcher(mgr.GetClient(), result, func() {
		watcherLog.Info("TLS settings changed, shutting down for restart")
		cancel()
	})
	if err := watcher.SetupWithManager(mgr); err != nil {
		watcherLog.Error(err, "Failed to set up TLS security profile watcher; profile changes will not trigger a restart")
	}
	return ctx
}
