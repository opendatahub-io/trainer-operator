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

package e2e

import (
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/opendatahub-io/trainer-operator/test/support"
)

const (
	prometheusNamespace   = "openshift-monitoring"
	prometheusName        = "e2e"
	prometheusServiceAcct = "prometheus-k8s"
	metricsMonitorName    = "trainer-operator-controller-manager-metrics-monitor"
)

var prometheusResource = schema.GroupVersionResource{
	Group: "monitoring.coreos.com", Version: "v1", Resource: "prometheuses",
}

func TestServiceMonitorScrapedByPrometheus(t *testing.T) {
	g := NewWithT(t)

	_, err := k8sClient.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: prometheusNamespace},
	}, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(func() {
		_ = k8sClient.CoreV1().Namespaces().Delete(ctx, prometheusNamespace, metav1.DeleteOptions{})
	})

	_, err = k8sClient.CoreV1().ServiceAccounts(prometheusNamespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: prometheusServiceAcct},
	}, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	const scrapeBindingName = "trainer-operator-prometheus-e2e-metrics-reader"
	_, err = k8sClient.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: scrapeBindingName},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: metricsReaderRoleName,
		},
		Subjects: []rbacv1.Subject{{
			Kind: rbacv1.ServiceAccountKind, Name: prometheusServiceAcct, Namespace: prometheusNamespace,
		}},
	}, metav1.CreateOptions{})
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(func() {
		_ = k8sClient.RbacV1().ClusterRoleBindings().Delete(ctx, scrapeBindingName, metav1.DeleteOptions{})
	})

	prometheus := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "monitoring.coreos.com/v1",
		"kind":       "Prometheus",
		"metadata": map[string]any{
			"name": prometheusName,
		},
		"spec": map[string]any{
			"serviceAccountName": prometheusServiceAcct,
			"serviceMonitorSelector": map[string]any{
				"matchLabels": map[string]any{"app.kubernetes.io/name": "trainer-operator"},
			},
			"serviceMonitorNamespaceSelector": map[string]any{
				"matchLabels": map[string]any{"kubernetes.io/metadata.name": namespace},
			},
		},
	}}
	g.Eventually(func(g Gomega) {
		_, createErr := k8sClient.DynamicClient.Resource(prometheusResource).Namespace(prometheusNamespace).Create(
			ctx, prometheus, metav1.CreateOptions{})
		g.Expect(createErr).NotTo(HaveOccurred())
	}).Should(Succeed())

	const podName = "prometheus-e2e-0"
	g.Eventually(func(g Gomega) {
		pod, getErr := k8sClient.CoreV1().Pods(prometheusNamespace).Get(ctx, podName, metav1.GetOptions{})
		g.Expect(getErr).NotTo(HaveOccurred())
		g.Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
	}).WithTimeout(5 * time.Minute).Should(Succeed())

	address, stop, err := k8sClient.PortForwardPrometheus(ctx, prometheusNamespace, podName)
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(stop)

	g.Eventually(func(g Gomega) {
		scraped, status, queryErr := support.PrometheusServiceMonitorScrapeStatus(
			ctx, address, namespace, metricsMonitorName, metricsServiceName)
		g.Expect(queryErr).NotTo(HaveOccurred())
		g.Expect(scraped).To(BeTrue(),
			fmt.Sprintf("Prometheus has not successfully scraped ServiceMonitor %s/%s: %s",
				namespace, metricsMonitorName, status))
	}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
}
