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

package ocp

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/opendatahub-io/trainer-operator/test/support"
)

func TestServiceMonitorScrapedByPrometheus(t *testing.T) {
	g := NewWithT(t)
	const (
		prometheusNamespace = "openshift-monitoring"
		prometheusPod       = "prometheus-k8s-0"
		monitorName         = "trainer-operator-controller-manager-metrics-monitor"
		serviceName         = "trainer-operator-controller-manager-metrics-service"
	)

	g.Eventually(func(g Gomega) {
		pod, err := k8sClient.CoreV1().Pods(prometheusNamespace).Get(ctx, prometheusPod, metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pod.Status.Phase).To(Equal(corev1.PodRunning))
	}).WithTimeout(5 * time.Minute).Should(Succeed())

	address, stop, err := k8sClient.PortForwardPrometheus(ctx, prometheusNamespace, prometheusPod)
	g.Expect(err).NotTo(HaveOccurred())
	t.Cleanup(stop)

	g.Eventually(func(g Gomega) {
		scraped, status, queryErr := support.PrometheusServiceMonitorScrapeStatus(
			ctx, address, namespace, monitorName, serviceName)
		g.Expect(queryErr).NotTo(HaveOccurred())
		g.Expect(scraped).To(BeTrue(),
			"OpenShift Prometheus has not successfully scraped the operator ServiceMonitor target: %s", status)
	}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
}
