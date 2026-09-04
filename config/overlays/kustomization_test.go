package overlays_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

const (
	tlsProfileReaderName        = "trainer-operator-openshift-tls-profile-reader"
	tlsProfileReaderBindingName = "trainer-operator-openshift-tls-profile-reader-binding"
	servingCertAnnotation       = "service.beta.openshift.io/serving-cert-secret-name"
	metricsCertPathArg          = "--metrics-cert-path=/tmp/k8s-metrics-server/metrics-certs"
	metricsBindAddressHTTPS     = "--metrics-bind-address=:8443"
	metricsSecureArg            = "--metrics-secure=true"
	apiserversRBACRule          = "- apiservers"
	networkPolicyKind           = "kind: NetworkPolicy"
)

func TestKustomizeBuild(t *testing.T) {
	kustomize := kustomizeBin(t)

	overlays := []struct {
		name                string
		path                string
		crbSubjectNamespace string
		contain             []string
		omit                []string
	}{
		{
			name: "default-xks",
			path: "default",
			contain: []string{
				metricsBindAddressHTTPS,
				metricsSecureArg,
			},
			omit: []string{
				tlsProfileReaderName,
				apiserversRBACRule,
				servingCertAnnotation,
				"--metrics-cert-path=",
				networkPolicyKind,
			},
		},
		{
			name:                "openshift",
			path:                "overlays/openshift",
			crbSubjectNamespace: "trainer-operator-system",
			contain: []string{
				tlsProfileReaderName,
				apiserversRBACRule,
				servingCertAnnotation,
				metricsCertPathArg,
				networkPolicyKind,
			},
		},
		{
			name:                "odh",
			path:                "overlays/odh",
			crbSubjectNamespace: "opendatahub",
			contain: []string{
				"namespace: opendatahub",
				tlsProfileReaderName,
			},
		},
		{
			name:                "rhoai",
			path:                "overlays/rhoai",
			crbSubjectNamespace: "redhat-ods-applications",
			contain: []string{
				"namespace: redhat-ods-applications",
				tlsProfileReaderName,
			},
		},
		{
			name: "dev-certs",
			path: "overlays/dev-certs",
			contain: []string{
				metricsCertPathArg,
			},
			omit: []string{
				tlsProfileReaderName,
				servingCertAnnotation,
			},
		},
	}

	for _, tc := range overlays {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			out := buildOverlay(t, g, kustomize, tc.path)
			for _, want := range tc.contain {
				g.Expect(out).Should(ContainSubstring(want), "overlay %s", tc.path)
			}
			for _, omit := range tc.omit {
				g.Expect(out).ShouldNot(ContainSubstring(omit), "overlay %s", tc.path)
			}
			if tc.crbSubjectNamespace != "" {
				namespace, err := tlsProfileCRBSubjectNamespace(out)
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(namespace).Should(Equal(tc.crbSubjectNamespace))
			}
		})
	}
}

func tlsProfileCRBSubjectNamespace(manifest string) (string, error) {
	for _, doc := range strings.Split(manifest, "---") {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		var crb rbacv1.ClusterRoleBinding
		if err := yaml.Unmarshal([]byte(doc), &crb); err != nil {
			continue
		}
		if crb.Name != tlsProfileReaderBindingName {
			continue
		}

		for _, subject := range crb.Subjects {
			if subject.Kind == rbacv1.ServiceAccountKind {
				return subject.Namespace, nil
			}
		}
	}

	return "", fmt.Errorf("TLS profile ClusterRoleBinding %q not found", tlsProfileReaderBindingName)
}

func buildOverlay(t *testing.T, g Gomega, kustomize, overlay string) string {
	t.Helper()
	cmd := exec.Command(kustomize, "build", filepath.Join("..", overlay))
	out, err := cmd.CombinedOutput()
	g.Expect(err).ShouldNot(HaveOccurred(), string(out))
	return string(out)
}

func kustomizeBin(t *testing.T) string {
	t.Helper()
	g := NewWithT(t)

	if bin := os.Getenv("KUSTOMIZE"); bin != "" {
		return bin
	}

	local := filepath.Join("..", "..", "bin", "kustomize")
	if _, err := os.Stat(local); err == nil {
		return local
	}

	path, err := exec.LookPath("kustomize")
	g.Expect(err).ShouldNot(HaveOccurred(), "kustomize not found in PATH or bin/")
	return path
}
