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

package runtimes

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/onsi/gomega"
	"gopkg.in/yaml.v3"
)

const (
	runtimeManifestPath = "../../manifests/runtimes/vllm-extract-cuda.yaml"
	verifierModelPath   = "/data/model"
	hiddenStatesPath    = "/data/hidden_states"

	verifierModelEnv        = "SPECULATOR_VERIFIER_MODEL"
	hiddenStatesPathEnv     = "SPECULATOR_HS_PATH"
	gpuMemoryUtilizationEnv = "SPECULATOR_GPU_MEM_UTIL"
	vllmGPUCountEnv         = "SPECULATOR_VLLM_GPU_COUNT"
	targetLayerIDsEnv       = "SPECULATOR_TARGET_LAYER_IDS"
	speculativeConfigEnv    = "SPECULATOR_VLLM_SPECULATIVE_CONFIG"
)

type runtimeManifest struct {
	Spec struct {
		Template struct {
			Spec struct {
				ReplicatedJobs []replicatedJob `yaml:"replicatedJobs"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type replicatedJob struct {
	Name     string                `yaml:"name"`
	Template replicatedJobTemplate `yaml:"template"`
}

type replicatedJobTemplate struct {
	Spec jobSpec `yaml:"spec"`
}

type jobSpec struct {
	Template podTemplate `yaml:"template"`
}

type podTemplate struct {
	Spec podSpec `yaml:"spec"`
}

type podSpec struct {
	InitContainers []containerSpec `yaml:"initContainers"`
}

type containerSpec struct {
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`
	Args    []string `yaml:"args"`
}

func TestLauncherPassesSpeculativeConfigAsSingleArgument(t *testing.T) {
	g := gomega.NewWithT(t)
	script := readLauncherScript(t)
	providedConfig := `{
  "method": "extract_hidden_states",
  "enforce_eager": true,
  "max_model_len": 2048,
  "kwargs": {
    "parallel_drafting": false,
    "nested": {"flags": [true, false, null], "message": "spaces and \"quotes\""}
  }
}`

	argv := runLauncher(t, script, map[string]string{
		verifierModelEnv:        verifierModelPath,
		hiddenStatesPathEnv:     hiddenStatesPath,
		gpuMemoryUtilizationEnv: "0.72",
		vllmGPUCountEnv:         "3",
		targetLayerIDsEnv:       "2,5",
		speculativeConfigEnv:    providedConfig,
	})

	assertLauncherArgs(t, g, argv, providedConfig, "0.72", 3)
}

func TestLauncherUsesExtractionFallbackWhenSpeculativeConfigIsUnsetOrEmpty(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		includeEnvVar bool
	}{
		{name: "unset"},
		{name: "empty", includeEnvVar: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			env := map[string]string{
				verifierModelEnv:        verifierModelPath,
				hiddenStatesPathEnv:     hiddenStatesPath,
				gpuMemoryUtilizationEnv: "",
				vllmGPUCountEnv:         "",
				targetLayerIDsEnv:       "3,7,11",
			}
			if testCase.includeEnvVar {
				env[speculativeConfigEnv] = ""
			}

			argv := runLauncher(t, readLauncherScript(t), env)
			speculativeConfig := speculativeConfigArg(t, g, argv)

			var extractionConfig struct {
				Method               string `json:"method"`
				NumSpeculativeTokens int    `json:"num_speculative_tokens"`
				DraftModelConfig     struct {
					HFConfig struct {
						LayerIDs []int `json:"eagle_aux_hidden_state_layer_ids"`
					} `json:"hf_config"`
				} `json:"draft_model_config"`
			}
			g.Expect(json.Unmarshal([]byte(speculativeConfig), &extractionConfig)).To(gomega.Succeed())
			g.Expect(extractionConfig.Method).To(gomega.Equal("extract_hidden_states"))
			g.Expect(extractionConfig.NumSpeculativeTokens).To(gomega.Equal(1))
			g.Expect(extractionConfig.DraftModelConfig.HFConfig.LayerIDs).To(
				gomega.Equal([]int{3, 7, 11}),
			)

			assertLauncherArgs(t, g, argv, speculativeConfig, "0.9", 1)
		})
	}
}

func readLauncherScript(t *testing.T) string {
	t.Helper()

	manifestBytes, err := os.ReadFile(runtimeManifestPath)
	if err != nil {
		t.Fatalf("read runtime manifest: %v", err)
	}
	var manifest runtimeManifest
	if err := yaml.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("unmarshal runtime manifest: %v", err)
	}
	for _, job := range manifest.Spec.Template.Spec.ReplicatedJobs {
		if job.Name != "node" {
			continue
		}
		for _, container := range job.Template.Spec.Template.Spec.InitContainers {
			if container.Name != "vllm-sidecar" {
				continue
			}
			if !equalStrings(container.Command, []string{"sh", "-c"}) {
				t.Fatalf("expected the sidecar command to be [sh -c], got %q", container.Command)
			}
			if len(container.Args) != 1 {
				t.Fatalf("expected one launcher script argument, got %d", len(container.Args))
			}
			return container.Args[0]
		}
	}
	t.Fatal("could not find node/vllm-sidecar launcher in runtime manifest")
	return ""
}

func runLauncher(t *testing.T, launcherScript string, launcherEnv map[string]string) []string {
	t.Helper()

	tempDir := t.TempDir()
	binDir := filepath.Join(tempDir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatalf("create fake binary directory: %v", err)
	}
	capturePath := filepath.Join(tempDir, "argv.bin")
	fakePython := filepath.Join(binDir, "python3")
	fakePythonScript := "#!/bin/sh\nprintf '%s\\000' \"$@\" > \"$ARGV_CAPTURE\"\n"
	if err := os.WriteFile(fakePython, []byte(fakePythonScript), 0o755); err != nil {
		t.Fatalf("write fake python3: %v", err)
	}

	launcherEnv["ARGV_CAPTURE"] = capturePath
	launcherEnv["PATH"] = binDir + string(os.PathListSeparator) + os.Getenv("PATH")
	command := exec.Command("sh", "-c", launcherScript)
	command.Env = launcherEnvironment(launcherEnv)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run launcher: %v\n%s", err, output)
	}

	captured, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read captured argv: %v", err)
	}
	if len(captured) == 0 || captured[len(captured)-1] != 0 {
		t.Fatalf("captured argv is not NUL terminated: %q", captured)
	}
	arguments := bytes.Split(captured[:len(captured)-1], []byte{0})
	argv := make([]string, len(arguments))
	for i, argument := range arguments {
		argv[i] = string(argument)
	}
	return argv
}

func launcherEnvironment(overrides map[string]string) []string {
	controlled := map[string]struct{}{
		"ARGV_CAPTURE":          {},
		"PATH":                  {},
		gpuMemoryUtilizationEnv: {},
		hiddenStatesPathEnv:     {},
		targetLayerIDsEnv:       {},
		verifierModelEnv:        {},
		vllmGPUCountEnv:         {},
		speculativeConfigEnv:    {},
	}
	environment := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, isControlled := controlled[key]; !isControlled {
			environment[key] = value
		}
	}
	for key, value := range overrides {
		environment[key] = value
	}

	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+environment[key])
	}
	return result
}

func assertLauncherArgs(
	t *testing.T,
	g *gomega.WithT,
	argv []string,
	expectedSpeculativeConfig string,
	expectedGPUMemoryUtilization string,
	expectedTensorParallelSize int,
) {
	t.Helper()

	var speculativeIndices []int
	for i, argument := range argv {
		if argument == "--speculative-config" {
			speculativeIndices = append(speculativeIndices, i)
		}
	}
	g.Expect(speculativeIndices).To(gomega.HaveLen(1))
	if len(speculativeIndices) != 1 {
		return
	}
	index := speculativeIndices[0]
	g.Expect(index + 1).To(gomega.BeNumerically("<", len(argv)))
	if index+1 >= len(argv) {
		return
	}
	g.Expect(argv[index+1]).To(gomega.Equal(expectedSpeculativeConfig))

	kvTransferConfig := argumentValue(t, g, argv, "--kv-transfer-config")
	var transferConfig struct {
		Connector string `json:"kv_connector"`
		Role      string `json:"kv_role"`
		Extra     struct {
			SharedStoragePath string `json:"shared_storage_path"`
		} `json:"kv_connector_extra_config"`
	}
	g.Expect(json.Unmarshal([]byte(kvTransferConfig), &transferConfig)).To(gomega.Succeed())
	g.Expect(transferConfig.Connector).To(gomega.Equal("ExampleHiddenStatesConnector"))
	g.Expect(transferConfig.Role).To(gomega.Equal("kv_producer"))
	g.Expect(transferConfig.Extra.SharedStoragePath).To(gomega.Equal(hiddenStatesPath))

	withoutSpeculativeConfig := make([]string, 0, len(argv)-2)
	withoutSpeculativeConfig = append(withoutSpeculativeConfig, argv[:index]...)
	withoutSpeculativeConfig = append(withoutSpeculativeConfig, argv[index+2:]...)
	expectedNonSpeculativeArgs := []string{
		"-m",
		"vllm.entrypoints.cli.main",
		"serve",
		verifierModelPath,
		"--kv-transfer-config",
		kvTransferConfig,
		"--port",
		"8234",
		"--gpu-memory-utilization",
		expectedGPUMemoryUtilization,
		"--no-enable-chunked-prefill",
		"--trust-remote-code",
	}
	if expectedTensorParallelSize > 1 {
		expectedNonSpeculativeArgs = append(
			expectedNonSpeculativeArgs,
			"--tensor-parallel-size",
			strconv.Itoa(expectedTensorParallelSize),
		)
	}
	g.Expect(withoutSpeculativeConfig).To(gomega.Equal(expectedNonSpeculativeArgs))
}

func speculativeConfigArg(t *testing.T, g *gomega.WithT, argv []string) string {
	t.Helper()
	return argumentValue(t, g, argv, "--speculative-config")
}

func argumentValue(t *testing.T, g *gomega.WithT, argv []string, flag string) string {
	t.Helper()

	var indices []int
	for i, argument := range argv {
		if argument == flag {
			indices = append(indices, i)
		}
	}
	g.Expect(indices).To(gomega.HaveLen(1))
	if len(indices) != 1 {
		return ""
	}
	index := indices[0]
	g.Expect(index + 1).To(gomega.BeNumerically("<", len(argv)))
	if index+1 >= len(argv) {
		return ""
	}
	return argv[index+1]
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
