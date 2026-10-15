package secstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

type dscEngineTest struct {
	DesiredState        json.RawMessage `json:"desiredState"`
	ActualState         dscState        `json:"actualState"`
	InDesiredState      bool            `json:"inDesiredState"`
	DifferingProperties []string        `json:"differingProperties"`
}

type dscEngineSet struct {
	BeforeState       dscState `json:"beforeState"`
	AfterState        dscState `json:"afterState"`
	ChangedProperties []string `json:"changedProperties"`
}

func TestDSCIntegration(t *testing.T) {
	dsc := os.Getenv("SECSTORE_TEST_DSC")
	if dsc == "" {
		t.Skip("requires pinned DSC, a built secstore, and a private Linux mount namespace")
	}
	if err := requireRoot(); err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("SECSTORE_TEST_BINARY")
	manifest := os.Getenv("SECSTORE_TEST_MANIFEST")
	if binary == "" || manifest == "" {
		t.Fatal("SECSTORE_TEST_BINARY and SECSTORE_TEST_MANIFEST are required")
	}
	for _, path := range []string{dsc, binary, manifest} {
		if !filepath.IsAbs(path) {
			t.Fatal("integration paths must be absolute")
		}
	}
	s := testStore(t)
	base := filepath.Dir(s.vaultDir)
	t.Setenv("SECSTORE_VAULT_DIR", s.vaultDir)
	t.Setenv("SECSTORE_RUN_DIR", s.runDir)
	t.Setenv("SECSTORE_RUN_SIZE", "16M")
	t.Setenv("SECSTORE_FILE_MODE", "0400")
	t.Setenv("HOME", base)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(base, "cache"))
	t.Setenv("NO_COLOR", "1")
	t.Setenv("DSC_RESTRICTED_PATH", "")
	t.Setenv("PATH", filepath.Dir(binary)+":"+filepath.Dir(dsc)+":/usr/bin:/bin")
	t.Setenv("DSC_RESOURCE_PATH", filepath.Dir(manifest))
	t.Cleanup(func() {
		if err := syscall.Unmount(s.runDir, 0); err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.EINVAL) {
			t.Errorf("unmount integration tmpfs: %v", err)
		}
	})
	secret := "synthetic-dsc-secret-one"
	replacement := "synthetic-dsc-secret-two"
	run := func(executable, input string, args ...string) ([]byte, []byte) {
		t.Helper()
		command := exec.Command(executable, args...)
		command.Dir = base
		for _, variable := range os.Environ() {
			if variable != "DSC_RESOURCE_PATH=" && variable != "DSC_RESTRICTED_PATH=" {
				command.Env = append(command.Env, variable)
			}
		}
		command.Stdin = strings.NewReader(input)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			diagnostic := strings.ReplaceAll(strings.ReplaceAll(stderr.String(), secret, "<redacted>"), replacement, "<redacted>")
			// Do not dump an engine's echoed property bag on failure.
			if index := strings.IndexByte(diagnostic, '{'); index >= 0 {
				end := strings.LastIndexByte(diagnostic, '}')
				suffix := ""
				if end >= index {
					suffix = diagnostic[end+1:]
				}
				diagnostic = diagnostic[:index] + "<object omitted>" + suffix
			}
			t.Fatalf("integration command failed (%s): %v; %s", filepath.Base(executable), err, diagnostic)
		}
		return stdout.Bytes(), stderr.Bytes()
	}
	version, _ := run(dsc, "", "--version")
	if strings.TrimSpace(string(version)) != "dsc 3.3.0" {
		t.Fatal("integration expectations require DSC 3.3.0")
	}
	decode := func(data []byte, target any) {
		t.Helper()
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatal("DSC emitted an unexpected JSON result; output withheld")
		}
	}
	checkDiscovery := func() {
		t.Helper()
		output, _ := run(dsc, "", "resource", "list", "Secstore/secrets", "--output-format", "json")
		var result struct {
			Type string `json:"type"`
			Path string `json:"path"`
		}
		decode(output, &result)
		if result.Type != "Secstore/secrets" || filepath.Clean(result.Path) != filepath.Clean(manifest) {
			t.Fatal("DSC did not discover the installed manifest")
		}
	}
	checkDiscovery()
	t.Run("PATH-discovery", func(t *testing.T) {
		t.Setenv("DSC_RESOURCE_PATH", "")
		checkDiscovery()
	})
	schema, _ := run(dsc, "", "resource", "schema", "--resource", "Secstore/secrets", "--output-format", "json")
	var resourceSchema struct {
		Required []string `json:"required"`
	}
	decode(schema, &resourceSchema)
	if !reflect.DeepEqual(resourceSchema.Required, []string{"name"}) {
		t.Fatal("schema must accept a name-only Get")
	}
	assertSanitized := func(data ...[]byte) {
		t.Helper()
		for _, output := range data {
			if bytes.Contains(output, []byte(secret)) || bytes.Contains(output, []byte(replacement)) {
				t.Fatal("secret leaked outside the expected engine desired-state field")
			}
		}
	}
	resource := func(op, input string) ([]byte, []byte) {
		t.Helper()
		return run(dsc, input, "resource", op, "--resource", "Secstore/secrets", "--file", "-", "--output-format", "json")
	}
	checkTest := func(input string, exists, compliant, exposed bool, differences ...string) {
		t.Helper()
		output, diagnostics := resource("test", input)
		var result dscEngineTest
		decode(output, &result)
		if result.ActualState.Exist != exists || result.InDesiredState != compliant ||
			!reflect.DeepEqual(result.DifferingProperties, append([]string{}, differences...)) {
			t.Fatal("DSC did not interpret compliance/differences correctly")
		}
		actual, err := json.Marshal(result.ActualState)
		if err != nil {
			t.Fatal(err)
		}
		assertSanitized(actual, diagnostics)
		leaked := bytes.Contains(output, []byte(secret)) || bytes.Contains(output, []byte(replacement))
		if leaked != exposed {
			t.Fatal("DSC resource test exposure changed; review pinned engine expectations")
		}
		// Only desiredState.value may contain the synthetic secret.
		var envelope map[string]json.RawMessage
		decode(output, &envelope)
		var desiredState map[string]json.RawMessage
		decode(envelope["desiredState"], &desiredState)
		delete(desiredState, "value")
		envelope["desiredState"], err = json.Marshal(desiredState)
		if err != nil {
			t.Fatal(err)
		}
		remaining, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		assertSanitized(remaining)
	}
	checkSet := func(input string, exists bool, changes ...string) {
		t.Helper()
		output, diagnostics := resource("set", input)
		assertSanitized(output, diagnostics)
		var result dscEngineSet
		decode(output, &result)
		if result.AfterState.Exist != exists || !reflect.DeepEqual(result.ChangedProperties, append([]string{}, changes...)) {
			t.Fatal("DSC did not interpret Set final state/changes correctly")
		}
	}
	desired := dscInput(t, "app/key", &secret, true)
	changed := dscInput(t, "app/key", &replacement, true)
	secureDesired := dscInput(t, "app/key", map[string]string{"secureString": secret}, true)
	secureChanged := dscInput(t, "app/key", map[string]string{"secureString": replacement}, true)
	absent := dscInput(t, "app/key", nil, false)
	output, diagnostics := resource("get", `{"name":"app/key"}`)
	assertSanitized(output, diagnostics)
	var get struct {
		ActualState dscState `json:"actualState"`
	}
	decode(output, &get)
	if get.ActualState.Exist {
		t.Fatal("Get reported a missing secret as present")
	}
	checkTest(desired, false, false, true, "_exist", "value")
	checkTest(secureDesired, false, false, false, "_exist", "value")
	checkTest(absent, false, true, false)
	checkSet(absent, false)
	assertMissing(t, s.vaultDir)
	checkSet(desired, true, "_exist", "value")
	assertMissing(t, filepath.Join(s.runDir, "app", "key"))
	checkTest(desired, true, true, true)
	checkTest(secureDesired, true, true, false)
	before := snapshotDSC(t, s.vaultDir)
	checkSet(desired, true)
	checkSet(secureDesired, true)
	if !reflect.DeepEqual(before, snapshotDSC(t, s.vaultDir)) {
		t.Fatal("DSC repeated Set rewrote unchanged storage")
	}
	checkTest(changed, true, false, true, "value")
	checkTest(secureChanged, true, false, false, "value")
	checkSet(secureChanged, true, "value")
	checkSet(changed, true)
	for _, input := range []string{changed, secureChanged} {
		for _, op := range []string{"get", "test", "set"} {
			output, diagnostics := run(binary, input, "dsc", op)
			assertSanitized(output, diagnostics)
		}
	}
	before = snapshotDSC(t, s.vaultDir)
	for _, value := range []any{replacement, map[string]string{"secureString": replacement}} {
		for _, op := range []string{"get", "test", "set"} {
			command := exec.Command(binary, "dsc", op)
			command.Stdin = strings.NewReader(dscInput(t, "../"+secret, value, true))
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			var exitError *exec.ExitError
			if err := command.Run(); !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
				t.Fatal("invalid secret input did not fail with the expected exit status")
			}
			if stdout.Len() != 0 {
				t.Fatal("failed resource operation emitted state")
			}
			assertSanitized(stdout.Bytes(), stderr.Bytes())
		}
	}
	if !reflect.DeepEqual(before, snapshotDSC(t, s.vaultDir)) {
		t.Fatal("invalid input changed storage")
	}

	configPath := filepath.Join(base, "secret.dsc.config.yaml")
	config := `$schema: https://aka.ms/dsc/schemas/v3/bundled/config/document.json
parameters:
  secretValue:
    type: string
resources:
  - name: databasePassword
    type: Secstore/secrets
    properties:
      name: app/key
      value: "[parameters('secretValue')]"
`
	parameters, err := json.Marshal(map[string]any{"parameters": map[string]string{"secretValue": replacement}})
	if err != nil {
		t.Fatal(err)
	}
	for _, parameterType := range []string{"string", "secureString"} {
		document := strings.Replace(config, "type: string", "type: "+parameterType, 1)
		if err := os.WriteFile(configPath, []byte(document), 0600); err != nil {
			t.Fatal(err)
		}
		output, diagnostics = run(dsc, string(parameters), "config", "--parameters-file", "-", "test", "--file", configPath, "--output-format", "json")
		var configResult struct {
			HadErrors bool `json:"hadErrors"`
			Results   []struct {
				Result dscEngineTest `json:"result"`
			} `json:"results"`
		}
		decode(output, &configResult)
		if configResult.HadErrors || len(configResult.Results) != 1 || !configResult.Results[0].Result.InDesiredState {
			t.Fatalf("%s parameter did not reach the resource correctly", parameterType)
		}
		assertSanitized(diagnostics)
		var desiredState struct {
			Value string `json:"value"`
		}
		decode(configResult.Results[0].Result.DesiredState, &desiredState)
		if parameterType == "secureString" {
			assertSanitized(output)
			if desiredState.Value != "<secureValue>" {
				t.Fatal("DSC secureString redaction changed; review pinned engine expectations")
			}
		} else if desiredState.Value != replacement || bytes.Count(output, []byte(replacement)) != 1 || bytes.Contains(output, []byte(secret)) {
			t.Fatal("DSC config test exposure changed; review pinned engine expectations")
		}
		before = snapshotDSC(t, s.vaultDir)
		output, diagnostics = run(dsc, string(parameters), "config", "--parameters-file", "-", "set", "--file", configPath, "--output-format", "json")
		assertSanitized(output, diagnostics)
		if !reflect.DeepEqual(before, snapshotDSC(t, s.vaultDir)) {
			t.Fatal("DSC config Set rewrote an unchanged secret")
		}
	}
	checkTest(absent, true, false, false, "_exist")
	checkSet(absent, false, "_exist")
	checkSet(absent, false)
	checkSet(changed, true, "_exist", "value")
	absenceConfig := strings.Replace(config, `value: "[parameters('secretValue')]"`, "_exist: false", 1)
	if err := os.WriteFile(configPath, []byte(absenceConfig), 0600); err != nil {
		t.Fatal(err)
	}
	output, diagnostics = run(dsc, string(parameters), "config", "--parameters-file", "-", "set", "--file", configPath, "--output-format", "json")
	assertSanitized(output, diagnostics)
	checkTest(absent, false, true, false)
	empty := ""
	emptyInput := dscInput(t, "empty", &empty, true)
	secureEmpty := dscInput(t, "empty", map[string]string{"secureString": empty}, true)
	checkSet(emptyInput, true, "_exist", "value")
	checkTest(emptyInput, true, true, false)
	checkTest(secureEmpty, true, true, false)
	checkSet(secureEmpty, true)
}
