package secstore

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestDSCInput(t *testing.T) {
	for _, tc := range []struct {
		name, operation, input string
		valid                  bool
	}{
		{"get", "get", `{"name":"app/key"}`, true},
		{"empty-value", "set", `{"name":"app/key","value":""}`, true},
		{"secure-string-object", "set", `{"name":"key","value":{"secureString":"synthetic-secret"}}`, false},
		{"empty-secure-string-object", "set", `{"name":"key","value":{"secureString":""}}`, false},
		{"absent", "test", `{"name":"key","_exist":false}`, true},
		{"null-compliance", "get", `{"name":"key","_inDesiredState":null}`, true},
		{"whitespace", "get", " \n{\"name\":\"key\"}\t\n", true},
		{"no-input", "get", "", false},
		{"array", "get", "[]", false},
		{"null", "get", "null", false},
		{"string", "get", `"synthetic-secret"`, false},
		{"number", "get", "1", false},
		{"missing-name", "get", `{}`, false},
		{"empty-name", "get", `{"name":""}`, false},
		{"invalid-name", "get", `{"name":"../synthetic-secret"}`, false},
		{"null-name", "get", `{"name":null}`, false},
		{"wrong-name", "get", `{"name":[]}`, false},
		{"missing-value", "test", `{"name":"key"}`, false},
		{"missing-set-value", "set", `{"name":"key","_exist":true}`, false},
		{"null-value", "set", `{"name":"key","value":null}`, false},
		{"wrong-value", "set", `{"name":"key","value":{}}`, false},
		{"wrong-secure-string", "set", `{"name":"key","value":{"secureString":null}}`, false},
		{"extra-secure-property", "set", `{"name":"key","value":{"secureString":"","synthetic-secret":true}}`, false},
		{"duplicate-secure-property", "set", `{"name":"key","value":{"secureString":"","secureString":"synthetic-secret"}}`, false},
		{"null-exist", "get", `{"name":"key","_exist":null}`, false},
		{"wrong-exist", "get", `{"name":"key","_exist":"synthetic-secret"}`, false},
		{"unknown", "get", `{"name":"key","synthetic-secret":true}`, false},
		{"duplicate", "set", `{"name":"key","value":"synthetic-secret","value":""}`, false},
		{"duplicate-escaped", "get", `{"name":"key","\u006eame":"other"}`, false},
		{"case", "get", `{"Name":"key"}`, false},
		{"computed", "test", `{"name":"key","_exist":false,"_inDesiredState":true}`, false},
		{"truncated", "get", `{"name":"key"`, false},
		{"trailing", "get", `{"name":"key"} {"value":"synthetic-secret"}`, false},
		{"garbage", "get", `{"name":"key"} synthetic-secret`, false},
		{"utf8", "set", "{\"name\":\"key\",\"value\":\"\xff\"}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := readDSCRequest(strings.NewReader(tc.input), tc.operation)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("input leaked in error")
			}
			if tc.name == "empty-value" && (request.value == nil || *request.value != "" || !request.exist) {
				t.Fatal("empty value or default existence lost")
			}
		})
	}
}

func TestDSCInputLimit(t *testing.T) {
	input := `{"name":"key"}`
	input += strings.Repeat(" ", maxDSCInput-len(input))
	if _, err := readDSCRequest(strings.NewReader(input), "get"); err != nil {
		t.Fatalf("exact limit: %v", err)
	}
	if _, err := readDSCRequest(strings.NewReader(input+" "), "get"); err == nil {
		t.Fatal("accepted input beyond limit")
	}
	cause := errors.New("synthetic-secret read failure")
	_, err := readDSCRequest(iotest.ErrReader(cause), "get")
	if !errors.Is(err, cause) || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("input error classification or sanitization failed: %v", err)
	}
}

func TestDSCArguments(t *testing.T) {
	for _, args := range [][]string{{"dsc"}, {"dsc", "synthetic-secret"}, {"dsc", "set", "synthetic-secret"}} {
		err := Run(args, strings.NewReader(""), io.Discard, io.Discard)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("invalid DSC arguments were accepted or echoed")
		}
	}
}
