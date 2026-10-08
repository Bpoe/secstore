package secstore

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	for _, name := range []string{"a", "kea/db_password", "bind/dhcp-update", "app/key.v2", "A/0-x_y.z", "secret.age"} {
		t.Run(name, func(t *testing.T) {
			if err := validateName(name); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"", "/etc/passwd", "../x", "a/../x", "./a", "a/.", "a//b", "a/", ".hidden", "-key", "a b", "a\n/../b", "a\r", "a\t", "a\x00", "a\x7f", "caf\u00e9", `a\b`, "a:b"} {
		t.Run("invalid/"+name, func(t *testing.T) {
			if err := validateName(name); err == nil {
				t.Fatalf("accepted %q", name)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}, {"add", "--help"}, {"hydrate", "-h"}} {
		_, _, help, err := parseArgs(args)
		if err != nil || !help {
			t.Fatalf("%v: help=%v err=%v", args, help, err)
		}
	}
	for _, cmd := range []string{"add", "remove"} {
		command, name, help, err := parseArgs([]string{cmd, "--name", "app/key"})
		if command != cmd || name != "app/key" || help || err != nil {
			t.Fatalf("unexpected parse: %q %q %v %v", command, name, help, err)
		}
	}
	for _, args := range [][]string{
		{"unknown"}, {"add"}, {"remove"}, {"add", "--name"}, {"add", "--name", ""},
		{"add", "--name", "../x"}, {"add", "--value", "secret"}, {"hydrate", "ignored"},
		{"init", "--name", "x"}, {"remove", "--name", "x", "extra"},
	} {
		if _, _, _, err := parseArgs(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestHelp(t *testing.T) {
	var stderr bytes.Buffer
	if err := Run([]string{"--help"}, strings.NewReader(""), &stderr); err != nil {
		t.Fatal(err)
	}
	if stderr.String() != usage {
		t.Fatalf("unexpected help: %s", stderr.String())
	}
}

func TestLoadConfig(t *testing.T) {
	c, err := loadConfig(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if c.runSize != "16M" || c.fileMode != 0400 || !filepath.IsAbs(c.vaultDir) || !filepath.IsAbs(c.runDir) {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	t.Run("overrides", func(t *testing.T) {
		values := map[string]string{
			"SECSTORE_VAULT_DIR": filepath.Join(t.TempDir(), "vault"),
			"SECSTORE_RUN_DIR":   filepath.Join(t.TempDir(), "runtime"),
			"SECSTORE_RUN_SIZE":  "32M",
			"SECSTORE_FILE_MODE": "0444",
		}
		c, err := loadConfig(func(key string) string { return values[key] })
		if err != nil || c.fileMode != 0444 || c.runSize != "32M" || c.vaultDir != values["SECSTORE_VAULT_DIR"] {
			t.Fatalf("overrides: %+v, %v", c, err)
		}
	})
	for key, values := range map[string][]string{
		"SECSTORE_FILE_MODE": {"888", "0999", "1000", "04755", "-1", "u+r", "400,exec"},
		"SECSTORE_RUN_SIZE":  {"0", "-1", "16M,exec", "16M,noswap", "unlimited", "1.5M", " 16M"},
	} {
		for _, value := range values {
			t.Run(key+"/"+value, func(t *testing.T) {
				_, err := loadConfig(func(k string) string {
					if k == key {
						return value
					}
					return ""
				})
				if err == nil {
					t.Fatal("accepted invalid configuration")
				}
			})
		}
	}
	for _, paths := range [][2]string{{"/tmp/store", "/tmp/store"}, {"/tmp/store", "/tmp/store/run"}, {"/tmp/store/vault", "/tmp/store"}, {"/", "/tmp/store"}} {
		_, err := loadConfig(func(key string) string {
			switch key {
			case "SECSTORE_VAULT_DIR":
				return paths[0]
			case "SECSTORE_RUN_DIR":
				return paths[1]
			default:
				return ""
			}
		})
		if err == nil {
			t.Fatalf("accepted overlapping paths %v", paths)
		}
	}
}
