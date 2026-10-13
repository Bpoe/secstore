package secstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/iotest"
	"time"
)

func dscInput(t *testing.T, name string, value *string, exists bool) string {
	t.Helper()
	input := map[string]any{"name": name, "_exist": exists}
	if value != nil {
		input["value"] = *value
	}
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertDSC(t *testing.T, s *store, op, input string, exists, compliant bool, wantDiff ...string) {
	t.Helper()
	var output bytes.Buffer
	if err := s.runDSC(op, strings.NewReader(input), &output); err != nil {
		t.Fatalf("%s failed: %v", op, err)
	}
	decoder := json.NewDecoder(&output)
	var state map[string]any
	if err := decoder.Decode(&state); err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(input), &expected); err != nil {
		t.Fatal(err)
	}
	if len(state) != 3 || state["_exist"] != exists || state["name"] != expected.Name {
		t.Fatal("incorrect or unsanitized state")
	}
	if op == "test" {
		if state["_inDesiredState"] != compliant {
			t.Fatal("incorrect compliance")
		}
	} else if state["_inDesiredState"] != nil {
		t.Fatal("compliance must be null outside Test")
	}
	if op != "get" {
		var diff []string
		if err := decoder.Decode(&diff); err != nil {
			t.Fatal(err)
		}
		if diff == nil || !reflect.DeepEqual(diff, append([]string{}, wantDiff...)) {
			t.Fatalf("incorrect differences: %v", diff)
		}
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("unexpected trailing output")
	}
}

type dscFileSnapshot struct {
	Mode     os.FileMode
	Modified time.Time
	Inode    uint64
	UID, GID uint32
	Data     string
}

func snapshotDSC(t *testing.T, base string) map[string]dscFileSnapshot {
	t.Helper()
	result := make(map[string]dscFileSnapshot)
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		item := dscFileSnapshot{Mode: info.Mode(), Modified: info.ModTime(), Inode: stat.Ino, UID: stat.Uid, GID: stat.Gid}
		if info.Mode().IsRegular() {
			item.Data = string(readFile(t, path))
		}
		result[path] = item
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDSCLifecycle(t *testing.T) {
	s := testStore(t)
	mountCalls := 0
	prepare := s.prepareRuntime
	s.prepareRuntime = func(c config, log io.Writer) error {
		mountCalls++
		return prepare(c, log)
	}
	secret := "synthetic-secret-\u00e9-\x00\n"
	desired := dscInput(t, "app/key", &secret, true)
	absent := dscInput(t, "app/key", nil, false)
	assertDSC(t, s, "get", `{"name":"app/key"}`, false, false)
	assertDSC(t, s, "test", desired, false, false, "_exist", "value")
	assertDSC(t, s, "test", absent, false, true)
	assertDSC(t, s, "set", absent, false, false)
	assertMissing(t, s.vaultDir)
	assertMissing(t, s.runDir)
	assertDSC(t, s, "set", desired, true, false, "_exist", "value")
	if mountCalls != 1 {
		t.Fatal("automatic initialization did not prepare runtime exactly once")
	}
	assertMissing(t, filepath.Join(s.runDir, "app", "key"))
	identity := readFile(t, filepath.Join(s.vaultDir, "identity.txt"))
	assertDSC(t, s, "get", `{"name":"app/key"}`, true, false)
	assertDSC(t, s, "test", desired, true, true)
	assertDSC(t, s, "test", absent, true, false, "_exist")
	before := snapshotDSC(t, filepath.Dir(s.vaultDir))
	assertDSC(t, s, "set", desired, true, false)
	if !reflect.DeepEqual(before, snapshotDSC(t, filepath.Dir(s.vaultDir))) {
		t.Fatal("unchanged Set modified storage or runtime")
	}
	execute(t, s, "hydrate", "", nil)
	replacement := "synthetic-replacement"
	changed := dscInput(t, "app/key", &replacement, true)
	assertDSC(t, s, "test", changed, true, false, "value")
	assertDSC(t, s, "set", changed, true, false, "value")
	if string(readFile(t, filepath.Join(s.runDir, "app", "key"))) != secret {
		t.Fatal("update changed hydrated plaintext")
	}
	if !bytes.Equal(identity, readFile(t, filepath.Join(s.vaultDir, "identity.txt"))) {
		t.Fatal("Set rotated identity")
	}
	assertDSC(t, s, "set", absent, false, false, "_exist")
	assertMissing(t, filepath.Join(s.runDir, "app"))
	assertMissing(t, filepath.Join(s.vaultDir, "secrets", "app"))
	assertDSC(t, s, "set", absent, false, false)
	assertDSC(t, s, "test", absent, false, true)
	empty := ""
	assertDSC(t, s, "set", dscInput(t, "empty", &empty, true), true, false, "_exist", "value")
	assertDSC(t, s, "test", dscInput(t, "empty", &empty, true), true, true)
	assertDSC(t, s, "set", dscInput(t, "empty", &empty, true), true, false)
}

func TestDSCReadOnly(t *testing.T) {
	for _, setup := range []string{"missing", "empty", "empty-secrets", "lock-only", "initialized"} {
		t.Run(setup, func(t *testing.T) {
			s := testStore(t)
			switch setup {
			case "empty", "empty-secrets", "lock-only":
				root, err := privateDir(s.vaultDir)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				if setup == "empty-secrets" {
					if err := root.Mkdir("secrets", 0700); err != nil {
						t.Fatal(err)
					}
				}
				if setup == "lock-only" {
					lock, err := acquireLock(root, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					lock.Close()
				}
			case "initialized":
				execute(t, s, "init", "", nil)
				execute(t, s, "add", "key", []byte("synthetic"))
				if err := os.Chmod(s.vaultDir, 0750); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(s.vaultDir, ".lock"), 0400); err != nil {
					t.Fatal(err)
				}
			}
			s.prepareRuntime = func(config, io.Writer) error {
				t.Fatal("read-only command prepared runtime")
				return nil
			}
			before := snapshotDSC(t, filepath.Dir(s.vaultDir))
			assertDSC(t, s, "get", `{"name":"new/nested/key"}`, false, false)
			assertDSC(t, s, "test", `{"name":"new/nested/key","value":""}`, false, false, "_exist", "value")
			assertDSC(t, s, "test", `{"name":"new/nested/key","_exist":false}`, false, true)
			if setup == "initialized" {
				assertDSC(t, s, "get", `{"name":"key"}`, true, false)
				assertDSC(t, s, "test", `{"name":"key","value":"synthetic"}`, true, true)
			}
			if !reflect.DeepEqual(before, snapshotDSC(t, filepath.Dir(s.vaultDir))) {
				t.Fatal("Get/Test changed filesystem state")
			}
		})
	}
}

func TestDSCFailures(t *testing.T) {
	for _, failure := range []string{"identity", "missing-identity", "missing-secrets", "missing-lock", "truncated", "tampered", "symlink", "writable", "wrong-parent"} {
		t.Run(failure, func(t *testing.T) {
			s := testStore(t)
			execute(t, s, "init", "", nil)
			secret := strings.Repeat("synthetic-secret", 12000)
			execute(t, s, "add", "app/key", []byte(secret))
			blob := filepath.Join(s.vaultDir, "secrets", "app", "key.age")
			switch failure {
			case "identity":
				if err := os.WriteFile(filepath.Join(s.vaultDir, "identity.txt"), []byte("synthetic-secret\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-identity", "missing-lock":
				path := "identity.txt"
				if failure == "missing-lock" {
					path = ".lock"
				}
				if err := os.Remove(filepath.Join(s.vaultDir, path)); err != nil {
					t.Fatal(err)
				}
			case "missing-secrets":
				if err := os.Rename(filepath.Join(s.vaultDir, "secrets"), filepath.Join(s.vaultDir, "orphaned")); err != nil {
					t.Fatal(err)
				}
			case "truncated", "tampered":
				data := readFile(t, blob)
				if failure == "truncated" {
					data = data[:len(data)-1]
				} else {
					data[len(data)-1] ^= 1
				}
				if err := os.WriteFile(blob, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("app", filepath.Join(s.vaultDir, "secrets", "alias")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(blob, 0666); err != nil {
					t.Fatal(err)
				}
			case "wrong-parent":
				if err := os.Rename(filepath.Join(s.vaultDir, "secrets", "app"), filepath.Join(s.vaultDir, "saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(s.vaultDir, "secrets", "app"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, operation := range []string{"get", "test", "set"} {
				var output bytes.Buffer
				err := s.runDSC(operation, strings.NewReader(`{"name":"app/key","value":"different-synthetic-secret"}`), &output)
				if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "synthetic-secret") {
					t.Fatalf("%s did not fail safely: %v", operation, err)
				}
			}
			if failure == "truncated" || failure == "tampered" {
				assertDSC(t, s, "set", `{"name":"app/key","_exist":false}`, false, false, "_exist")
			}
		})
	}
}

func TestDSCInitializationFailure(t *testing.T) {
	s := testStore(t)
	s.prepareRuntime = func(config, io.Writer) error { return errors.New("synthetic-secret mount failure") }
	var output bytes.Buffer
	err := s.runDSC("set", strings.NewReader(`{"name":"key","value":"synthetic-secret"}`), &output)
	if err == nil || output.Len() != 0 || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("initialization error was ignored or exposed")
	}
	assertMissing(t, filepath.Join(s.vaultDir, "secrets", "key.age"))
}

func TestDSCInvalidInputDoesNotInitialize(t *testing.T) {
	s := testStore(t)
	for _, input := range []string{`{"name":"key"}`, `{"name":"key","value":"synthetic"}{}`, strings.Repeat(" ", maxDSCInput+1)} {
		if err := s.runDSC("set", strings.NewReader(input), io.Discard); err == nil {
			t.Fatal("accepted invalid input")
		}
		assertMissing(t, s.vaultDir)
		assertMissing(t, s.runDir)
	}
}

func TestDSCOutputFailure(t *testing.T) {
	s := testStore(t)
	cause := errors.New("synthetic-secret writer failure")
	err := s.runDSC("get", strings.NewReader(`{"name":"key"}`), failingDSCWriter{cause})
	if !errors.Is(err, cause) || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("output error lost or exposed")
	}
	err = s.runDSC("set", iotest.ErrReader(cause), io.Discard)
	if !errors.Is(err, cause) {
		t.Fatal("input error lost")
	}
	assertMissing(t, s.vaultDir)
}

type failingDSCWriter struct{ err error }

func (w failingDSCWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDSCExistingLock(t *testing.T) {
	s := testStore(t)
	execute(t, s, "init", "", nil)
	root, err := os.OpenRoot(s.vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := acquireExistingLock(root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if other, err := acquireLock(root, 20*time.Millisecond); err == nil {
		other.Close()
		t.Fatal("legacy writer bypassed DSC lock")
	}
	lock.Close()
	other, err := acquireLock(root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
}

func TestDSCConcurrentSet(t *testing.T) {
	s := testStore(t)
	var initializations atomic.Int32
	prepare := s.prepareRuntime
	s.prepareRuntime = func(c config, log io.Writer) error {
		initializations.Add(1)
		return prepare(c, log)
	}
	var group sync.WaitGroup
	failures := make(chan error, 6)
	for range 6 {
		group.Go(func() {
			failures <- s.runDSC("set", strings.NewReader(`{"name":"key","value":"synthetic"}`), io.Discard)
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
		if initializations.Load() != 1 {
			t.Fatal("concurrent Set initialized more than once")
		}
	}
	assertDSC(t, s, "test", `{"name":"key","value":"synthetic"}`, true, true)
}

func TestDSCPermissions(t *testing.T) {
	if base := os.Getenv("SECSTORE_PERMISSION_CHILD"); base != "" {
		s := &store{config: config{vaultDir: filepath.Join(base, "vault"), runDir: filepath.Join(base, "run")}, log: io.Discard}
		for _, operation := range []string{"get", "test", "set"} {
			var output bytes.Buffer
			err := s.runDSC(operation, strings.NewReader(`{"name":"key","value":"synthetic"}`), &output)
			if !errors.Is(err, fs.ErrPermission) || output.Len() != 0 {
				t.Fatalf("%s must report permission failure: %v", operation, err)
			}
		}
		if err := Run([]string{"dsc", "get"}, strings.NewReader(`{"name":"key"}`), io.Discard, io.Discard); err == nil {
			t.Fatal("non-root DSC invocation accepted")
		}
		return
	}
	if os.Geteuid() != 0 {
		s := testStore(t)
		execute(t, s, "init", "", nil)
		path := filepath.Join(s.vaultDir, "identity.txt")
		if err := os.Chmod(path, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(path, 0600)
		err := s.runDSC("get", strings.NewReader(`{"name":"key"}`), io.Discard)
		if !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("unreadable identity: %v", err)
		}
		return
	}
	base, err := os.MkdirTemp("", "secstore-dsc-permission-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "vault"), 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(base, "permission.test")
	if err := os.WriteFile(binary, readFile(t, os.Args[0]), 0755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-test.run=^TestDSCPermissions$")
	command.Env = append(os.Environ(), "SECSTORE_PERMISSION_CHILD="+base)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unprivileged subprocess: %v: %s", err, output)
	}
}
