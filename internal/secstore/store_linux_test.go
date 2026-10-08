package secstore

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"filippo.io/age"
)

func testStore(t *testing.T) *store {
	t.Helper()
	base := privateTempDir(t)
	return &store{
		config: config{vaultDir: filepath.Join(base, "vault"), runDir: filepath.Join(base, "run"), runSize: "16M", fileMode: 0400},
		log:    io.Discard,
		// Unit tests use only synthetic secrets. Real mounts are covered by
		// TestRuntimeIntegration in a private Linux mount namespace.
		prepareRuntime: func(c config, _ io.Writer) error {
			root, err := privateDir(c.runDir)
			if err != nil {
				return err
			}
			return root.Close()
		},
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func execute(t *testing.T, s *store, command, name string, data []byte) {
	t.Helper()
	if err := s.execute(command, name, bytes.NewReader(data)); err != nil {
		t.Fatalf("%s %s: %v", command, name, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected missing %s: %v", path, err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode=%04o, want %04o", path, info.Mode().Perm(), want)
	}
}

func TestStoreLifecycle(t *testing.T) {
	s := testStore(t)
	execute(t, s, "init", "", nil)
	identityPath := filepath.Join(s.vaultDir, "identity.txt")
	identity := readFile(t, identityPath)
	execute(t, s, "init", "", nil)
	if !bytes.Equal(identity, readFile(t, identityPath)) {
		t.Fatal("init replaced the identity")
	}
	assertMode(t, s.vaultDir, 0700)
	assertMode(t, filepath.Join(s.vaultDir, "secrets"), 0700)
	assertMode(t, identityPath, 0600)
	assertMode(t, filepath.Join(s.vaultDir, ".lock"), 0600)
	assertMode(t, s.runDir, 0700)

	input := bytes.Repeat([]byte("synthetic-secret\x00\xff\n"), 10000)
	execute(t, s, "add", "app/password", input)
	blobPath := filepath.Join(s.vaultDir, "secrets", "app", "password.age")
	plainPath := filepath.Join(s.runDir, "app", "password")
	ciphertext := readFile(t, blobPath)
	if bytes.Contains(ciphertext, []byte("synthetic-secret")) {
		t.Fatal("plaintext found in ciphertext")
	}
	assertMissing(t, plainPath)
	assertMode(t, blobPath, 0600)
	assertMode(t, filepath.Dir(blobPath), 0700)

	identities, err := age.ParseIdentities(bytes.NewReader(identity))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(plaintext)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("age interoperability: %v", err)
	}

	execute(t, s, "hydrate", "", nil)
	if !bytes.Equal(readFile(t, plainPath), input) {
		t.Fatal("hydration changed binary plaintext")
	}
	assertMode(t, plainPath, 0400)
	assertMode(t, filepath.Dir(plainPath), 0700)
	s.fileMode = 0444
	execute(t, s, "add", "app/password", []byte("replacement"))
	if !bytes.Equal(readFile(t, plainPath), input) {
		t.Fatal("add unexpectedly modified the runtime copy")
	}
	oldReader, err := os.Open(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	defer oldReader.Close()
	execute(t, s, "hydrate", "", nil)
	if string(readFile(t, plainPath)) != "replacement" {
		t.Fatal("hydrate did not publish replacement")
	}
	oldData, err := io.ReadAll(oldReader)
	if err != nil || !bytes.Equal(oldData, input) {
		t.Fatalf("replacement was not an atomic rename: %v", err)
	}
	assertMode(t, plainPath, 0444)
	execute(t, s, "add", "empty", nil)
	execute(t, s, "hydrate", "", nil)
	if len(readFile(t, filepath.Join(s.runDir, "empty"))) != 0 {
		t.Fatal("empty secret did not round-trip")
	}
	execute(t, s, "remove", "app/password", nil)
	execute(t, s, "remove", "app/password", nil)
	assertMissing(t, blobPath)
	assertMissing(t, plainPath)
	assertMissing(t, filepath.Dir(blobPath))
	assertMissing(t, filepath.Dir(plainPath))
	execute(t, s, "remove", "empty", nil)
	assertMode(t, filepath.Join(s.vaultDir, "secrets"), 0700)
	execute(t, s, "hydrate", "", nil)
}

func TestFailedAddPreservesBlob(t *testing.T) {
	s := testStore(t)
	execute(t, s, "init", "", nil)
	execute(t, s, "add", "key", []byte("original"))
	path := filepath.Join(s.vaultDir, "secrets", "key.age")
	before := readFile(t, path)
	sourceErr := errors.New("synthetic input failure")
	input := io.MultiReader(strings.NewReader("partial"), iotest.ErrReader(sourceErr))
	err := s.execute("add", "key", input)
	if !errors.Is(err, sourceErr) {
		t.Fatalf("original error was not preserved: %v", err)
	}
	for _, context := range []string{"add in vault", s.vaultDir, path, "stream stdin into age encryption"} {
		if !strings.Contains(err.Error(), context) {
			t.Fatalf("error lacks %q context: %v", context, err)
		}
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("failed add replaced the original ciphertext")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "key.age" {
		t.Fatalf("temporary ciphertext leaked: %v %v", entries, err)
	}
}

func TestFailedHydrationPreservesRuntime(t *testing.T) {
	for _, failure := range []string{"truncated", "tampered", "wrong-identity", "invalid-name", "path-conflict"} {
		t.Run(failure, func(t *testing.T) {
			s := testStore(t)
			execute(t, s, "init", "", nil)
			execute(t, s, "add", "a", []byte("old-a"))
			execute(t, s, "add", "z", []byte("old-z"))
			execute(t, s, "hydrate", "", nil)
			execute(t, s, "add", "a", []byte("new-a"))
			z := filepath.Join(s.vaultDir, "secrets", "z.age")
			switch failure {
			case "truncated", "tampered":
				data := readFile(t, z)
				if failure == "truncated" {
					data = data[:len(data)-1]
				} else {
					data[len(data)-1] ^= 1
				}
				if err := os.WriteFile(z, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-identity":
				identity, err := age.GenerateX25519Identity()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(s.vaultDir, "identity.txt"), []byte(identity.String()+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid-name":
				if err := os.Rename(z, filepath.Join(s.vaultDir, "secrets", ".hidden.age")); err != nil {
					t.Fatal(err)
				}
			case "path-conflict":
				execute(t, s, "add", "a/child", []byte("conflict"))
			}
			if err := os.WriteFile(filepath.Join(s.runDir, "stale"), []byte("keep-until-success"), 0400); err != nil {
				t.Fatal(err)
			}
			if err := s.execute("hydrate", "", nil); err == nil {
				t.Fatal("hydration should fail")
			}
			for _, name := range []string{"a", "z"} {
				if got := string(readFile(t, filepath.Join(s.runDir, name))); got != "old-"+name {
					t.Fatalf("failed hydration changed %s: %q", name, got)
				}
			}
			if got := string(readFile(t, filepath.Join(s.runDir, "stale"))); got != "keep-until-success" {
				t.Fatal("failed hydration removed stale runtime copy")
			}
			entries, err := os.ReadDir(s.runDir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".hydrate.") {
					t.Fatal("staged plaintext leaked after hydration failed")
				}
			}
		})
	}
}

func TestHydrationPrunesStaleFiles(t *testing.T) {
	s := testStore(t)
	execute(t, s, "init", "", nil)
	execute(t, s, "add", "keep", []byte("kept"))
	execute(t, s, "add", "old/nested/key", []byte("stale"))
	execute(t, s, "hydrate", "", nil)
	if err := os.Remove(filepath.Join(s.vaultDir, "secrets", "old", "nested", "key.age")); err != nil {
		t.Fatal(err)
	}
	abandoned := filepath.Join(s.runDir, ".hydrate.interrupted", "nested")
	if err := os.MkdirAll(abandoned, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(abandoned, "partial"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	execute(t, s, "hydrate", "", nil)
	assertMissing(t, filepath.Join(s.runDir, "old"))
	assertMissing(t, filepath.Join(s.runDir, ".hydrate.interrupted"))
	if string(readFile(t, filepath.Join(s.runDir, "keep"))) != "kept" {
		t.Fatal("lost wanted secret")
	}
	if err := os.Remove(filepath.Join(s.vaultDir, "secrets", "keep.age")); err != nil {
		t.Fatal(err)
	}
	execute(t, s, "hydrate", "", nil)
	entries, err := os.ReadDir(s.runDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("empty vault did not clear runtime: %v %v", entries, err)
	}
}

func TestRequireInitialized(t *testing.T) {
	for _, command := range []string{"add", "remove", "hydrate"} {
		t.Run(command, func(t *testing.T) {
			s := testStore(t)
			if err := s.execute(command, "key", strings.NewReader("synthetic")); err == nil {
				t.Fatal("accepted uninitialized vault")
			}
		})
	}
}

func TestRemoveWithoutRuntime(t *testing.T) {
	s := testStore(t)
	execute(t, s, "init", "", nil)
	execute(t, s, "add", "app/key", []byte("synthetic"))
	if err := os.Remove(s.runDir); err != nil {
		t.Fatal(err)
	}
	execute(t, s, "remove", "app/key", nil)
	assertMissing(t, s.runDir)
	assertMissing(t, filepath.Join(s.vaultDir, "secrets", "app"))
}

func TestInvalidIdentityNotOverwritten(t *testing.T) {
	s := testStore(t)
	execute(t, s, "init", "", nil)
	path := filepath.Join(s.vaultDir, "identity.txt")
	if err := os.WriteFile(path, []byte("invalid identity\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"init", "add", "hydrate"} {
		err := s.execute(cmd, "key", strings.NewReader("synthetic"))
		if err == nil {
			t.Fatalf("%s accepted invalid identity", cmd)
		}
		if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), cmd+" in vault") {
			t.Fatalf("identity error lacks command and file context: %v", err)
		}
	}
	if string(readFile(t, path)) != "invalid identity\n" {
		t.Fatal("invalid identity was overwritten")
	}
}

func TestSymlinksRejected(t *testing.T) {
	for _, target := range []string{"identity", "blob", "blob-parent", "runtime-file", "runtime-parent", "vault", "runtime", "lock"} {
		t.Run(target, func(t *testing.T) {
			s := testStore(t)
			execute(t, s, "init", "", nil)
			execute(t, s, "add", "app/key", []byte("synthetic"))
			outside := t.TempDir()
			outsideFile := filepath.Join(outside, "key")
			if err := os.WriteFile(outsideFile, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			link := ""
			linkTarget := outsideFile
			command, name := "hydrate", ""
			switch target {
			case "identity":
				link = filepath.Join(s.vaultDir, "identity.txt")
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
			case "blob":
				link = filepath.Join(s.vaultDir, "secrets", "linked.age")
			case "blob-parent":
				link, linkTarget = filepath.Join(s.vaultDir, "secrets", "linked"), outside
				command, name = "add", "linked/key"
			case "runtime-file":
				if err := os.Mkdir(filepath.Join(s.runDir, "app"), 0700); err != nil {
					t.Fatal(err)
				}
				link = filepath.Join(s.runDir, "app", "key")
			case "runtime-parent":
				link, linkTarget = filepath.Join(s.runDir, "app"), outside
			case "vault":
				s.vaultDir = filepath.Join(filepath.Dir(s.vaultDir), "linked")
				link, linkTarget = s.vaultDir, outside
				command = "init"
			case "runtime":
				s.runDir = filepath.Join(filepath.Dir(s.runDir), "linked")
				link, linkTarget = s.runDir, outside
			case "lock":
				link = filepath.Join(s.vaultDir, ".lock")
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(linkTarget, link); err != nil {
				t.Fatal(err)
			}
			if err := s.execute(command, name, strings.NewReader("synthetic")); err == nil {
				t.Fatal("accepted symlink")
			}
			if string(readFile(t, outsideFile)) != "untouched" {
				t.Fatal("modified symlink target")
			}
		})
	}
}

func TestPrivateDirRejectsUntrustedPathsBeforeSecuring(t *testing.T) {
	t.Run("writable target", func(t *testing.T) {
		base := privateTempDir(t)
		target := filepath.Join(base, "vault")
		if err := os.Mkdir(target, 0777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0777); err != nil {
			t.Fatal(err)
		}
		if root, err := privateDir(target); err == nil {
			root.Close()
			t.Fatal("accepted a writable target directory")
		}
		assertMode(t, target, 0777)
	})

	t.Run("writable ancestor", func(t *testing.T) {
		base := privateTempDir(t)
		ancestor := filepath.Join(base, "unsafe")
		if err := os.Mkdir(ancestor, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ancestor, 0777); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(ancestor, "vault")
		if root, err := privateDir(target); err == nil {
			root.Close()
			t.Fatal("accepted a writable ancestor")
		}
		assertMissing(t, target)
		assertMode(t, ancestor, 0777)
	})

	t.Run("writable vault content", func(t *testing.T) {
		base := privateTempDir(t)
		vault := filepath.Join(base, "vault")
		if err := os.Mkdir(vault, 0700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(vault, "identity.txt")
		if err := os.WriteFile(file, []byte("synthetic"), 0666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, 0666); err != nil {
			t.Fatal(err)
		}
		if root, err := privateDir(vault); err == nil {
			root.Close()
			t.Fatal("accepted writable vault content")
		}
		assertMode(t, vault, 0700)
		assertMode(t, file, 0666)
	})

	t.Run("foreign-owned content", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("changing ownership requires root")
		}
		base := privateTempDir(t)
		vault := filepath.Join(base, "vault")
		if err := os.Mkdir(vault, 0700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(vault, "identity.txt")
		if err := os.WriteFile(file, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(file, 1, -1); err != nil {
			t.Fatal(err)
		}
		if root, err := privateDir(vault); err == nil {
			root.Close()
			t.Fatal("accepted foreign-owned vault content")
		}
		assertMode(t, vault, 0700)
	})

	t.Run("foreign-owned ancestor", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("changing ownership requires root")
		}
		base := privateTempDir(t)
		ancestor := filepath.Join(base, "ancestor")
		if err := os.Mkdir(ancestor, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(ancestor, 1, -1); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(ancestor, "vault")
		if root, err := privateDir(target); err == nil {
			root.Close()
			t.Fatal("accepted a foreign-owned path component")
		}
		assertMissing(t, target)
	})
}

func TestLockTimeoutAndRelease(t *testing.T) {
	vault, err := privateDir(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Close()
	first, err := acquireLock(vault, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireLock(vault, 20*time.Millisecond); err == nil {
		second.Close()
		t.Fatal("concurrent acquisition succeeded")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireLock(vault, time.Second)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRootRequired(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root behavior requires an unprivileged test process")
	}
	if err := Run([]string{"init"}, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("root requirement not enforced: %v", err)
	}
}

func TestAgeCLICompatibility(t *testing.T) {
	cli := os.Getenv("SECSTORE_TEST_AGE")
	if cli == "" {
		t.Skip("set SECSTORE_TEST_AGE to an age CLI binary for legacy interoperability tests")
	}
	s := testStore(t)
	execute(t, s, "init", "", nil)
	keyFile := filepath.Join(s.vaultDir, "identity.txt")
	identities, err := age.ParseIdentities(bytes.NewReader(readFile(t, keyFile)))
	if err != nil {
		t.Fatal(err)
	}
	identity, ok := identities[0].(*age.X25519Identity)
	if !ok {
		t.Fatal("generated identity is not X25519")
	}
	secret := []byte("synthetic legacy age secret\x00\n")
	var encrypted, diagnostics bytes.Buffer
	command := exec.Command(cli, "-r", identity.Recipient().String())
	command.Stdin = bytes.NewReader(secret)
	command.Stdout, command.Stderr = &encrypted, &diagnostics
	if err := command.Run(); err != nil {
		t.Fatalf("legacy age encryption: %v: %s", err, diagnostics.String())
	}
	if err := os.WriteFile(filepath.Join(s.vaultDir, "secrets", "legacy.age"), encrypted.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	execute(t, s, "hydrate", "", nil)
	if !bytes.Equal(readFile(t, filepath.Join(s.runDir, "legacy")), secret) {
		t.Fatal("could not hydrate legacy CLI ciphertext")
	}

	execute(t, s, "add", "new", secret)
	var decrypted bytes.Buffer
	diagnostics.Reset()
	command = exec.Command(cli, "-d", "-i", keyFile, filepath.Join(s.vaultDir, "secrets", "new.age"))
	command.Stdout, command.Stderr = &decrypted, &diagnostics
	if err := command.Run(); err != nil {
		t.Fatalf("legacy age decryption: %v: %s", err, diagnostics.String())
	}
	if !bytes.Equal(decrypted.Bytes(), secret) {
		t.Fatal("legacy CLI could not decrypt Go ciphertext")
	}
}
