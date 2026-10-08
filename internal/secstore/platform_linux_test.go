package secstore

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestParseMounts(t *testing.T) {
	input := "36 25 0:32 / /run/secrets\\040store rw,nosuid,nodev,noexec shared:1 - tmpfs tmpfs rw,size=16384k,noswap\n"
	mounts, err := parseMounts(strings.NewReader(input))
	if err != nil || len(mounts) != 1 {
		t.Fatalf("parse: %v %v", mounts, err)
	}
	if mounts[0].path != "/run/secrets store" || mounts[0].fsType != "tmpfs" || !slices.Contains(mounts[0].options, "noswap") {
		t.Fatalf("incorrect mount: %+v", mounts[0])
	}
	if err := validateRuntimeMount(&mounts[0], mounts[0].path); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"malformed\n", "1 2 3 / /run rw - tmpfs\n", "1 2 3 - tmpfs tmpfs rw\n"} {
		if _, err := parseMounts(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted malformed mountinfo %q", input)
		}
	}
}

func TestRuntimeMountPolicy(t *testing.T) {
	for _, mount := range []*mountInfo{
		nil,
		{fsType: "ext4", options: []string{"rw", "noswap"}},
		{fsType: "tmpfs", options: []string{"rw"}},
		{fsType: "tmpfs", options: []string{"ro", "noswap"}},
		{fsType: "tmpfs", options: []string{"rw", "ro", "noswap"}},
	} {
		if err := validateRuntimeMount(mount, "/run/secrets"); err == nil {
			t.Fatalf("accepted unsafe mount %+v", mount)
		}
	}
	for _, mounts := range [][]mountInfo{
		{{path: "/run/secrets/nested"}},
		{{path: "/run/secrets"}, {path: "/run/secrets"}},
	} {
		if _, err := runtimeMount(mounts, "/run/secrets"); err == nil {
			t.Fatalf("accepted unsafe mounts %+v", mounts)
		}
	}
	mount, err := runtimeMount([]mountInfo{{path: "/run"}, {path: "/run/secrets-other"}}, "/run/secrets")
	if err != nil || mount != nil {
		t.Fatalf("ancestor/sibling is not the runtime mount: %v %v", mount, err)
	}
}

func TestRuntimeIntegration(t *testing.T) {
	if os.Getenv("SECSTORE_MOUNT_TEST") != "1" {
		t.Skip("requires SECSTORE_MOUNT_TEST=1 in a private mount namespace")
	}
	if err := requireRoot(); err != nil {
		t.Fatal(err)
	}
	t.Run("noswap-lifecycle", func(t *testing.T) {
		s := testStore(t)
		s.prepareRuntime = ensureRuntime
		t.Cleanup(func() {
			if err := syscall.Unmount(s.runDir, 0); err != nil {
				t.Errorf("unmount runtime: %v", err)
			}
		})
		execute(t, s, "init", "", nil)
		mounts, err := readMounts()
		if err != nil {
			t.Fatal(err)
		}
		mount, err := runtimeMount(mounts, s.runDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateRuntimeMount(mount, s.runDir); err != nil {
			t.Fatal(err)
		}
		for _, option := range []string{"nosuid", "nodev", "noexec", "noswap"} {
			if !slices.Contains(mount.options, option) {
				t.Fatalf("missing mount option %s", option)
			}
		}
		execute(t, s, "add", "app/key", []byte("synthetic mount test"))
		execute(t, s, "hydrate", "", nil)
		if string(readFile(t, filepath.Join(s.runDir, "app", "key"))) != "synthetic mount test" {
			t.Fatal("real tmpfs hydration failed")
		}
		execute(t, s, "hydrate", "", nil)
		execute(t, s, "remove", "app/key", nil)
	})
	t.Run("swappable-mount-rejected", func(t *testing.T) {
		s := testStore(t)
		if err := os.MkdirAll(s.runDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount("tmpfs", s.runDir, "tmpfs", 0, "size=1M"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := syscall.Unmount(s.runDir, 0); err != nil {
				t.Errorf("unmount: %v", err)
			}
		})
		if err := ensureRuntime(s.config, io.Discard); err == nil || !strings.Contains(err.Error(), "noswap") {
			t.Fatalf("accepted swappable tmpfs: %v", err)
		}
	})
	t.Run("nested-mount-rejected", func(t *testing.T) {
		s := testStore(t)
		s.prepareRuntime = ensureRuntime
		execute(t, s, "init", "", nil)
		t.Cleanup(func() {
			if err := syscall.Unmount(s.runDir, 0); err != nil {
				t.Errorf("unmount runtime: %v", err)
			}
		})
		nested := filepath.Join(s.runDir, "nested")
		if err := os.Mkdir(nested, 0700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount("tmpfs", nested, "tmpfs", 0, "size=1M"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := syscall.Unmount(nested, 0); err != nil {
				t.Errorf("unmount nested: %v", err)
			}
		})
		if err := s.execute("hydrate", "", nil); err == nil || !strings.Contains(err.Error(), "nested mount") {
			t.Fatalf("accepted nested mount: %v", err)
		}
	})
	t.Run("full-tmpfs-preserves-live-files", func(t *testing.T) {
		s := testStore(t)
		s.runSize = "1M"
		s.prepareRuntime = ensureRuntime
		execute(t, s, "init", "", nil)
		t.Cleanup(func() {
			if err := syscall.Unmount(s.runDir, 0); err != nil {
				t.Errorf("unmount runtime: %v", err)
			}
		})
		execute(t, s, "add", "key", []byte("old"))
		execute(t, s, "hydrate", "", nil)
		execute(t, s, "add", "key", bytes.Repeat([]byte("x"), 2*1024*1024))
		if err := s.execute("hydrate", "", nil); !errors.Is(err, syscall.ENOSPC) {
			t.Fatalf("expected full tmpfs error: %v", err)
		}
		if string(readFile(t, filepath.Join(s.runDir, "key"))) != "old" {
			t.Fatal("full tmpfs damaged the live secret")
		}
		entries, err := os.ReadDir(s.runDir)
		if err != nil || len(entries) != 1 || entries[0].Name() != "key" {
			t.Fatalf("full tmpfs left staged plaintext: %v %v", entries, err)
		}
	})
	t.Run("command-entrypoint", func(t *testing.T) {
		s := testStore(t)
		t.Setenv("SECSTORE_VAULT_DIR", s.vaultDir)
		t.Setenv("SECSTORE_RUN_DIR", s.runDir)
		t.Setenv("SECSTORE_RUN_SIZE", s.runSize)
		t.Setenv("SECSTORE_FILE_MODE", "0444")
		if err := Run([]string{"init"}, nil, io.Discard); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := syscall.Unmount(s.runDir, 0); err != nil {
				t.Errorf("unmount runtime: %v", err)
			}
		})
		if err := Run([]string{"add", "--name", "cli/key"}, strings.NewReader("synthetic"), io.Discard); err != nil {
			t.Fatal(err)
		}
		if err := Run([]string{"hydrate"}, nil, io.Discard); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(s.runDir, "cli", "key")
		assertMode(t, path, 0444)
		if string(readFile(t, path)) != "synthetic" {
			t.Fatal("CLI hydration failed")
		}
		if err := Run([]string{"remove", "--name", "cli/key"}, nil, io.Discard); err != nil {
			t.Fatal(err)
		}
		assertMissing(t, path)
	})
}
