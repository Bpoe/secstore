package secstore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
)

type store struct {
	config
	log            io.Writer
	prepareRuntime func(config, io.Writer) error
}

func (s *store) info(format string, args ...any) {
	fmt.Fprintf(s.log, "secstore: "+format+"\n", args...)
}

func (s *store) execute(command, name string, stdin io.Reader) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%s in vault %q: %w", command, s.vaultDir, err)
		}
	}()
	vault, err := privateDir(s.vaultDir)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	defer func() { err = errors.Join(err, vault.Close()) }()
	lock, err := acquireLock(vault, 30*time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if command == "init" {
		return s.init(vault)
	}
	if err := s.requireInitialized(vault); err != nil {
		return err
	}
	switch command {
	case "add":
		return s.add(vault, name, stdin)
	case "remove":
		return s.remove(vault, name)
	case "hydrate":
		return s.hydrate(vault)
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

func (s *store) requireInitialized(vault *os.Root) error {
	info, err := vault.Lstat("secrets")
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("not initialized: run 'secstore init'")
	}
	if err != nil {
		return fmt.Errorf("inspect secret directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("secrets must be a real directory")
	}
	if err := regularFile(vault, "identity.txt"); err != nil {
		return fmt.Errorf("missing or invalid identity: run 'secstore init': %w", err)
	}
	return nil
}

func readIdentity(vault *os.Root) (_ *age.X25519Identity, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("read identity %q: %w", filepath.Join(vault.Name(), "identity.txt"), err)
		}
	}()
	f, err := openRegular(vault, "identity.txt")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse age identity: %w", err)
	}
	if len(identities) != 1 {
		return nil, errors.New("expected exactly one age X25519 identity")
	}
	identity, ok := identities[0].(*age.X25519Identity)
	if !ok {
		return nil, errors.New("expected an age X25519 identity")
	}
	return identity, nil
}

func (s *store) init(vault *os.Root) error {
	if err := ensureDirs(vault, "secrets"); err != nil {
		return err
	}
	if err := regularFile(vault, "identity.txt"); errors.Is(err, fs.ErrNotExist) {
		s.info("creating local identity at %s", filepath.Join(s.vaultDir, "identity.txt"))
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return fmt.Errorf("generate identity: %w", err)
		}
		if err := atomicWrite(vault, "identity.txt", 0600, func(w io.Writer) error {
			_, err := fmt.Fprintf(w, "# created: %s\n# public key: %s\n%s\n",
				time.Now().Format(time.RFC3339), identity.Recipient(), identity)
			return err
		}); err != nil {
			return fmt.Errorf("write identity: %w", err)
		}
	} else if err != nil {
		return err
	} else {
		s.info("identity already exists at %s", filepath.Join(s.vaultDir, "identity.txt"))
		if err := securePath(vault, "identity.txt", 0600); err != nil {
			return err
		}
		if _, err := readIdentity(vault); err != nil {
			return err
		}
	}
	if err := s.prepareRuntime(s.config, s.log); err != nil {
		return err
	}
	s.info("initialized")
	return nil
}

func (s *store) add(vault *os.Root, name string, stdin io.Reader) error {
	if err := validateName(name); err != nil {
		return err
	}
	identity, err := readIdentity(vault)
	if err != nil {
		return err
	}
	path := filepath.Join("secrets", filepath.FromSlash(name)+".age")
	if err := atomicWrite(vault, path, 0600, func(w io.Writer) error {
		encrypted, err := age.Encrypt(w, identity.Recipient())
		if err != nil {
			return err
		}
		if _, err := io.Copy(encrypted, stdin); err != nil {
			return fmt.Errorf("stream stdin into age encryption: %w", err)
		}
		return encrypted.Close()
	}); err != nil {
		return fmt.Errorf("encrypt %s: %w", name, err)
	}
	s.info("added %s", name)
	return nil
}

func (s *store) remove(vault *os.Root, name string) (err error) {
	if err := validateName(name); err != nil {
		return err
	}
	path := filepath.FromSlash(name)
	secrets, err := vault.OpenRoot("secrets")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, secrets.Close()) }()
	if err := removeFile(secrets, path+".age"); err != nil {
		return fmt.Errorf("remove encrypted secret %q: %w", name, err)
	}
	if err := pruneParents(secrets, filepath.Dir(path)); err != nil {
		return fmt.Errorf("prune encrypted secret directories for %q: %w", name, err)
	}
	if err := checkPath(s.runDir); err != nil {
		return err
	}
	runtime, err := os.OpenRoot(s.runDir)
	if errors.Is(err, fs.ErrNotExist) {
		s.info("removed %s", name)
		return nil
	}
	if err != nil {
		return fmt.Errorf("open runtime directory %q: %w", s.runDir, err)
	}
	defer func() { err = errors.Join(err, runtime.Close()) }()
	if err := removeFile(runtime, path); err != nil {
		return fmt.Errorf("remove runtime secret %q: %w", filepath.Join(s.runDir, path), err)
	}
	if err := pruneParents(runtime, filepath.Dir(path)); err != nil {
		return fmt.Errorf("prune runtime directories under %q: %w", s.runDir, err)
	}
	s.info("removed %s", name)
	return nil
}

func blobNames(vault *os.Root) ([]string, error) {
	var names []string
	err := fs.WalkDir(vault.FS(), "secrets", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in secret tree: %s", path)
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".age") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("not a regular secret blob: %s", path)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(path, "secrets/"), ".age")
		if err := validateName(name); err != nil {
			return err
		}
		names = append(names, name)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if wanted[parent] {
				return nil, fmt.Errorf("secret %q conflicts with parent secret %q", name, parent)
			}
		}
		wanted[name] = true
	}
	return names, nil
}

func decrypt(vault, runtime *os.Root, blob, dest string, mode os.FileMode, identity age.Identity) (err error) {
	f, err := openRegular(vault, blob)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return atomicWrite(runtime, dest, mode, func(w io.Writer) error {
		plaintext, err := age.Decrypt(f, identity)
		if err != nil {
			return err
		}
		// Authentication is only complete after the reader reaches EOF.
		_, err = io.Copy(w, plaintext)
		return err
	})
}

func (s *store) hydrate(vault *os.Root) (err error) {
	if err := s.prepareRuntime(s.config, s.log); err != nil {
		return err
	}
	runtime, err := os.OpenRoot(s.runDir)
	if err != nil {
		return fmt.Errorf("open runtime directory %q: %w", s.runDir, err)
	}
	defer func() { err = errors.Join(err, runtime.Close()) }()
	identity, err := readIdentity(vault)
	if err != nil {
		return err
	}
	names, err := blobNames(vault)
	if err != nil {
		return fmt.Errorf("scan encrypted secrets: %w", err)
	}
	stage := ".hydrate." + rand.Text()
	if err := runtime.Mkdir(stage, 0700); err != nil {
		return fmt.Errorf("create hydration staging directory in %q: %w", s.runDir, err)
	}
	defer func() {
		if cleanupErr := runtime.RemoveAll(stage); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove hydration staging directory: %w", cleanupErr))
		}
	}()
	for _, name := range names {
		path := filepath.FromSlash(name)
		if err := decrypt(vault, runtime, filepath.Join("secrets", path+".age"),
			filepath.Join(stage, path), s.fileMode, identity); err != nil {
			return fmt.Errorf("decrypt %s: %w", name, err)
		}
	}
	// Check all destinations before publishing any files. Replacements are
	// atomic per file, not a transaction across the entire secret set.
	for _, name := range names {
		path := filepath.FromSlash(name)
		if err := ensureDirs(runtime, filepath.Dir(path)); err != nil {
			return fmt.Errorf("prepare runtime secret %q: %w", filepath.Join(s.runDir, path), err)
		}
		if err := regularFile(runtime, path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("inspect runtime secret %q: %w", filepath.Join(s.runDir, path), err)
		}
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		path := filepath.FromSlash(name)
		if err := runtime.Rename(filepath.Join(stage, path), path); err != nil {
			return fmt.Errorf("publish runtime secret %q: %w", filepath.Join(s.runDir, path), err)
		}
		wanted[name] = true
	}
	if err := cleanRuntime(runtime, stage, wanted); err != nil {
		return fmt.Errorf("clean stale runtime files in %q: %w", s.runDir, err)
	}
	s.info("hydrated %d secret(s) to %s", len(names), s.runDir)
	return nil
}

func cleanRuntime(runtime *os.Root, stage string, wanted map[string]bool) error {
	var dirs []string
	err := fs.WalkDir(runtime.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == stage {
			return fs.SkipDir
		}
		if entry.IsDir() {
			if path != "." {
				dirs = append(dirs, path)
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected non-regular runtime file: %s", path)
		}
		if !wanted[path] {
			return runtime.Remove(filepath.FromSlash(path))
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := pruneParents(runtime, filepath.FromSlash(dirs[i])); err != nil {
			return err
		}
	}
	return nil
}
