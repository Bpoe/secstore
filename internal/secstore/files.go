package secstore

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Configuration paths must have trusted ancestors. Refuse symlinks even when
// they stay within a root, so secret names cannot alias one another.
func privateDir(path string) (*os.Root, error) {
	root, err := openPath(path, true)
	if err != nil {
		return nil, err
	}
	if err := validateTree(root); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	if err := securePath(root, ".", 0700); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return root, nil
}

func checkPath(path string) error {
	root, err := openPath(path, false)
	if err != nil || root == nil {
		return err
	}
	return root.Close()
}

func trustedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || int(stat.Uid) == os.Geteuid())
}

func validateDirectory(info os.FileInfo, ancestor bool) error {
	if !info.IsDir() {
		return errors.New("not a real directory (symlinks are not allowed)")
	}
	if !trustedOwner(info) {
		return errors.New("directory is not owned by root or the invoking user")
	}
	if info.Mode().Perm()&0022 != 0 && !(ancestor && info.Mode()&os.ModeSticky != 0) {
		return errors.New("directory is writable by other users")
	}
	return nil
}

func openPath(path string, create bool) (*os.Root, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	path = filepath.Clean(path)
	if path == string(filepath.Separator) {
		return nil, errors.New("filesystem root cannot be used as a private directory")
	}
	current, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		info, err := current.Lstat(part)
		if errors.Is(err, fs.ErrNotExist) {
			if !create {
				return nil, current.Close()
			}
			if err := current.Mkdir(part, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, errors.Join(err, current.Close())
			}
			info, err = current.Lstat(part)
		}
		if err != nil {
			return nil, errors.Join(err, current.Close())
		}
		ancestor := i < len(parts)-1
		if err := validateDirectory(info, ancestor); err != nil {
			return nil, errors.Join(fmt.Errorf("%s: %w", filepath.Join(current.Name(), part), err), current.Close())
		}
		next, err := current.OpenRoot(part)
		if err != nil {
			return nil, errors.Join(err, current.Close())
		}
		openedInfo, err := next.Stat(".")
		if err == nil && !os.SameFile(info, openedInfo) {
			err = errors.New("directory changed during path validation")
		}
		if err == nil {
			err = validateDirectory(openedInfo, ancestor)
		}
		if err != nil {
			return nil, errors.Join(err, next.Close(), current.Close())
		}
		if err := current.Close(); err != nil {
			return nil, errors.Join(err, next.Close())
		}
		current = next
	}
	return current, nil
}

func validateTree(root *os.Root) error {
	return fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !trustedOwner(info) {
			return fmt.Errorf("%s is not owned by root or the invoking user", path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in private directory: %s", path)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("not a regular file or directory: %s", path)
		}
		if info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("%s is writable by other users", path)
		}
		return nil
	})
}

func securePath(root *os.Root, path string, mode os.FileMode) error {
	f, err := root.Open(path)
	if err != nil {
		return err
	}
	err = secureFile(f, mode)
	return errors.Join(err, f.Close())
}

func ensureDirs(root *os.Root, path string) error {
	if path == "." {
		return nil
	}
	current := ""
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err := root.Mkdir(current, 0700); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if !info.IsDir() {
			return fmt.Errorf("not a real directory: %s", current)
		}
		if err := securePath(root, current, 0700); err != nil {
			return err
		}
	}
	return nil
}

func regularFile(root *os.Root, path string) error {
	for parent := filepath.Dir(path); parent != "."; parent = filepath.Dir(parent) {
		info, err := root.Lstat(parent)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("not a real directory: %s", parent)
		}
	}
	info, err := root.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file (symlinks are not allowed): %s", path)
	}
	return nil
}

func openRegular(root *os.Root, path string) (*os.File, error) {
	if err := regularFile(root, path); err != nil {
		return nil, err
	}
	return root.Open(path)
}

func atomicWrite(root *os.Root, path string, mode os.FileMode, write func(io.Writer) error) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("write %q: %w", filepath.Join(root.Name(), path), err)
		}
	}()
	if err := ensureDirs(root, filepath.Dir(path)); err != nil {
		return err
	}
	if err := regularFile(root, path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), ".secstore-"+rand.Text())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	closed, published := false, false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		if !published {
			err = errors.Join(err, root.Remove(tmp))
		}
	}()
	if err = write(f); err != nil {
		return err
	}
	if err = secureFile(f, mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if err = root.Rename(tmp, path); err != nil {
		return err
	}
	published = true
	return nil
}

func removeFile(root *os.Root, path string) error {
	if err := regularFile(root, path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return root.Remove(path)
}

func pruneParents(root *os.Root, path string) error {
	for path != "." {
		entries, err := fs.ReadDir(root.FS(), filepath.ToSlash(path))
		if errors.Is(err, fs.ErrNotExist) {
			path = filepath.Dir(path)
			continue
		}
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return nil
		}
		if err := root.Remove(path); err != nil {
			return err
		}
		path = filepath.Dir(path)
	}
	return nil
}
