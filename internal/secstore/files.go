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
)

// Configuration paths must have trusted ancestors. Refuse symlinks even when
// they stay within a root, so secret names cannot alias one another.
func privateDir(path string) (*os.Root, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if err := securePath(root, ".", 0700); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return root, nil
}

func checkPath(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err == nil && !info.IsDir() {
			return fmt.Errorf("not a real directory (symlinks are not allowed): %s", path)
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
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
