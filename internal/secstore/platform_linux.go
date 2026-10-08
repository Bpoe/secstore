package secstore

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	return nil
}

func secureFile(f *os.File, mode os.FileMode) error {
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 {
		gid = 0
	}
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	return f.Chmod(mode)
}

func acquireLock(vault *os.Root, timeout time.Duration) (*os.File, error) {
	if err := regularFile(vault, ".lock"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	f, err := vault.OpenFile(".lock", os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := secureFile(f, 0600); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	deadline := time.Now().Add(timeout)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return nil, errors.Join(fmt.Errorf("lock vault: %w", err), f.Close())
		}
		if !time.Now().Before(deadline) {
			return nil, errors.Join(fmt.Errorf("another secstore operation is in progress (lock: %s)",
				filepath.Join(vault.Name(), ".lock")), f.Close())
		}
		time.Sleep(min(50*time.Millisecond, time.Until(deadline)))
	}
}

type mountInfo struct {
	path    string
	fsType  string
	options []string
}

var mountUnescaper = strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)

func parseMounts(r io.Reader) ([]mountInfo, error) {
	var mounts []mountInfo
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		before, after, ok := strings.Cut(scanner.Text(), " - ")
		fields, tail := strings.Fields(before), strings.Fields(after)
		if !ok || len(fields) < 6 || len(tail) < 3 {
			return nil, errors.New("malformed /proc/self/mountinfo")
		}
		mounts = append(mounts, mountInfo{
			path:    mountUnescaper.Replace(fields[4]),
			fsType:  tail[0],
			options: strings.Split(fields[5]+","+tail[2], ","),
		})
	}
	return mounts, scanner.Err()
}

func readMounts() (_ []mountInfo, err error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return parseMounts(f)
}

func runtimeMount(mounts []mountInfo, path string) (*mountInfo, error) {
	var found *mountInfo
	for i := range mounts {
		mount := &mounts[i]
		if mount.path == path {
			if found != nil {
				return nil, fmt.Errorf("stacked mounts at %s are not supported", path)
			}
			found = mount
		} else if within(path, mount.path) {
			return nil, fmt.Errorf("nested mount at %s is not allowed in runtime directory", mount.path)
		}
	}
	return found, nil
}

func validateRuntimeMount(mount *mountInfo, path string) error {
	if mount == nil || mount.fsType != "tmpfs" {
		return fmt.Errorf("%s is not a tmpfs mountpoint", path)
	}
	if !slices.Contains(mount.options, "noswap") {
		return fmt.Errorf("%s is tmpfs but is not mounted with noswap", path)
	}
	if !slices.Contains(mount.options, "rw") || slices.Contains(mount.options, "ro") {
		return fmt.Errorf("%s is not writable", path)
	}
	return nil
}

func ensureRuntime(c config, log io.Writer) (err error) {
	root, err := privateDir(c.runDir)
	if err != nil {
		return fmt.Errorf("open runtime directory: %w", err)
	}
	if err := root.Close(); err != nil {
		return err
	}
	mounts, err := readMounts()
	if err != nil {
		return err
	}
	mount, err := runtimeMount(mounts, c.runDir)
	if err != nil {
		return err
	}
	if mount == nil {
		fmt.Fprintf(log, "secstore: mounting tmpfs at %s\n", c.runDir)
		flags := uintptr(syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
		if err := syscall.Mount("tmpfs", c.runDir, "tmpfs", flags, "mode=0700,size="+c.runSize+",noswap"); err != nil {
			return fmt.Errorf("failed to mount noswap tmpfs at %s: %w", c.runDir, err)
		}
		mounts, err = readMounts()
		if err != nil {
			return err
		}
		mount, err = runtimeMount(mounts, c.runDir)
		if err != nil {
			return err
		}
	}
	if err := validateRuntimeMount(mount, c.runDir); err != nil {
		return err
	}
	root, err = privateDir(c.runDir)
	if err != nil {
		return err
	}
	return root.Close()
}
