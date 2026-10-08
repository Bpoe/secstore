//go:build !linux

package secstore

import (
	"errors"
	"io"
	"os"
	"time"
)

var errLinuxOnly = errors.New("secstore requires Linux")

func requireRoot() error { return errLinuxOnly }

func secureFile(f *os.File, mode os.FileMode) error { return f.Chmod(mode) }

func acquireLock(*os.Root, time.Duration) (*os.File, error) { return nil, errLinuxOnly }

func ensureRuntime(config, io.Writer) error { return errLinuxOnly }
