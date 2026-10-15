package secstore

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// Only an empty vault (possibly with a lock and an empty secrets directory)
// can be initialized without risking an identity replacement for orphaned data.
func dscUninitialized(vault *os.Root) (bool, error) {
	entries, err := fs.ReadDir(vault.FS(), ".")
	if err != nil {
		return false, dscFailure("cannot inspect vault structure", err)
	}
	for _, entry := range entries {
		if entry.Name() == "identity.txt" {
			return false, nil
		}
	}
	for _, entry := range entries {
		switch entry.Name() {
		case ".lock":
		case "secrets":
			children, err := fs.ReadDir(vault.FS(), "secrets")
			if err != nil {
				return false, dscFailure("cannot inspect secret directory", err)
			}
			if len(children) != 0 {
				return false, errors.New("vault contains secrets but has no identity")
			}
		default:
			return false, errors.New("vault contains data but has no identity")
		}
	}
	return true, nil
}

func inspectDSCSecret(vault *os.Root, identity age.Identity, name string, desired *string, authenticate bool) (exists, matches bool, err error) {
	secrets, err := vault.OpenRoot("secrets")
	if err != nil {
		return false, false, dscFailure("cannot open structural secret directory", err)
	}
	defer func() { err = errors.Join(err, dscFailure("cannot close secret directory", secrets.Close())) }()
	blob, err := openRegular(secrets, filepath.FromSlash(name)+".age")
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, dscFailure("cannot open encrypted secret", err)
	}
	defer func() { err = errors.Join(err, dscFailure("cannot close encrypted secret", blob.Close())) }()
	if !authenticate {
		return true, false, nil
	}
	plaintext, err := age.Decrypt(blob, identity)
	if err != nil {
		return false, false, dscFailure("cannot authenticate encrypted secret", err)
	}
	if desired == nil {
		_, err = io.Copy(io.Discard, plaintext)
		return true, false, dscFailure("cannot authenticate encrypted secret", err)
	}
	actualHash := sha256.New()
	if _, err := io.Copy(actualHash, plaintext); err != nil {
		return false, false, dscFailure("cannot authenticate encrypted secret", err)
	}
	desiredHash := sha256.New()
	if _, err := io.Copy(desiredHash, strings.NewReader(*desired)); err != nil {
		return false, false, dscFailure("cannot compare desired value", err)
	}
	return true, subtle.ConstantTimeCompare(actualHash.Sum(nil), desiredHash.Sum(nil)) == 1, nil
}

func dscDifferences(request dscRequest, exists, matches bool) []string {
	diff := []string{}
	if request.exist != exists {
		diff = append(diff, "_exist")
	}
	if request.exist && (!exists || !matches) {
		diff = append(diff, "value")
	}
	return diff
}

func (s *store) reconcileDSC(operation string, request dscRequest) (state dscState, diff []string, err error) {
	state.Name = request.name
	diff = []string{}
	defer func() {
		if operation == "test" && err == nil {
			compliant := len(diff) == 0
			state.InDesiredState = &compliant
		}
	}()
	absent := func() {
		if operation == "test" {
			diff = dscDifferences(request, false, false)
		}
	}
	create := operation == "set" && request.exist
	vault, err := openPath(s.vaultDir, false)
	if err != nil {
		return state, diff, dscFailure("cannot securely open vault", err)
	}
	if vault == nil {
		if !create {
			absent()
			return state, diff, nil
		}
		vault, err = openPath(s.vaultDir, true)
		if err != nil {
			return state, diff, dscFailure("cannot create vault", err)
		}
	}
	defer func() { err = errors.Join(err, dscFailure("cannot close vault", vault.Close())) }()
	lock, err := acquireExistingLock(vault, 30*time.Second)
	if errors.Is(err, fs.ErrNotExist) {
		if err := validateTree(vault); err != nil {
			return state, diff, dscFailure("unsafe vault contents", err)
		}
		uninitialized, inspectErr := dscUninitialized(vault)
		if inspectErr != nil {
			return state, diff, inspectErr
		}
		if !uninitialized {
			return state, diff, errors.New("initialized vault is missing its lock")
		}
		if !create {
			absent()
			return state, diff, nil
		}
		lock, err = acquireLock(vault, 30*time.Second)
	}
	if err != nil {
		return state, diff, dscFailure("cannot acquire vault lock", err)
	}
	defer func() { err = errors.Join(err, dscFailure("cannot release vault lock", lock.Close())) }()
	if err := validateTree(vault); err != nil {
		return state, diff, dscFailure("unsafe vault contents", err)
	}
	uninitialized, err := dscUninitialized(vault)
	if err != nil {
		return state, diff, err
	}
	prepareWrite := func() error {
		if err := securePath(vault, ".", 0700); err != nil {
			return dscFailure("cannot secure vault", err)
		}
		return dscFailure("cannot secure vault lock", secureFile(lock, 0600))
	}
	if uninitialized {
		if !create {
			absent()
			return state, diff, nil
		}
		if err := prepareWrite(); err != nil {
			return state, diff, err
		}
		if err := s.init(vault); err != nil {
			return state, diff, dscFailure("cannot initialize store or prepare runtime tmpfs", err)
		}
	}
	if err := s.requireInitialized(vault); err != nil {
		return state, diff, dscFailure("invalid initialized vault structure", err)
	}
	identity, err := readIdentity(vault)
	if err != nil {
		return state, diff, dscFailure("invalid or unreadable age identity", err)
	}
	var desired *string
	if operation != "get" && request.exist {
		desired = request.value
	}
	exists, matches, err := inspectDSCSecret(vault, identity, request.name, desired, operation != "set" || request.exist)
	if err != nil {
		return state, diff, err
	}
	state.Exist = exists
	if operation == "get" {
		return state, diff, nil
	}
	diff = dscDifferences(request, exists, matches)
	if operation == "test" || (request.exist && len(diff) == 0) {
		return state, diff, nil
	}
	if err := prepareWrite(); err != nil {
		return state, diff, err
	}
	if request.exist {
		err = dscFailure("cannot encrypt and store secret", s.add(vault, request.name, strings.NewReader(*request.value)))
	} else {
		err = dscFailure("cannot remove secret", s.remove(vault, request.name))
	}
	if err != nil {
		return state, diff, err
	}
	state.Exist = request.exist
	return state, diff, nil
}
