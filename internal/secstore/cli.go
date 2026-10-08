package secstore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const usage = `Usage:
  secstore init
  secstore add --name <name>        # reads plaintext from stdin
  secstore remove --name <name>
  secstore hydrate

Environment overrides:
  SECSTORE_VAULT_DIR   default: /var/lib/secstore
  SECSTORE_RUN_DIR     default: /run/secrets-store
  SECSTORE_RUN_SIZE    default: 16M
  SECSTORE_FILE_MODE   default: 0400
`

type config struct {
	vaultDir string
	runDir   string
	runSize  string
	fileMode os.FileMode
}

var (
	namePartPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	sizePattern     = regexp.MustCompile(`^[1-9][0-9]*([kKmMgGtTpP]|%)?$`)
	modePattern     = regexp.MustCompile(`^0?[0-7]{3}$`)
)

func validateName(name string) error {
	if name == "" {
		return errors.New("secret name is required")
	}
	for _, part := range strings.Split(name, "/") {
		if !namePartPattern.MatchString(part) {
			return fmt.Errorf("invalid secret name component: %q", part)
		}
	}
	return nil
}

func loadConfig(getenv func(string) string) (config, error) {
	value := func(key, fallback string) string {
		if s := getenv(key); s != "" {
			return s
		}
		return fallback
	}
	c := config{
		vaultDir: value("SECSTORE_VAULT_DIR", "/var/lib/secstore"),
		runDir:   value("SECSTORE_RUN_DIR", "/run/secrets-store"),
		runSize:  value("SECSTORE_RUN_SIZE", "16M"),
	}
	var err error
	if c.vaultDir, err = filepath.Abs(c.vaultDir); err != nil {
		return c, fmt.Errorf("resolve vault directory: %w", err)
	}
	if c.runDir, err = filepath.Abs(c.runDir); err != nil {
		return c, fmt.Errorf("resolve runtime directory: %w", err)
	}
	if within(c.vaultDir, c.runDir) || within(c.runDir, c.vaultDir) {
		return c, errors.New("vault and runtime directories must be separate, non-overlapping trees")
	}
	if !sizePattern.MatchString(c.runSize) {
		return c, errors.New("SECSTORE_RUN_SIZE must be a positive size in bytes, with an optional K/M/G/T/P or % suffix")
	}
	mode := value("SECSTORE_FILE_MODE", "0400")
	if !modePattern.MatchString(mode) {
		return c, errors.New("SECSTORE_FILE_MODE must be an octal permission mode between 0000 and 0777")
	}
	n, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return c, fmt.Errorf("parse SECSTORE_FILE_MODE: %w", err)
	}
	c.fileMode = os.FileMode(n)
	return c, nil
}

func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func parseArgs(args []string) (command, name string, help bool, err error) {
	if len(args) == 0 {
		return "", "", true, nil
	}
	command = args[0]
	switch command {
	case "-h", "--help", "help":
		return "", "", true, nil
	case "init", "hydrate", "add", "remove":
	default:
		return "", "", false, fmt.Errorf("unknown command: %s", command)
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			return command, "", true, nil
		case "--name":
			if command != "add" && command != "remove" {
				return "", "", false, fmt.Errorf("unknown argument for %s: %s", command, args[i])
			}
			if i+1 == len(args) {
				return "", "", false, errors.New("--name requires a value")
			}
			i++
			name = args[i]
		default:
			return "", "", false, fmt.Errorf("unknown argument for %s: %s", command, args[i])
		}
	}
	if command == "add" || command == "remove" {
		err = validateName(name)
	}
	return
}

// Run executes a command using the supplied streams and process environment.
func Run(args []string, stdin io.Reader, stderr io.Writer) error {
	command, name, help, err := parseArgs(args)
	if err != nil {
		return err
	}
	if help {
		_, err = io.WriteString(stderr, usage)
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	c, err := loadConfig(os.Getenv)
	if err != nil {
		return err
	}
	s := store{config: c, log: stderr, prepareRuntime: ensureRuntime}
	return s.execute(command, name, stdin)
}
