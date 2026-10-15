package secstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"unicode/utf8"
)

const maxDSCInput = 1024 * 1024

type dscRequest struct {
	name  string
	value *string
	exist bool
}

type dscState struct {
	Name           string `json:"name"`
	Exist          bool   `json:"_exist"`
	InDesiredState *bool  `json:"_inDesiredState"`
}

// Keep the cause for error classification without displaying input, key, or
// ciphertext fragments that lower-level parsers can include in their errors.
type dscError struct {
	message string
	cause   error
}

func (e *dscError) Error() string {
	if errors.Is(e.cause, fs.ErrPermission) {
		return e.message + ": permission denied"
	}
	return e.message
}

func (e *dscError) Unwrap() error { return e.cause }

func dscFailure(message string, err error) error {
	if err == nil {
		return nil
	}
	return &dscError{message: message, cause: err}
}

func readDSCRequest(r io.Reader, operation string) (dscRequest, error) {
	request := dscRequest{exist: true}
	data, err := io.ReadAll(io.LimitReader(r, maxDSCInput+1))
	if err != nil {
		return request, dscFailure("cannot read DSC input", err)
	}
	defer clear(data)
	if len(data) > maxDSCInput {
		return request, errors.New("DSC input exceeds the 1 MiB limit")
	}
	if !utf8.Valid(data) {
		return request, errors.New("DSC input must be UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return request, errors.New("DSC input must be one JSON object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return request, errors.New("invalid DSC JSON object")
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return request, errors.New("invalid or duplicate DSC property")
		}
		seen[key] = true
		switch key {
		case "name":
			var name *string
			if err := decoder.Decode(&name); err != nil || name == nil {
				return request, errors.New("name must be a string")
			}
			request.name = *name
		case "value":
			request.value, err = readDSCValue(decoder)
			if err != nil {
				return request, err
			}
		case "_exist":
			var exist *bool
			if err := decoder.Decode(&exist); err != nil || exist == nil {
				return request, errors.New("_exist must be a boolean")
			}
			request.exist = *exist
		case "_inDesiredState":
			var state any
			if err := decoder.Decode(&state); err != nil || state != nil {
				return request, errors.New("_inDesiredState is read-only")
			}
		default:
			return request, errors.New("unknown DSC property")
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return request, errors.New("invalid DSC JSON object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return request, errors.New("DSC input must contain exactly one JSON object")
	}
	if err := validateName(request.name); err != nil {
		return request, errors.New("invalid or missing secret name")
	}
	if operation != "get" && request.exist && request.value == nil {
		return request, errors.New("value is required when _exist is true")
	}
	return request, nil
}

func readDSCValue(decoder *json.Decoder) (*string, error) {
	invalid := errors.New("value must be a string or an object containing only a secureString string")
	token, err := decoder.Token()
	if err != nil {
		return nil, invalid
	}
	if value, ok := token.(string); ok {
		return &value, nil
	}
	// DSC transports secureString parameters as tagged objects. Normalize
	// both forms immediately so neither can bypass secret handling.
	if token != json.Delim('{') {
		return nil, invalid
	}
	key, err := decoder.Token()
	if err != nil || key != "secureString" {
		return nil, invalid
	}
	token, err = decoder.Token()
	value, ok := token.(string)
	if err != nil || !ok {
		return nil, invalid
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, invalid
	}
	return &value, nil
}

func runDSC(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) != 1 || (args[0] != "get" && args[0] != "test" && args[0] != "set") {
		return errors.New("expected secstore dsc get, test, or set without additional arguments")
	}
	if err := requireRoot(); err != nil {
		return dscFailure("DSC operations require Linux and root privileges", err)
	}
	c, err := loadConfig(os.Getenv)
	if err != nil {
		return dscFailure("invalid secstore configuration", err)
	}
	// Legacy progress messages aren't part of the DSC protocol. All failures
	// propagate through the sanitized error boundary instead.
	s := store{config: c, log: io.Discard, prepareRuntime: ensureRuntime}
	if err := s.runDSC(args[0], stdin, stdout); err != nil {
		return fmt.Errorf("dsc %s: %w", args[0], err)
	}
	return nil
}

func (s *store) runDSC(operation string, stdin io.Reader, stdout io.Writer) error {
	request, err := readDSCRequest(stdin, operation)
	if err != nil {
		return err
	}
	state, diff, err := s.reconcileDSC(operation, request)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	if err := encoder.Encode(state); err != nil {
		return dscFailure("cannot write DSC state", err)
	}
	if operation != "get" {
		if err := encoder.Encode(diff); err != nil {
			return dscFailure("cannot write DSC property differences", err)
		}
	}
	return nil
}
