package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// defaultTransitKey is the transit key a consumer encrypts and HMACs under when
// the service sets no `transit-key`; Runtime.enableTransit applies the same
// default.
const defaultTransitKey = "api-keys"

// transitProvisionScript provisions, in a deployed Vault, the transit state the
// local runtime seeds in Runtime.enableTransit: the transit engine at transit/
// and the configured key. The deployment renders it as the vault container's
// postStart hook, so it runs against every start of the in-memory dev server.
//
//go:embed provision/transit.sh
var transitProvisionScript string

// transitKeyNamePattern bounds the key name to one plain Vault path segment. It
// reaches the hook as an argv entry, never through a shell expansion, but a
// name with a slash or a leading dot would address a different Vault path than
// the one consumers call.
var transitKeyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func (s *Service) transitKeyName() (string, error) {
	key := defaultTransitKey
	if s.Settings != nil && s.TransitKey != "" {
		key = s.TransitKey
	}
	if !transitKeyNamePattern.MatchString(key) {
		return "", fmt.Errorf("transit-key %q is not a valid Vault transit key name", key)
	}
	return key, nil
}

// transitProvisionCommand renders the postStart exec command as a JSON array.
// The script is passed to `sh -c` and the key name as its positional $1, so the
// configured value is data to the script, not script text.
func (s *Service) transitProvisionCommand() (string, error) {
	key, err := s.transitKeyName()
	if err != nil {
		return "", err
	}
	// A JSON array is a YAML flow sequence. HTML escaping stays off so the
	// rendered script reads as written (`2>&1`, not `2\u003e\u00261`).
	var command bytes.Buffer
	encoder := json.NewEncoder(&command)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode([]string{"/bin/sh", "-c", transitProvisionScript, "vault-provision", key}); err != nil {
		return "", err
	}
	return strings.TrimSpace(command.String()), nil
}
