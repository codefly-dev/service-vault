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

// provisionMode selects how provision/provision.sh treats the server it runs
// against: the in-memory dev server of the ephemeral local-apply render, or the
// durable, auto-unsealed raft server of a restricted (deployed) render.
type provisionMode string

const (
	provisionModeDev     provisionMode = "dev"
	provisionModeDurable provisionMode = "durable"
)

// provisionScript provisions, in a deployed Vault, the state the local runtime
// seeds (Runtime.enableTransit and localVaultState.bootstrap): in durable mode
// initialization, the composition-supplied access token and KV v2 at secret/;
// in both modes the transit engine at transit/ and the configured key. The
// deployment renders it as the vault container's postStart hook, so it runs on
// every start of the Vault process.
//
//go:embed provision/provision.sh
var provisionScript string

// serverScript starts the durable server of a restricted render: raft storage
// on the pod's persistent volume, auto-unsealed by the environment's seal.
//
//go:embed provision/server.sh
var serverScript string

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

// provisionCommand renders the postStart exec command as a JSON array. The
// script is passed to `sh -c` and the mode and key name as its positional $1
// and $2, so the configured value is data to the script, not script text.
func provisionCommand(mode provisionMode, key string) (string, error) {
	return execCommand("/bin/sh", "-c", provisionScript, "vault-provision", string(mode), key)
}

// serverCommand renders the durable container's command. dumb-init stays PID 1,
// as under the image's own entrypoint, so signals reach vault and zombies are
// reaped.
func serverCommand() (string, error) {
	return execCommand("/usr/bin/dumb-init", "--", "/bin/sh", "-c", serverScript, "vault-server")
}

// execCommand renders an exec argv as a JSON array, which is a valid YAML flow
// sequence. HTML escaping stays off so a rendered script reads as written
// (`2>&1`, not `2>&1`).
func execCommand(argv ...string) (string, error) {
	var command bytes.Buffer
	encoder := json.NewEncoder(&command)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(argv); err != nil {
		return "", err
	}
	return strings.TrimSpace(command.String()), nil
}
