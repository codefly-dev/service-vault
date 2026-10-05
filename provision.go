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
// initialization and KV v2 at secret/; in both modes the transit engine at
// transit/ with the configured key, the consumer policy, and the
// composition-supplied access token scoped to that policy. The deployment
// renders it as the vault container's postStart hook, so it runs on every start
// of the Vault process.
//
//go:embed provision/provision.sh
var provisionScript string

// serverScript starts the durable server of a restricted render: raft storage
// on the pod's persistent volume, auto-unsealed by the environment's seal.
//
//go:embed provision/server.sh
var serverScript string

// devScript starts the in-memory server of the ephemeral local-apply render. It
// is a script rather than plain `server -dev` arguments for two reasons it
// states itself: an in-memory store refuses to start outside the one render
// that may run it, and the dev banner's unseal key and root token never reach
// the container's output.
//
//go:embed provision/dev.sh
var devScript string

// consumerPolicyName is the Vault policy provision/provision.sh writes and the
// access token carries — the only one it carries. It grants the paths a
// consumer reads and writes and nothing else; no consumer holds a root-policy
// credential. Declared here so the render and the script cannot drift apart.
const consumerPolicyName = "codefly-access"

// consumerTokenTTL is how long the access token lives. Consumers hold it as a
// static secret and have no renewal path — a scoped token's `renew-self` is
// refused, unlike the root-policy token this replaced, which never expired at
// all. So the lifetime has to stay effectively unbounded or every consumer
// would stop reading the store a month after the Vault was provisioned. Giving
// this credential a real rotation lifetime means consumers authenticating to
// Vault themselves (an auth method) rather than presenting a delivered token,
// which is a change to what consumers receive, not to its scope.
//
// Vault caps a non-root token at the token store's max lease TTL (768h by
// default), so the store is tuned to this value before the token is created.
const consumerTokenTTL = "87600h"

// consumerPolicy is the policy installed under consumerPolicyName: the paths a
// consumer reads and writes, and nothing else. KV v2 under secret/, and the one
// configured transit key's operations plus a read of the key itself (its type
// and version, never its material).
//
// Vault attaches its own `default` policy to every non-root token on top of
// this; that policy grants a token only operations on itself and its own
// cubbyhole, and no path under secret/ or transit/. Absent here, and therefore
// denied: everything under sys/ (no mount, no policy, no audit device, no seal
// setting), token creation, every other transit key, and creating, rotating,
// retyping or deleting a transit key.
//
// provision/provision.sh carries the same text as a shell heredoc, with the key
// name as $key — the deployed renders and the local runtime must grant one
// scope, not two. TestConsumerPolicyIsOneScope holds the two copies together.
func consumerPolicy(transitKey string) string {
	return fmt.Sprintf(`path "secret/data/*" {
  capabilities = ["create", "read", "update", "patch", "delete"]
}

path "secret/metadata/*" {
  capabilities = ["read", "list", "delete"]
}

path "secret/delete/*" {
  capabilities = ["update"]
}

path "secret/undelete/*" {
  capabilities = ["update"]
}

path "secret/destroy/*" {
  capabilities = ["update"]
}

path "transit/encrypt/%[1]s" {
  capabilities = ["update"]
}

path "transit/decrypt/%[1]s" {
  capabilities = ["update"]
}

path "transit/hmac/%[1]s" {
  capabilities = ["update"]
}

path "transit/verify/%[1]s" {
  capabilities = ["update"]
}

path "transit/rewrap/%[1]s" {
  capabilities = ["update"]
}

path "transit/keys/%[1]s" {
  capabilities = ["read"]
}
`, transitKey)
}

// localApplyRenderProfile is what the ephemeral local-apply render declares to
// the in-memory server as VAULT_CODEFLY_RENDER_PROFILE. provision/dev.sh
// refuses to start without it, so a manifest carrying that server into a
// deployed runtime context stops at start-up instead of backing a product with
// a store a restart empties.
const (
	localApplyRenderProfile      = "ephemeral-local-apply"
	renderProfileEnvironmentName = "VAULT_CODEFLY_RENDER_PROFILE"
)

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

// devCommand renders the in-memory container's command, the same shape as
// serverCommand: dumb-init stays PID 1 and the script execs vault.
func devCommand() (string, error) {
	return execCommand("/usr/bin/dumb-init", "--", "/bin/sh", "-c", devScript, "vault-dev")
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
