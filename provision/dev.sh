#!/bin/sh
# Starts the in-memory Vault server of the ephemeral local-apply render. It is
# that container's command, the counterpart of provision/server.sh for the
# durable (deployed) render, and it exists for two invariants an `args: [server,
# -dev]` container cannot hold.
#
# 1. An in-memory store is a local-development shape only. The security posture
#    (rule 3) requires such a shape to refuse to start in a deployed runtime
#    context, by name: a restart loses every transit key it held, so a product
#    bound to it loses the values sealed under them. Only the local-apply render
#    declares VAULT_CODEFLY_RENDER_PROFILE, so this server refuses to start
#    wherever that declaration is absent or names another context — including a
#    StatefulSet copied out of a local render into a deployed composition, which
#    is the shape this guard exists for. A deployed cell runs the durable server
#    (provision/server.sh) or binds a Vault operated outside this service.
#
# 2. No start-up credential reaches a log, in development mode either.
#    `vault server -dev` prints its unseal key and its root token to standard
#    output as part of its banner, and a cell retains container output. Standard
#    output carries nothing else that standard error does not also carry — the
#    configuration block, the "server started" marker and the whole log stream
#    are on standard error — so discarding standard output removes both
#    credentials and keeps every log line, unbuffered.
#
# The dev server's root token is minted here, kept in the container's own tmpfs
# at mode 0600, and never rendered into a manifest, published to a consumer or
# written to output. It is a bootstrap credential for provision/provision.sh
# (dev mode), which uses it to provision the store and to install
# VAULT_ACCESS_TOKEN — the token consumers present — under a policy scoped to
# what a consumer reads. It dies with the container, as the store does.
#
# Rendered verbatim into the manifest, whose validator rejects any `$` + `{`
# sequence as an unresolved placeholder: variables are expanded only as $NAME.
set -eu

# The one render that may run an in-memory store. provision.go holds the same
# two values; they are a contract between this script and the render.
expected_profile="ephemeral-local-apply"
profile="$(printenv VAULT_CODEFLY_RENDER_PROFILE || true)"
if [ "$profile" != "$expected_profile" ]; then
	echo "vault: an in-memory (-dev) Vault is a local-development shape and refuses to start in a deployed runtime context: VAULT_CODEFLY_RENDER_PROFILE is \"$profile\", not \"$expected_profile\". A deployed cell runs the durable server with storage on a persistent volume, or binds a Vault operated outside this service" >&2
	exit 78
fi

root_file="/tmp/vault-dev-root"
if [ -n "$(printenv VAULT_DEV_ROOT_FILE || true)" ]; then
	root_file="$VAULT_DEV_ROOT_FILE"
fi

umask 077
VAULT_DEV_ROOT_TOKEN_ID="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export VAULT_DEV_ROOT_TOKEN_ID
if [ "$(printf '%s' "$VAULT_DEV_ROOT_TOKEN_ID" | wc -c)" -ne 64 ]; then
	echo "vault: cannot mint the in-memory server's bootstrap token" >&2
	exit 70
fi
printf '%s' "$VAULT_DEV_ROOT_TOKEN_ID" > "$root_file"

# Standard output is the banner, which carries the unseal key and the root
# token. Standard error is the log stream and is kept.
exec vault server -dev -dev-listen-address=0.0.0.0:8200 >/dev/null
