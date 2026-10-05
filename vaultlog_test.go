package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestLineRedactingWriterHandlesChunkedSecrets(t *testing.T) {
	const secret = "dev-root-token"
	var output bytes.Buffer
	w := newLineRedactingWriter(&output, secret)
	for _, chunk := range []string{"Root Token: dev-", "root-token\nready\n"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("secret leaked into logs: %q", output.String())
	}
	if got, want := output.String(), "Root Token: ****\nready\n"; got != want {
		t.Fatalf("redacted output = %q, want %q", got, want)
	}
}

// SP-SEC-03. A server that mints its own start-up credentials announces them
// under these labels, so this process never holds their values: the label is
// what is redacted, and the value never has to be known to be kept out.
func TestLineRedactingWriterRedactsCredentialsItDoesNotHold(t *testing.T) {
	for _, test := range []struct{ line, want string }{
		{"Unseal Key: TD2RGSynt9Bn8+yTTIWww9nSlGx1pqLrZCc+B27Dn3s=", "Unseal Key: ****"},
		{"Root Token: hvs.unknown-to-this-process", "Root Token: ****"},
		{"Recovery Key 1: 0f1e2d3c", "Recovery Key 1: ****"},
		{"        Initial Root Token: hvs.another", "        Initial Root Token: ****"},
		{"2026-06-16T14:56:37.312Z [INFO]  core: post-unseal setup starting", "2026-06-16T14:56:37.312Z [INFO]  core: post-unseal setup starting"},
		{"2026-06-16T14:56:37.312Z [INFO]  core: root token generated", "2026-06-16T14:56:37.312Z [INFO]  core: root token generated"},
	} {
		t.Run(test.line, func(t *testing.T) {
			var output bytes.Buffer
			w := newLineRedactingWriter(&output)
			if _, err := w.Write([]byte(test.line + "\n")); err != nil {
				t.Fatal(err)
			}
			if got, want := output.String(), test.want+"\n"; got != want {
				t.Fatalf("redacted output = %q, want %q", got, want)
			}
		})
	}
}
