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
