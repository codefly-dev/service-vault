package main

import (
	"strings"
	"testing"
)

func TestVaultServerArgsKeepRootTokenSecret(t *testing.T) {
	token := "root-token-that-must-not-appear"
	n := &nixVault{port: 18200, token: token}
	args := strings.Join(n.serverArgs(), " ")
	if strings.Contains(args, token) || strings.Contains(args, "dev-root-token-id") {
		t.Fatalf("Vault root token leaked into process argv: %q", args)
	}
}
