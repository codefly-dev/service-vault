package main

// vaultlog.go — structured rendering of the vault server log stream.
//
// Vault lines look like "2026-06-16T14:56:37.312Z [INFO]  core: post-unseal
// setup starting": an RFC3339 timestamp, a bracketed level, then the message.
// Raw, every line lands at one undifferentiated level. A woollog.Writer parses
// each line with this declarative gortk.LogSpec and re-emits it through Wool at
// the mapped severity (the timestamp is dropped — Wool stamps its own).

import (
	"bytes"
	"io"
	"strings"
	"sync"

	"github.com/codefly-dev/core/wool"
	"github.com/codefly-dev/core/woollog"
	"github.com/codefly-dev/gortk"
)

var vaultLog = gortk.LogSpec{
	LineRegex: `^\S+ \[(?P<level>\w+)\]\s+(?P<msg>.*)$`,
	LevelMap: map[string]string{
		"TRACE": "debug", "DEBUG": "debug", "INFO": "info",
		"WARN": "warn", "WARNING": "warn", "ERROR": "error",
	},
	DefaultLevel: "info",
}

func newVaultLogWriter(w *wool.Wool, secrets ...string) io.Writer {
	return newLineRedactingWriter(woollog.MustNew(w, vaultLog), secrets...)
}

type lineRedactingWriter struct {
	dst     io.Writer
	secrets []string
	buf     []byte
	mu      sync.Mutex
}

func newLineRedactingWriter(dst io.Writer, secrets ...string) io.Writer {
	filtered := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			filtered = append(filtered, secret)
		}
	}
	return &lineRedactingWriter{dst: dst, secrets: filtered}
}

func (w *lineRedactingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := string(w.buf[:i])
		w.buf = w.buf[i+1:]
		for _, secret := range w.secrets {
			line = strings.ReplaceAll(line, secret, "****")
		}
		if _, err := io.WriteString(w.dst, line+"\n"); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}
