package main

// vaultlog.go — structured rendering of the vault server log stream.
//
// Vault lines look like "2026-06-16T14:56:37.312Z [INFO]  core: post-unseal
// setup starting": an RFC3339 timestamp, a bracketed level, then the message.
// Raw, every line lands at one undifferentiated level. A woollog.Writer parses
// each line with this declarative gortk.LogSpec and re-emits it through Wool at
// the mapped severity (the timestamp is dropped — Wool stamps its own).

import (
	"io"

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

func newVaultLogWriter(w *wool.Wool) io.Writer {
	return woollog.MustNew(w, vaultLog)
}
