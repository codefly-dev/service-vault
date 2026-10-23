package keyservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Client is the runtime capability consumed by Host. It owns provider payloads,
// not the consumer's outer envelope, signing algorithm or authorization policy.
type Client interface {
	Tag() string
	Identity() string
	Accepts(string) bool
	Seal(context.Context, string, string) (string, error)
	Open(context.Context, string, string) (string, error)
	MAC(context.Context, string) (string, error)
	Wrap(context.Context, string, string) (string, error)
	Unwrap(context.Context, string, string) (string, error)
	ForKey(context.Context, string) (Client, error)
}

// ErrInvalidCiphertext distinguishes corrupt or purpose-mismatched input from
// provider outages and revoked access. Consumers map it to their domain error.
var ErrInvalidCiphertext = errors.New("invalid managed key-service ciphertext")

func (a *Azure) Tag() string { return "azure-managed-hsm" }

// New consumes an explicit, non-secret provider binding projected by the
// deployment owner. Unknown providers and unknown fields fail before auth.
func New(ctx context.Context, descriptor string) (Client, error) {
	var binding struct {
		Provider string          `json:"provider"`
		Settings json.RawMessage `json:"settings"`
	}
	d := json.NewDecoder(strings.NewReader(descriptor))
	d.DisallowUnknownFields()
	if d.Decode(&binding) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid managed key-service descriptor")
	}
	if binding.Provider != "azure-managed-hsm" {
		return nil, errors.New("unsupported managed key-service provider")
	}
	azure, err := DecodeAzureBinding(string(binding.Settings))
	if err != nil {
		return nil, err
	}
	return NewAzure(ctx, azure)
}
