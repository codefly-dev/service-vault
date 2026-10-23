// Package keyservice contains runtime clients owned by the key-service agent.
// Consumers retain their envelope framing and signing contracts; provider SDKs
// and provider-specific validation stay here, outside product services.
package keyservice

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// AzureBinding is a non-secret, explicit installation. Key references pin a
// version. All three keys must be distinct and in the same Managed HSM.
// No default credential chain or operator login is used by a hosted consumer.
type AzureBinding struct {
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	EnvelopeKey    string `json:"envelope_key"`
	MACKey         string `json:"mac_key"`
	SigningWrapKey string `json:"signing_wrap_key"`
}

type keyRef struct{ uri, base, name, version string }

var keyURL = regexp.MustCompile(`^https://([a-z][a-z0-9-]{1,22}[a-z0-9]\.managedhsm\.azure\.net)/keys/([A-Za-z0-9-]{1,127})/([a-f0-9]{32})$`)
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func parseKey(uri string) (keyRef, error) {
	m := keyURL.FindStringSubmatch(uri)
	if m == nil {
		return keyRef{}, errors.New("key service requires a version-pinned public-cloud Managed HSM key URL")
	}
	return keyRef{uri: uri, base: "https://" + m[1], name: m[2], version: m[3]}, nil
}

func (b AzureBinding) validate() ([3]keyRef, error) {
	var keys [3]keyRef
	for _, id := range []string{b.TenantID, b.ClientID} {
		if !uuid.MatchString(id) || id == "00000000-0000-0000-0000-000000000000" {
			return keys, errors.New("key service requires explicit tenant and workload client UUIDs")
		}
	}
	for i, uri := range []string{b.EnvelopeKey, b.MACKey, b.SigningWrapKey} {
		key, err := parseKey(uri)
		if err != nil {
			return keys, err
		}
		keys[i] = key
		for j := 0; j < i; j++ {
			if key.base != keys[j].base || key.name == keys[j].name {
				return keys, errors.New("key service requires distinct purpose keys in one Managed HSM")
			}
		}
	}
	return keys, nil
}

// Azure operates on non-exportable symmetric keys in Azure Managed HSM.
// An ordinary Standard Key Vault cannot satisfy this binding.
type Azure struct {
	client *azkeys.Client
	keys   [3]keyRef
}

func NewAzure(ctx context.Context, binding AzureBinding) (*Azure, error) {
	return newAzure(ctx, binding, nil, nil)
}

func newAzure(ctx context.Context, binding AzureBinding, credential azcore.TokenCredential, transport policy.Transporter) (*Azure, error) {
	keys, err := binding.validate()
	if err != nil {
		return nil, err
	}
	if credential == nil {
		credential, err = azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{TenantID: binding.TenantID, ClientID: binding.ClientID})
		if err != nil {
			return nil, errors.New("cannot initialize the key-service workload credential")
		}
	}
	if transport == nil {
		transport = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	client, err := azkeys.NewClient(keys[0].base, credential, &azkeys.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: transport, Retry: policy.RetryOptions{MaxRetries: -1}}})
	if err != nil {
		return nil, errors.New("cannot initialize the managed key service")
	}
	a := &Azure{client: client, keys: keys}
	for i, key := range keys {
		ops := []azkeys.KeyOperation{azkeys.KeyOperationEncrypt, azkeys.KeyOperationDecrypt}
		if i == 1 {
			ops = []azkeys.KeyOperation{azkeys.KeyOperationSign}
		}
		if err := a.checkKey(ctx, key, ops); err != nil {
			return nil, err
		}
	}
	for _, key := range []keyRef{keys[0], keys[2]} {
		if err := a.probe(ctx, key); err != nil {
			return nil, err
		}
	}
	if _, err := a.MAC(ctx, "key-service boot probe"); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Azure) probe(ctx context.Context, key keyRef) error {
	const purpose, value = "codefly.key-service.boot-probe/v1", "key-service boot probe"
	sealed, err := a.seal(ctx, key, purpose, value)
	if err != nil {
		return err
	}
	opened, err := a.open(ctx, key, purpose, sealed)
	if err != nil {
		return err
	}
	if opened != value {
		return errors.New("managed key service failed its encryption round trip")
	}
	return nil
}

func (a *Azure) checkKey(ctx context.Context, key keyRef, ops []azkeys.KeyOperation) error {
	r, err := a.client.GetKey(ctx, key.name, key.version, nil)
	if err != nil {
		return safeError(err)
	}
	now := time.Now()
	if r.Attributes == nil || r.Attributes.Enabled == nil || !*r.Attributes.Enabled ||
		(r.Attributes.Exportable != nil && *r.Attributes.Exportable) ||
		(r.Attributes.NotBefore != nil && now.Before(*r.Attributes.NotBefore)) ||
		(r.Attributes.Expires != nil && !now.Before(*r.Attributes.Expires)) {
		return errors.New("key service requires an enabled, non-exportable key within its validity period")
	}
	if r.Key == nil || r.Key.KID == nil || string(*r.Key.KID) != key.uri || r.Key.Kty == nil || *r.Key.Kty != azkeys.KeyTypeOctHSM || len(r.Key.K) != 0 || r.ReleasePolicy != nil {
		return errors.New("key service returned the wrong key identity, type or custody")
	}
	for _, required := range ops {
		found := false
		for _, op := range r.Key.KeyOps {
			if op != nil && *op == required {
				found = true
			}
		}
		if !found {
			return errors.New("key service key does not permit its declared operations")
		}
	}
	return nil
}

// payload is only the provider portion of the consumer's stored envelope.
// The key version survives rotation, while the configured key family bounds
// which historical versions a reader may ask the service to decrypt.
type payload struct {
	Version    int    `json:"v"`
	Key        string `json:"kid"`
	IV         []byte `json:"iv"`
	Tag        []byte `json:"tag"`
	Ciphertext []byte `json:"ciphertext"`
}

const maxPlaintext = 64 * 1024

func decode(value string) (payload, error) {
	var p payload
	if len(value) > 2*maxPlaintext {
		return p, errors.New("key-service ciphertext is too large")
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return p, errors.New("invalid key-service ciphertext encoding")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.Version != 1 || len(p.IV) != 12 || len(p.Tag) != 16 || len(p.Ciphertext) > maxPlaintext {
		return p, errors.New("invalid key-service ciphertext")
	}
	return p, nil
}

func (a *Azure) Identity() string { return a.keys[0].base + "/keys/" + a.keys[0].name }

func (a *Azure) Accepts(value string) bool {
	p, err := decode(value)
	if err != nil {
		return false
	}
	k, err := parseKey(p.Key)
	return err == nil && k.base == a.keys[0].base && k.name == a.keys[0].name
}

func (a *Azure) Seal(ctx context.Context, purpose, plaintext string) (string, error) {
	return a.seal(ctx, a.keys[0], purpose, plaintext)
}

func (a *Azure) seal(ctx context.Context, key keyRef, purpose, plaintext string) (string, error) {
	if purpose == "" || len(plaintext) > maxPlaintext || len(purpose) > 4096 {
		return "", errors.New("invalid key-service purpose or plaintext size")
	}
	// Managed HSM owns GCM nonce generation. A caller-supplied IV is refused;
	// retain the returned nonce with the authenticated ciphertext for Open.
	r, err := a.client.Encrypt(ctx, key.name, key.version, azkeys.KeyOperationParameters{Algorithm: ptr(azkeys.EncryptionAlgorithmA256GCM), Value: []byte(plaintext), AdditionalAuthenticatedData: []byte(purpose)}, nil)
	if err != nil {
		return "", safeError(err)
	}
	if r.KID == nil || string(*r.KID) != key.uri || len(r.IV) != 12 || len(r.AuthenticationTag) != 16 || len(r.Result) != len(plaintext) {
		return "", errors.New("invalid managed encryption response")
	}
	b, _ := json.Marshal(payload{Version: 1, Key: key.uri, IV: r.IV, Tag: r.AuthenticationTag, Ciphertext: r.Result})
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Azure) Open(ctx context.Context, purpose, value string) (string, error) {
	return a.open(ctx, a.keys[0], purpose, value)
}

func (a *Azure) open(ctx context.Context, key keyRef, purpose, value string) (string, error) {
	if purpose == "" || len(purpose) > 4096 {
		return "", errors.New("invalid key-service purpose")
	}
	p, err := decode(value)
	if err != nil {
		return "", errors.Join(ErrInvalidCiphertext, err)
	}
	k, err := parseKey(p.Key)
	if err != nil || k.base != key.base || k.name != key.name {
		return "", errors.Join(ErrInvalidCiphertext, errors.New("ciphertext belongs to a different key"))
	}
	r, err := a.client.Decrypt(ctx, k.name, k.version, azkeys.KeyOperationParameters{Algorithm: ptr(azkeys.EncryptionAlgorithmA256GCM), Value: p.Ciphertext, AdditionalAuthenticatedData: []byte(purpose), IV: p.IV, AuthenticationTag: p.Tag}, nil)
	if err != nil {
		var response *azcore.ResponseError
		if errors.As(err, &response) && response.StatusCode == http.StatusBadRequest {
			return "", errors.Join(ErrInvalidCiphertext, safeError(err))
		}
		return "", safeError(err)
	}
	if r.KID == nil || string(*r.KID) != k.uri || len(r.Result) != len(p.Ciphertext) {
		return "", errors.New("invalid managed decryption response")
	}
	return string(r.Result), nil
}

// MAC stays pinned to the exact version in the binding. The caller owns its
// persisted hash framing; key rotation must never silently change lookups.
func (a *Azure) MAC(ctx context.Context, value string) (string, error) {
	if a.keys[1].uri == "" {
		return "", errors.New("organization keys cannot compute deployment MACs")
	}
	if len(value) > maxPlaintext {
		return "", errors.New("key-service MAC input is too large")
	}
	k := a.keys[1]
	r, err := a.client.Sign(ctx, k.name, k.version, azkeys.SignParameters{Algorithm: ptr(azkeys.SignatureAlgorithmHS256), Value: []byte(value)}, nil)
	if err != nil {
		return "", safeError(err)
	}
	if r.KID == nil || string(*r.KID) != k.uri || len(r.Result) != 32 {
		return "", errors.New("invalid managed MAC response")
	}
	return base64.RawURLEncoding.EncodeToString([]byte(k.uri)) + ":" + base64.StdEncoding.EncodeToString(r.Result), nil
}

// Wrap and Unwrap preserve the consumer's signing material. The caller supplies
// the existing purpose string and validates its own key type; no signing
// algorithm or key generation policy is invented by this client.
func (a *Azure) Wrap(ctx context.Context, purpose, value string) (string, error) {
	if a.keys[2].uri == "" {
		return "", errors.New("organization keys cannot wrap deployment signing material")
	}
	return a.seal(ctx, a.keys[2], purpose, value)
}
func (a *Azure) Unwrap(ctx context.Context, purpose, value string) (string, error) {
	if a.keys[2].uri == "" {
		return "", errors.New("organization keys cannot unwrap deployment signing material")
	}
	return a.open(ctx, a.keys[2], purpose, value)
}

// ForKey binds an organization's envelope key in this installation. It cannot
// select another HSM or either reserved deployment key, and it never gets MAC.
func (a *Azure) ForKey(ctx context.Context, uri string) (Client, error) {
	if a.keys[1].uri == "" {
		return nil, errors.New("organization keys cannot select further key bindings")
	}
	k, err := parseKey(uri)
	if err != nil {
		return nil, err
	}
	if k.base != a.keys[0].base {
		return nil, errors.New("organization key belongs to a different key service")
	}
	for _, reserved := range a.keys {
		if k.name == reserved.name {
			return nil, errors.New("organization key is reserved for the deployment")
		}
	}
	if err := a.checkKey(ctx, k, []azkeys.KeyOperation{azkeys.KeyOperationEncrypt, azkeys.KeyOperationDecrypt}); err != nil {
		return nil, err
	}
	if err := a.probe(ctx, k); err != nil {
		return nil, err
	}
	return &Azure{client: a.client, keys: [3]keyRef{k}}, nil
}

type operationError struct{ status int }

func (e *operationError) Error() string {
	return fmt.Sprintf("managed key service request failed (HTTP %d)", e.status)
}
func (e *operationError) HTTPStatusCode() int { return e.status }
func safeError(err error) error {
	var response *azcore.ResponseError
	if errors.As(err, &response) {
		return &operationError{status: response.StatusCode}
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	// SDK errors can carry URLs, response bodies and reflected plaintext.
	return errors.New("managed key service request failed")
}
func ptr[T any](v T) *T { return &v }

// DecodeAzureBinding rejects unknown fields rather than accepting a typo that
// drops a custody or workload constraint.
func DecodeAzureBinding(value string) (AzureBinding, error) {
	var b AzureBinding
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF {
		return b, errors.New("invalid Azure key-service binding")
	}
	_, err := b.validate()
	return b, err
}
