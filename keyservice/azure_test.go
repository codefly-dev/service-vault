package keyservice

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

const hsm = "https://example-keys.managedhsm.azure.net"
const version = "0123456789abcdef0123456789abcdef"

type credential struct{}

func (credential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-only-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type server struct {
	t                                                *testing.T
	requests                                         int
	denied, exportable, wrongKey, software, disabled bool
}

// The real azkeys SDK serializes to this transport. The controlled service uses
// real AES-GCM/HMAC to exercise purpose binding, corruption and retained keys.
func (s *server) Do(req *http.Request) (*http.Response, error) {
	s.requests++
	path := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(path) < 3 || path[0] != "keys" || req.URL.Scheme != "https" || req.URL.Host != "example-keys.managedhsm.azure.net" {
		s.t.Fatalf("unexpected SDK request %s", req.URL)
	}
	kid := hsm + "/keys/" + path[1] + "/" + path[2]
	answer := func(status int, value any) (*http.Response, error) {
		b, err := json.Marshal(value)
		if err != nil {
			s.t.Fatal(err)
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(b))), Request: req}, nil
	}
	if req.Header.Get("Authorization") == "" {
		response, err := answer(401, map[string]any{})
		response.Header.Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111", resource="https://managedhsm.azure.net"`)
		return response, err
	}
	if s.denied {
		return answer(403, map[string]any{"error": map[string]string{"code": "Forbidden", "message": "REFLECTED-SECRET-MUST-NOT-LEAK"}})
	}
	if req.Method == http.MethodGet {
		kind := "oct-HSM"
		if s.software {
			kind = "oct"
		}
		if s.wrongKey {
			kid += "0"
		}
		return answer(200, map[string]any{"key": map[string]any{"kid": kid, "kty": kind, "key_ops": []string{"encrypt", "decrypt", "sign"}}, "attributes": map[string]any{"enabled": !s.disabled, "exportable": s.exportable}})
	}
	if len(path) != 4 {
		s.t.Fatal("unexpected key operation path")
	}
	if s.disabled {
		return answer(403, map[string]any{"error": map[string]string{"code": "Forbidden"}})
	}
	var body struct {
		Algorithm string `json:"alg"`
		Value     string `json:"value"`
		IV        string `json:"iv"`
		AAD       string `json:"aad"`
		Tag       string `json:"tag"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		s.t.Fatal(err)
	}
	decode := func(v string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			s.t.Fatal(err)
		}
		return b
	}
	value := decode(body.Value)
	key := sha256.Sum256([]byte(kid))
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	response := map[string]any{"kid": kid}
	switch path[3] {
	case "encrypt":
		if body.Algorithm != "A256GCM" {
			s.t.Fatal("wrong encryption algorithm")
		}
		if body.IV != "" {
			s.t.Fatal("Managed HSM refuses a caller-supplied GCM nonce")
		}
		iv := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(iv); err != nil {
			s.t.Fatal(err)
		}
		sealed := gcm.Seal(nil, iv, value, decode(body.AAD))
		response["value"] = base64.RawURLEncoding.EncodeToString(sealed[:len(sealed)-16])
		response["tag"] = base64.RawURLEncoding.EncodeToString(sealed[len(sealed)-16:])
		response["iv"] = base64.RawURLEncoding.EncodeToString(iv)
	case "decrypt":
		if body.Algorithm != "A256GCM" {
			s.t.Fatal("wrong decryption algorithm")
		}
		plain, err := gcm.Open(nil, decode(body.IV), append(value, decode(body.Tag)...), decode(body.AAD))
		if err != nil {
			return answer(400, map[string]any{"error": map[string]string{"code": "BadParameter", "message": "REFLECTED-SECRET-MUST-NOT-LEAK"}})
		}
		response["value"] = base64.RawURLEncoding.EncodeToString(plain)
	case "sign":
		if body.Algorithm != "HS256" {
			s.t.Fatal("wrong MAC algorithm")
		}
		h := hmac.New(sha256.New, key[:])
		h.Write(value)
		response["value"] = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	default:
		s.t.Fatalf("unexpected operation %s", path[3])
	}
	if s.wrongKey {
		response["kid"] = kid + "0"
	}
	return answer(200, response)
}

func binding() AzureBinding {
	return AzureBinding{TenantID: "11111111-1111-1111-1111-111111111111", ClientID: "22222222-2222-2222-2222-222222222222", EnvelopeKey: hsm + "/keys/envelope/" + version, MACKey: hsm + "/keys/mac/" + version, SigningWrapKey: hsm + "/keys/signing-wrap/" + version}
}
func client(t *testing.T, s *server, b AzureBinding) *Azure {
	t.Helper()
	a, err := newAzure(t.Context(), b, credential{}, s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func requireError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected refusal")
	}
	if strings.Contains(err.Error(), "REFLECTED-SECRET") {
		t.Fatalf("secret leaked: %v", err)
	}
}

func TestAzureRestartRotationAndSigningMaterial(t *testing.T) {
	s := &server{t: t}
	b := binding()
	a := client(t, s, b)
	sealed, err := a.Seal(t.Context(), "credential:row-1", "retained credential")
	if err != nil {
		t.Fatal(err)
	}
	other, err := a.Seal(t.Context(), "credential:row-1", "retained credential")
	if err != nil {
		t.Fatal(err)
	}
	if sealed == other {
		t.Fatal("nonce reused")
	}
	_, err = a.Open(t.Context(), "credential:row-2", sealed)
	requireError(t, err)
	hash, err := a.MAC(t.Context(), "api-key")
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("test signing seed"))
	wrapped, err := a.Wrap(t.Context(), "host-signing", base64.StdEncoding.EncodeToString(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	b.EnvelopeKey = strings.Replace(b.EnvelopeKey, version, strings.Repeat("a", 32), 1)
	b.SigningWrapKey = strings.Replace(b.SigningWrapKey, version, strings.Repeat("b", 32), 1)
	restarted := client(t, s, b)
	if !restarted.Accepts(sealed) {
		t.Fatal("rotation lost historical key")
	}
	plain, err := restarted.Open(t.Context(), "credential:row-1", sealed)
	if err != nil || plain != "retained credential" {
		t.Fatalf("restart lost ciphertext: %v", err)
	}
	got, err := restarted.MAC(t.Context(), "api-key")
	if err != nil || got != hash {
		t.Fatalf("lookup changed after restart: %v", err)
	}
	encoded, err := restarted.Unwrap(t.Context(), "host-signing", wrapped)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.NewKeyFromSeed(seed[:]).Equal(ed25519.NewKeyFromSeed(recovered)) {
		t.Fatal("restart changed signing identity")
	}
	_, err = restarted.Open(t.Context(), "host-signing", wrapped)
	requireError(t, err)
	_, err = restarted.Unwrap(t.Context(), "different-purpose", wrapped)
	requireError(t, err)
	s.denied = true
	_, err = restarted.Open(t.Context(), "credential:row-1", sealed)
	requireError(t, err)
	_, err = restarted.MAC(t.Context(), "api-key")
	requireError(t, err)
	_, err = restarted.Unwrap(t.Context(), "host-signing", wrapped)
	requireError(t, err)
}

func TestAzureRefusesWrongCustodyAndIdentity(t *testing.T) {
	for _, mode := range []string{"exportable", "software", "disabled", "wrong-key", "denied"} {
		t.Run(mode, func(t *testing.T) {
			s := &server{t: t, exportable: mode == "exportable", software: mode == "software", disabled: mode == "disabled", wrongKey: mode == "wrong-key", denied: mode == "denied"}
			_, err := newAzure(t.Context(), binding(), credential{}, s)
			requireError(t, err)
		})
	}
	s := &server{t: t}
	a := client(t, s, binding())
	s.wrongKey = true
	_, err := a.Seal(t.Context(), "purpose", "secret")
	requireError(t, err)
	_, err = a.MAC(t.Context(), "api-key")
	requireError(t, err)
}

func TestAzureRefusesMalformedBindingsBeforeNetwork(t *testing.T) {
	for _, edit := range []func(*AzureBinding){
		func(b *AzureBinding) { b.ClientID = "" }, func(b *AzureBinding) { b.TenantID = strings.Repeat("0", 36) },
		func(b *AzureBinding) { b.EnvelopeKey = strings.Replace(b.EnvelopeKey, "managedhsm", "vault", 1) },
		func(b *AzureBinding) { b.MACKey = strings.TrimSuffix(b.MACKey, version) },
		func(b *AzureBinding) { b.MACKey = b.EnvelopeKey }, func(b *AzureBinding) { b.SigningWrapKey += "?key=other" },
		func(b *AzureBinding) { b.EnvelopeKey = strings.Replace(b.EnvelopeKey, "example-keys", "other-keys", 1) },
	} {
		b := binding()
		edit(&b)
		s := &server{t: t}
		_, err := newAzure(t.Context(), b, credential{}, s)
		requireError(t, err)
		if s.requests != 0 {
			t.Fatal("invalid binding reached provider")
		}
	}
	_, err := New(t.Context(), `{"provider":"unknown","settings":{}}`)
	requireError(t, err)
	_, err = DecodeAzureBinding(`{"tenant_id":"x","unknown":true}`)
	requireError(t, err)
}

func TestAzureOrganizationKeysCannotUseDeploymentCapabilities(t *testing.T) {
	s := &server{t: t}
	a := client(t, s, binding())
	org, err := a.ForKey(t.Context(), hsm+"/keys/org-one/"+version)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := org.Seal(t.Context(), "row", "org secret")
	if err != nil {
		t.Fatal(err)
	}
	if a.Accepts(sealed) {
		t.Fatal("deployment accepts organization's ciphertext")
	}
	before := s.requests
	_, err = a.Open(t.Context(), "row", sealed)
	requireError(t, err)
	_, err = org.MAC(t.Context(), "api-key")
	requireError(t, err)
	_, err = org.Wrap(t.Context(), "host", "seed")
	requireError(t, err)
	_, err = org.Unwrap(t.Context(), "host", sealed)
	requireError(t, err)
	_, err = a.ForKey(t.Context(), binding().MACKey)
	requireError(t, err)
	if s.requests != before {
		t.Fatal("forbidden operation reached provider")
	}
	plain, err := org.Open(t.Context(), "row", sealed)
	if err != nil || plain != "org secret" {
		t.Fatal(err)
	}
}
