package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNewService_EmbedsBase(t *testing.T) {
	svc := NewService()
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.Base == nil {
		t.Fatal("Service.Base is nil — services.Base embedding broken")
	}
	if svc.Settings == nil {
		t.Fatal("Service.Settings is nil")
	}
}

func TestSettings_YAMLRoundTrip(t *testing.T) {
	src := []byte(`transit-key: "api-keys"`)
	var s Settings
	if err := yaml.Unmarshal(src, &s); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if s.TransitKey != "api-keys" {
		t.Errorf("TransitKey: got %q", s.TransitKey)
	}
}
