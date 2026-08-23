package keyring

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func writeKeyringFile(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadAndResolve(t *testing.T) {
	dir := t.TempDir()
	secret := base64.StdEncoding.EncodeToString([]byte("my-secret-key"))
	content := `{"keys":{"kid1":"` + secret + `"},"default_kid":"kid1"}`
	path := writeKeyringFile(t, dir, content)

	ring, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if ring.Len() != 1 {
		t.Errorf("Len = %d, want 1", ring.Len())
	}

	got, err := ring.Resolve("kid1")
	if err != nil {
		t.Fatalf("Resolve(kid1): %v", err)
	}
	if string(got) != "my-secret-key" {
		t.Errorf("secret = %q, want my-secret-key", got)
	}
}

func TestResolveDefaultWhenNoKid(t *testing.T) {
	dir := t.TempDir()
	s1 := base64.StdEncoding.EncodeToString([]byte("s1"))
	s2 := base64.StdEncoding.EncodeToString([]byte("s2"))
	content := `{"keys":{"k1":"` + s1 + `","k2":"` + s2 + `"},"default_kid":"k2"}`
	path := writeKeyringFile(t, dir, content)

	ring, _ := LoadFile(path)
	got, err := ring.Resolve("") // empty kid -> use default
	if err != nil {
		t.Fatalf("Resolve empty: %v", err)
	}
	if string(got) != "s2" {
		t.Errorf("default secret = %q, want s2", got)
	}
}

func TestResolveUnknownKidErrors(t *testing.T) {
	dir := t.TempDir()
	s := base64.StdEncoding.EncodeToString([]byte("x"))
	content := `{"keys":{"known":"` + s + `"},"default_kid":"known"}`
	path := writeKeyringFile(t, dir, content)

	ring, _ := LoadFile(path)
	_, err := ring.Resolve("unknown-kid")
	if err == nil {
		t.Fatal("expected ErrUnknownKid")
	}
}

func TestResolveNoDefaultErrors(t *testing.T) {
	dir := t.TempDir()
	s := base64.StdEncoding.EncodeToString([]byte("x"))
	content := `{"keys":{"k1":"` + s + `"}}`
	path := writeKeyringFile(t, dir, content)

	ring, _ := LoadFile(path)
	_, err := ring.Resolve("") // no default configured
	if err == nil {
		t.Fatal("expected ErrNoDefault")
	}
}

func TestLoadEmptyKeysErrors(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyringFile(t, dir, `{"keys":{}}`)
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected ErrEmptyRing")
	}
}

func TestLoadBadDefaultKidErrors(t *testing.T) {
	dir := t.TempDir()
	s := base64.StdEncoding.EncodeToString([]byte("x"))
	content := `{"keys":{"k1":"` + s + `"},"default_kid":"nonexistent"}`
	path := writeKeyringFile(t, dir, content)

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid default_kid")
	}
}

func TestSaveAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ring.json")

	ring := &Ring{
		keys:       map[string][]byte{"kid-a": []byte("secret-a"), "kid-b": []byte("secret-b")},
		defaultKid: "kid-a",
	}
	if err := ring.SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}

	ring2, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if ring2.Len() != 2 {
		t.Errorf("Len = %d, want 2", ring2.Len())
	}
	got, _ := ring2.Resolve("kid-b")
	if string(got) != "secret-b" {
		t.Errorf("kid-b secret = %q", got)
	}
}

func TestAddRemoveKey(t *testing.T) {
	s := base64.StdEncoding.EncodeToString([]byte("x"))
	ring, _ := Parse([]byte(`{"keys":{"k1":"` + s + `"},"default_kid":"k1"}`))

	ring.AddKey("k2", []byte("new-secret"))
	if ring.Len() != 2 {
		t.Errorf("Len after add = %d, want 2", ring.Len())
	}
	if !ring.HasKid("k2") {
		t.Error("should have k2")
	}

	ring.RemoveKey("k1")
	if ring.HasKid("k1") {
		t.Error("k1 should be removed")
	}
	if ring.DefaultKid() != "" {
		t.Error("default should be cleared when default kid is removed")
	}
}

func TestKids(t *testing.T) {
	s := base64.StdEncoding.EncodeToString([]byte("x"))
	ring, _ := Parse([]byte(`{"keys":{"a":"` + s + `","b":"` + s + `","c":"` + s + `"}}`))

	kids := ring.Kids()
	if len(kids) != 3 {
		t.Errorf("Kids len = %d, want 3", len(kids))
	}
}

func TestSetDefault(t *testing.T) {
	s := base64.StdEncoding.EncodeToString([]byte("x"))
	ring, _ := Parse([]byte(`{"keys":{"a":"` + s + `","b":"` + s + `"}}`))

	if err := ring.SetDefault("a"); err != nil {
		t.Fatal(err)
	}
	if ring.DefaultKid() != "a" {
		t.Error("default should be a")
	}
	if err := ring.SetDefault("missing"); err == nil {
		t.Error("SetDefault for missing kid should error")
	}
}

func TestLoadNonExistent(t *testing.T) {
	_, err := LoadFile("/nonexistent/path/keys.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeKeyringFile(t, dir, "not json")
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
