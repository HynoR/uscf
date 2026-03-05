package cmd

import (
	"strings"
	"testing"
)

func TestNormalizeDeviceName(t *testing.T) {
	got := normalizeDeviceName("  My__VM@@Node ###  ")
	if got == "" {
		t.Fatalf("expected non-empty normalized name")
	}
	if len(got) > maxDeviceNameLen {
		t.Fatalf("expected len <= %d, got %d (%q)", maxDeviceNameLen, len(got), got)
	}
	for _, r := range got {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			t.Fatalf("unexpected char %q in %q", r, got)
		}
	}
}

func TestBuildAutoDeviceNameContainsModeAndIDSuffix(t *testing.T) {
	gotPremium := buildAutoDeviceName(accountModePremium, "devbox", "acc-a1b2")
	if !strings.HasPrefix(gotPremium, "p-") {
		t.Fatalf("expected premium prefix, got %q", gotPremium)
	}
	if !strings.HasSuffix(gotPremium, "a1b2") {
		t.Fatalf("expected id suffix a1b2, got %q", gotPremium)
	}
	if len(gotPremium) > maxDeviceNameLen {
		t.Fatalf("expected len <= %d, got %d (%q)", maxDeviceNameLen, len(gotPremium), gotPremium)
	}

	gotTeam := buildAutoDeviceName(accountModeTeam, "node", "xyz9f0c")
	if !strings.HasPrefix(gotTeam, "t-") {
		t.Fatalf("expected team prefix, got %q", gotTeam)
	}
	if !strings.HasSuffix(gotTeam, "9f0c") {
		t.Fatalf("expected id suffix 9f0c, got %q", gotTeam)
	}
	if len(gotTeam) > maxDeviceNameLen {
		t.Fatalf("expected len <= %d, got %d (%q)", maxDeviceNameLen, len(gotTeam), gotTeam)
	}
}

func TestBuildAutoDeviceNameSameHostDifferentIDDifferentNames(t *testing.T) {
	a := buildAutoDeviceName(accountModePremium, "samehost", "vm-1111")
	b := buildAutoDeviceName(accountModePremium, "samehost", "vm-2222")
	if a == b {
		t.Fatalf("expected different names for different account ids, got same=%q", a)
	}
}

func TestBuildAutoDeviceNameFallbackWhenHostnameInvalid(t *testing.T) {
	got := buildAutoDeviceName(accountModeTeam, "___", "abcd")
	if !strings.HasPrefix(got, "t-") {
		t.Fatalf("expected team prefix, got %q", got)
	}
	if !strings.Contains(got, "node") && !strings.Contains(got, "n-") {
		t.Fatalf("expected fallback host token in %q", got)
	}
}

func TestResolveRegistrationDeviceNameFreeUnchanged(t *testing.T) {
	raw := " Raw Name "
	got := resolveRegistrationDeviceName(accountModeFree, raw, "id1234")
	if got != raw {
		t.Fatalf("free mode should keep explicit name unchanged, got %q want %q", got, raw)
	}
}

func TestResolveRegistrationDeviceNameExplicitPriorityWithNormalization(t *testing.T) {
	got := resolveRegistrationDeviceName(accountModePremium, "My Fancy Device Name", "id1234")
	if got == "" {
		t.Fatalf("expected non-empty normalized explicit name")
	}
	if len(got) > maxDeviceNameLen {
		t.Fatalf("expected len <= %d, got %d (%q)", maxDeviceNameLen, len(got), got)
	}
	if strings.Contains(got, " ") {
		t.Fatalf("expected no spaces after normalization, got %q", got)
	}
}
