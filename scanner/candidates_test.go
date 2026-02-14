package scanner

import (
	"math/rand"
	"testing"
)

func TestGenerateCandidatesV4SinglePoint(t *testing.T) {
	got, err := GenerateCandidates([]string{"162.159.198.1/32"}, 443, IPFamilyV4, 64, rand.New(rand.NewSource(1)))
	if err != nil {
		t.Fatalf("GenerateCandidates() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(got))
	}
	if got[0] != "162.159.198.1:443" {
		t.Fatalf("unexpected candidate: %s", got[0])
	}
}

func TestGenerateCandidatesV6SinglePoint(t *testing.T) {
	got, err := GenerateCandidates([]string{"2606:4700:103::1/128"}, 443, IPFamilyV6, 64, rand.New(rand.NewSource(1)))
	if err != nil {
		t.Fatalf("GenerateCandidates() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(got))
	}
	if got[0] != "[2606:4700:103::1]:443" {
		t.Fatalf("unexpected candidate: %s", got[0])
	}
}

func TestGenerateCandidatesFamilyFilter(t *testing.T) {
	got, err := GenerateCandidates([]string{"162.159.198.1/32", "2606:4700:103::1/128"}, 443, IPFamilyV4, 64, rand.New(rand.NewSource(2)))
	if err != nil {
		t.Fatalf("GenerateCandidates() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate for v4 family, got %d", len(got))
	}
	if got[0] != "162.159.198.1:443" {
		t.Fatalf("unexpected v4 candidate: %s", got[0])
	}
}
