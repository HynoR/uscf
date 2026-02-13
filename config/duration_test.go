package config

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDuration_UnmarshalJSON_string(t *testing.T) {
	tests := []struct {
		name string
		json string
		want time.Duration
	}{
		{"2s", `"2s"`, 2 * time.Second},
		{"5m", `"5m"`, 5 * time.Minute},
		{"1h", `"1h"`, time.Hour},
		{"100ms", `"100ms"`, 100 * time.Millisecond},
		{"1h30m", `"1h30m"`, 90 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			if err := json.Unmarshal([]byte(tt.json), &d); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}
			if got := d.Duration(); got != tt.want {
				t.Errorf("Duration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDuration_UnmarshalJSON_number(t *testing.T) {
	// 2000000000 ns = 2s (backward compat)
	var d Duration
	if err := json.Unmarshal([]byte("2000000000"), &d); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got := d.Duration(); got != 2*time.Second {
		t.Errorf("Duration() = %v, want 2s", got)
	}
}

func TestDuration_MarshalJSON(t *testing.T) {
	d := Duration(2 * time.Second)
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	// Should be human-readable string
	if got := string(data); got != `"2s"` {
		t.Errorf("MarshalJSON() = %v, want \"2s\"", got)
	}
}

func TestDuration_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := Duration(5 * time.Minute)
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	var got Duration
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Duration() != orig.Duration() {
		t.Errorf("round-trip: got %v, want %v", got.Duration(), orig.Duration())
	}
}

func TestDuration_UnmarshalJSON_invalid(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"invalid"`), &d); err == nil {
		t.Error("UnmarshalJSON() expected error for invalid string")
	}
	if err := json.Unmarshal([]byte(`true`), &d); err == nil {
		t.Error("UnmarshalJSON() expected error for non-string/non-number")
	}
}
