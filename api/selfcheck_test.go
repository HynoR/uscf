package api

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestSelfCheckObserveFailureThreshold(t *testing.T) {
	state := &selfCheckState{}

	for i := 0; i < 2; i++ {
		reconnect, _ := state.Observe(500, nil)
		if reconnect {
			t.Fatalf("should not reconnect before threshold, attempt=%d", i+1)
		}
	}

	reconnect, reason := state.Observe(500, nil)
	if !reconnect {
		t.Fatalf("expected reconnect on third consecutive failure")
	}
	if !strings.Contains(reason, "failed") {
		t.Fatalf("expected failure reason, got: %s", reason)
	}
}

func TestSelfCheckObserveTimeoutThreshold(t *testing.T) {
	state := &selfCheckState{}

	for i := 0; i < 2; i++ {
		reconnect, _ := state.Observe(0, context.DeadlineExceeded)
		if reconnect {
			t.Fatalf("should not reconnect before timeout threshold, attempt=%d", i+1)
		}
	}

	reconnect, reason := state.Observe(0, context.DeadlineExceeded)
	if !reconnect {
		t.Fatalf("expected reconnect on third consecutive timeout")
	}
	if !strings.Contains(reason, "timed out") {
		t.Fatalf("expected timeout reason, got: %s", reason)
	}
}

func TestSelfCheckObserveResetOn204(t *testing.T) {
	state := &selfCheckState{}

	state.Observe(500, nil)
	state.Observe(500, nil)

	reconnect, _ := state.Observe(204, nil)
	if reconnect {
		t.Fatalf("204 should not trigger reconnect")
	}
	if state.failStreak != 0 || state.timeoutStreak != 0 {
		t.Fatalf("expected streaks reset after 204, got fail=%d timeout=%d", state.failStreak, state.timeoutStreak)
	}

	reconnect, _ = state.Observe(500, nil)
	if reconnect {
		t.Fatalf("single failure after reset should not trigger reconnect")
	}
	if state.failStreak != 1 || state.timeoutStreak != 0 {
		t.Fatalf("expected fail=1 timeout=0 after one failure, got fail=%d timeout=%d", state.failStreak, state.timeoutStreak)
	}
}

func TestSelfCheckObserveMixedTimeoutBehavior(t *testing.T) {
	state := &selfCheckState{}

	state.Observe(0, context.DeadlineExceeded)
	state.Observe(204, nil)
	state.Observe(500, nil)
	reconnect, _ := state.Observe(0, context.DeadlineExceeded)

	if reconnect {
		t.Fatalf("mixed outcomes should not trigger reconnect in this sequence")
	}
	if state.timeoutStreak != 1 {
		t.Fatalf("expected timeout streak to be 1, got %d", state.timeoutStreak)
	}
}

func TestIsSelfCheckTimeout(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: true},
		{name: "net timeout", err: timeoutErr{}, want: true},
		{name: "url wrapped timeout", err: &url.Error{Err: context.DeadlineExceeded}, want: true},
		{name: "non-timeout", err: errors.New("boom"), want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := isSelfCheckTimeout(tc.err)
			if got != tc.want {
				t.Fatalf("isSelfCheckTimeout() = %v, want %v", got, tc.want)
			}
		})
	}
}
