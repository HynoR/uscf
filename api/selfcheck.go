package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"
)

const (
	selfCheckURL              = "http://www.gstatic.com/generate_204"
	selfCheckInterval         = 1 * time.Minute
	selfCheckTimeout          = 5 * time.Second
	selfCheckFailureThreshold = 3
	selfCheckTimeoutThreshold = 3
)

type selfCheckState struct {
	failStreak    int
	timeoutStreak int
}

func (s *selfCheckState) Observe(statusCode int, err error) (bool, string) {
	if err == nil && statusCode == http.StatusNoContent {
		s.failStreak = 0
		s.timeoutStreak = 0
		return false, ""
	}

	s.failStreak++
	if isSelfCheckTimeout(err) {
		s.timeoutStreak++
	} else {
		s.timeoutStreak = 0
	}

	if s.timeoutStreak >= selfCheckTimeoutThreshold {
		return true, fmt.Sprintf("timed out %d consecutive checks", selfCheckTimeoutThreshold)
	}
	if s.failStreak >= selfCheckFailureThreshold {
		return true, fmt.Sprintf("failed %d consecutive checks", selfCheckFailureThreshold)
	}
	return false, ""
}

func runSelfCheckLoop(ctx context.Context, dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)) error {
	if dialFunc == nil {
		return fmt.Errorf("self-check dial function is nil")
	}

	transport := &http.Transport{
		DialContext: dialFunc,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
	}

	ticker := time.NewTicker(selfCheckInterval)
	defer ticker.Stop()

	state := &selfCheckState{}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			statusCode, err := doSelfCheckRequest(ctx, client)
			if err != nil && errors.Is(err, context.Canceled) {
				return err
			}

			reconnect, reason := state.Observe(statusCode, err)
			if err != nil {
				slog.Debug(
					"self-check failed",
					"error", err,
					"status", statusCode,
					"fail_streak", state.failStreak,
					"timeout_streak", state.timeoutStreak,
				)
			} else if statusCode != http.StatusNoContent {
				slog.Debug(
					"self-check failed",
					"status", statusCode,
					"fail_streak", state.failStreak,
					"timeout_streak", state.timeoutStreak,
				)
			}

			if reconnect {
				slog.Warn("self-check threshold reached, reconnect required", "reason", reason)
				return fmt.Errorf("self-check %s", reason)
			}
		}
	}
}

func doSelfCheckRequest(parentCtx context.Context, client *http.Client) (int, error) {
	reqCtx, cancel := context.WithTimeout(parentCtx, selfCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, selfCheckURL, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		if parentCtx.Err() != nil {
			return 0, parentCtx.Err()
		}
		return 0, err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func isSelfCheckTimeout(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if errors.Is(urlErr.Err, context.DeadlineExceeded) {
			return true
		}
		if innerNetErr, ok := urlErr.Err.(net.Error); ok && innerNetErr.Timeout() {
			return true
		}
	}

	return false
}
