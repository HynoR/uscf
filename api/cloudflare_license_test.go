package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/models"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func setupCloudflareTestClient(t *testing.T, fn roundTripFunc) {
	t.Helper()
	oldBaseURL := cloudflareAPIBaseURL
	oldClient := cloudflareHTTPClient

	cloudflareAPIBaseURL = "https://api.test.local"
	cloudflareHTTPClient = &http.Client{Transport: fn}

	t.Cleanup(func() {
		cloudflareAPIBaseURL = oldBaseURL
		cloudflareHTTPClient = oldClient
	})
}

func makeResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestGetAccountRequest(t *testing.T) {
	const (
		deviceID = "device-1"
		token    = "token-1"
		license  = "LICENSE-A"
	)

	setupCloudflareTestClient(t, func(req *http.Request) (*http.Response, error) {
		expectedPath := fmt.Sprintf("/%s/reg/%s/account", internal.ApiVersion, deviceID)
		if req.URL.Path != expectedPath {
			t.Fatalf("unexpected path: got %s, want %s", req.URL.Path, expectedPath)
		}
		if req.Method != http.MethodGet {
			t.Fatalf("unexpected method: got %s, want GET", req.Method)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("unexpected auth header: %q", got)
		}
		return makeResponse(http.StatusOK, `{"id":"account-id","account_type":"free","license":"`+license+`"}`), nil
	})

	account, apiErr, err := GetAccount(models.AccountData{
		ID:    deviceID,
		Token: token,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiErr != nil {
		t.Fatalf("unexpected apiErr: %+v", apiErr)
	}
	if account.License != license {
		t.Fatalf("unexpected license: got %q, want %q", account.License, license)
	}
}

func TestRebindLicenseSkipsPutWhenLicenseMatches(t *testing.T) {
	const license = "LICENSE-A"

	getCalls := 0
	putCalls := 0

	setupCloudflareTestClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			getCalls++
			return makeResponse(http.StatusOK, `{"license":"`+license+`"}`), nil
		case http.MethodPut:
			putCalls++
			return makeResponse(http.StatusInternalServerError, `{}`), nil
		default:
			return makeResponse(http.StatusMethodNotAllowed, `{}`), nil
		}
	})

	finalAccount, changed, apiErr, err := RebindLicense(models.AccountData{
		ID:    "device-1",
		Token: "token-1",
	}, license)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiErr != nil {
		t.Fatalf("unexpected apiErr: %+v", apiErr)
	}
	if changed {
		t.Fatalf("expected changed=false")
	}
	if putCalls != 0 {
		t.Fatalf("expected no PUT call, got %d", putCalls)
	}
	if getCalls != 1 {
		t.Fatalf("expected exactly 1 GET call, got %d", getCalls)
	}
	if finalAccount.License != license {
		t.Fatalf("unexpected final license: got %q, want %q", finalAccount.License, license)
	}
}

func TestRebindLicenseUsesPutAndRefetch(t *testing.T) {
	current := "OLD-LICENSE"
	putCalls := 0
	getCalls := 0

	setupCloudflareTestClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			getCalls++
			return makeResponse(http.StatusOK, `{"license":"`+current+`"}`), nil
		case http.MethodPut:
			putCalls++
			payload, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("failed reading PUT body: %v", err)
			}
			if !strings.Contains(string(payload), `"license":"NEW-LICENSE"`) {
				t.Fatalf("unexpected PUT payload: %s", string(payload))
			}
			current = "NEW-LICENSE"
			return makeResponse(http.StatusOK, `{"updated":"now"}`), nil
		default:
			return makeResponse(http.StatusMethodNotAllowed, `{}`), nil
		}
	})

	finalAccount, changed, apiErr, err := RebindLicense(models.AccountData{
		ID:    "device-1",
		Token: "token-1",
	}, "NEW-LICENSE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiErr != nil {
		t.Fatalf("unexpected apiErr: %+v", apiErr)
	}
	if !changed {
		t.Fatalf("expected changed=true")
	}
	if putCalls != 1 {
		t.Fatalf("expected 1 PUT call, got %d", putCalls)
	}
	if getCalls != 2 {
		t.Fatalf("expected 2 GET calls, got %d", getCalls)
	}
	if finalAccount.License != "NEW-LICENSE" {
		t.Fatalf("unexpected final license: got %q", finalAccount.License)
	}
}

func TestRebindLicensePutFailureWithAPIError(t *testing.T) {
	setupCloudflareTestClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			return makeResponse(http.StatusOK, `{"license":"OLD"}`), nil
		case http.MethodPut:
			return makeResponse(http.StatusBadRequest, `{"success":false,"errors":[{"code":1000,"message":"invalid license"}]}`), nil
		default:
			return makeResponse(http.StatusMethodNotAllowed, `{}`), nil
		}
	})

	_, _, apiErr, err := RebindLicense(models.AccountData{
		ID:    "device-1",
		Token: "token-1",
	}, "NEW")
	if err == nil {
		t.Fatalf("expected error")
	}
	if apiErr == nil {
		t.Fatalf("expected apiErr")
	}
	if len(apiErr.Errors) == 0 || apiErr.Errors[0].Message != "invalid license" {
		t.Fatalf("unexpected apiErr content: %+v", apiErr)
	}
}

func TestRebindLicensePutFailureWithoutAPIErrorBody(t *testing.T) {
	setupCloudflareTestClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			return makeResponse(http.StatusOK, `{"license":"OLD"}`), nil
		case http.MethodPut:
			return makeResponse(http.StatusMethodNotAllowed, `method not allowed`), nil
		default:
			return makeResponse(http.StatusMethodNotAllowed, `{}`), nil
		}
	})

	_, _, apiErr, err := RebindLicense(models.AccountData{
		ID:    "device-1",
		Token: "token-1",
	}, "NEW")
	if err == nil {
		t.Fatalf("expected error")
	}
	if apiErr != nil {
		t.Fatalf("expected apiErr=nil, got %+v", apiErr)
	}
	if !strings.Contains(err.Error(), "405") {
		t.Fatalf("expected status in error, got: %v", err)
	}
}
