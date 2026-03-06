package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/HynoR/uscf/internal"
)

func TestRegisterWireGuardDeviceRequest(t *testing.T) {
	const publicKey = "wg-public-key"

	setupCloudflareTestClient(t, func(req *http.Request) (*http.Response, error) {
		expectedPath := fmt.Sprintf("/%s/reg", internal.ApiVersion)
		if req.URL.Path != expectedPath {
			t.Fatalf("unexpected path: got %s, want %s", req.URL.Path, expectedPath)
		}
		if req.Method != http.MethodPost {
			t.Fatalf("unexpected method: got %s, want POST", req.Method)
		}

		payload, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		var body map[string]any
		if err := json.Unmarshal(payload, &body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body["key"] != publicKey {
			t.Fatalf("request key = %v, want %q", body["key"], publicKey)
		}
		if body["model"] != "PC" {
			t.Fatalf("request model = %v, want %q", body["model"], "PC")
		}
		if body["key_type"] != internal.KeyTypeWg {
			t.Fatalf("request key_type = %v, want %q", body["key_type"], internal.KeyTypeWg)
		}
		if body["tunnel_type"] != internal.TunTypeWg {
			t.Fatalf("request tunnel_type = %v, want %q", body["tunnel_type"], internal.TunTypeWg)
		}

		return makeResponse(http.StatusOK, `{"id":"device-1","token":"token-1","account":{"license":"license-1"}}`), nil
	})

	account, err := RegisterWireGuardDevice(publicKey, "PC")
	if err != nil {
		t.Fatalf("RegisterWireGuardDevice() error = %v", err)
	}
	if account.ID != "device-1" || account.Token != "token-1" {
		t.Fatalf("unexpected account: %#v", account)
	}
}

func TestGetWireGuardSourceDeviceRequest(t *testing.T) {
	const (
		deviceID = "device-1"
		token    = "token-1"
	)

	setupCloudflareTestClient(t, func(req *http.Request) (*http.Response, error) {
		expectedPath := fmt.Sprintf("/%s/reg/%s", internal.ApiVersion, deviceID)
		if req.URL.Path != expectedPath {
			t.Fatalf("unexpected path: got %s, want %s", req.URL.Path, expectedPath)
		}
		if req.Method != http.MethodGet {
			t.Fatalf("unexpected method: got %s, want GET", req.Method)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("unexpected auth header: %q", got)
		}

		return makeResponse(http.StatusOK, `{"config":{"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::2"}},"peers":[{"public_key":"peer-public-key","endpoint":{"host":"engage.cloudflareclient.com:2408"}}]}}`), nil
	})

	device, err := GetWireGuardSourceDevice(deviceID, token)
	if err != nil {
		t.Fatalf("GetWireGuardSourceDevice() error = %v", err)
	}
	if len(device.Config.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(device.Config.Peers))
	}
	if device.Config.Peers[0].Endpoint.Host != "engage.cloudflareclient.com:2408" {
		t.Fatalf("unexpected endpoint host: %q", device.Config.Peers[0].Endpoint.Host)
	}
}

func TestSetWireGuardDeviceNameRequest(t *testing.T) {
	const (
		deviceID = "device-1"
		token    = "token-1"
		name     = "edge-node"
	)

	setupCloudflareTestClient(t, func(req *http.Request) (*http.Response, error) {
		expectedPath := fmt.Sprintf("/%s/reg/%s/account/reg/%s", internal.ApiVersion, deviceID, deviceID)
		if req.URL.Path != expectedPath {
			t.Fatalf("unexpected path: got %s, want %s", req.URL.Path, expectedPath)
		}
		if req.Method != http.MethodPatch {
			t.Fatalf("unexpected method: got %s, want PATCH", req.Method)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer "+token {
			t.Fatalf("unexpected auth header: %q", got)
		}

		payload, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if !strings.Contains(string(payload), `"name":"`+name+`"`) {
			t.Fatalf("unexpected payload: %s", string(payload))
		}

		return makeResponse(http.StatusOK, `[]`), nil
	})

	if err := SetWireGuardDeviceName(deviceID, token, name); err != nil {
		t.Fatalf("SetWireGuardDeviceName() error = %v", err)
	}
}
