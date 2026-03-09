package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/models"
)

// RegisterWireGuardDevice creates a standalone WireGuard-compatible device using the provided public key.
func RegisterWireGuardDevice(publicKey, model, jwt string) (models.AccountData, error) {
	if strings.TrimSpace(publicKey) == "" {
		return models.AccountData{}, fmt.Errorf("public key is required")
	}
	if strings.TrimSpace(model) == "" {
		model = internal.DefaultModel
	}

	serial, err := internal.GenerateRandomAndroidSerial()
	if err != nil {
		return models.AccountData{}, fmt.Errorf("generate serial: %w", err)
	}

	payload := models.Registration{
		Key:       publicKey,
		InstallID: "",
		FcmToken:  "",
		Tos:       internal.TimeAsCfString(time.Now()),
		Model:     model,
		Serial:    serial,
		OsVersion: "",
		KeyType:   internal.KeyTypeWg,
		TunType:   internal.TunTypeWg,
		Locale:    internal.DefaultLocale,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("marshal register request: %w", err)
	}

	req, err := http.NewRequest("POST", cloudflareAPIBaseURL+"/"+internal.ApiVersion+"/reg", bytes.NewBuffer(jsonData))
	if err != nil {
		return models.AccountData{}, fmt.Errorf("create register request: %w", err)
	}
	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	if strings.TrimSpace(jwt) != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}

	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("send register request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("read register response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(body)
		if apiErr != nil {
			return models.AccountData{}, fmt.Errorf("register wireguard device: %s (%s)", resp.Status, apiErr.ErrorsAsString("; "))
		}
		return models.AccountData{}, fmt.Errorf("register wireguard device: %s", resp.Status)
	}

	var account models.AccountData
	if err := json.Unmarshal(body, &account); err != nil {
		return models.AccountData{}, fmt.Errorf("decode register response: %w", err)
	}
	return account, nil
}

// GetWireGuardSourceDevice fetches the current source device configuration for profile generation.
func GetWireGuardSourceDevice(deviceID, accessToken string) (models.AccountData, error) {
	req, err := http.NewRequest("GET", cloudflareAPIBaseURL+"/"+internal.ApiVersion+"/reg/"+deviceID, nil)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("create source device request: %w", err)
	}
	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("send source device request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("read source device response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(body)
		if apiErr != nil {
			return models.AccountData{}, fmt.Errorf("fetch source device: %s (%s)", resp.Status, apiErr.ErrorsAsString("; "))
		}
		return models.AccountData{}, fmt.Errorf("fetch source device: %s", resp.Status)
	}

	var device models.AccountData
	if err := json.Unmarshal(body, &device); err != nil {
		return models.AccountData{}, fmt.Errorf("decode source device response: %w", err)
	}
	return device, nil
}

// SetWireGuardDeviceName updates the source device display name.
func SetWireGuardDeviceName(deviceID, accessToken, deviceName string) error {
	payload := struct {
		Name string `json:"name"`
	}{
		Name: deviceName,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal device name request: %w", err)
	}

	req, err := http.NewRequest("PATCH", cloudflareAPIBaseURL+"/"+internal.ApiVersion+"/reg/"+deviceID+"/account/reg/"+deviceID, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("create device name request: %w", err)
	}
	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send device name request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read device name response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := parseAPIError(body)
		if apiErr != nil {
			return fmt.Errorf("set device name: %s (%s)", resp.Status, apiErr.ErrorsAsString("; "))
		}
		return fmt.Errorf("set device name: %s", resp.Status)
	}
	return nil
}
