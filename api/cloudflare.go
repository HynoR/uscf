package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/models"
)

// Register creates a new user account by registering a WireGuard public key and generating a random Android-like device identifier.
// The WireGuard private key isn't stored anywhere, therefore it won't be usable. It's sole purpose is to mimic the Android app's registration process.
//
// This function sends a POST request to the API to register a new user and returns the created account data.
//
// Parameters:
//   - model: string - The device model string to register. (e.g., "PC")
//   - locale: string - The user's locale. (e.g., "en-US")
//   - jwt: string - Team token to register.
//   - acceptTos: bool - Whether the user accepts the Terms of Service (TOS). If false, the user will be prompted to accept.
//
// Returns:
//   - models.AccountData: The account data returned from the registration process.
//   - error:              An error if registration fails at any step.
//
// Example:
//
//	account, err := Register("PC", "en-US", "", false)
//	if err != nil {
//	    log.Fatalf("Registration failed: %v", err)
//	}
func Register(model, locale, jwt string, acceptTos bool) (models.AccountData, error) {
	wgKey, err := internal.GenerateRandomWgPubkey()
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to generate wg key: %v", err)
	}
	serial, err := internal.GenerateRandomAndroidSerial()
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to generate serial: %v", err)
	}

	if !acceptTos {
		fmt.Print("You must accept the Terms of Service (https://www.cloudflare.com/application/terms/) to register. Do you agree? (y/n): ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return models.AccountData{}, fmt.Errorf("failed to read user input: %v", err)
		}
		if response != "y" {
			return models.AccountData{}, fmt.Errorf("user did not accept TOS")
		}
	}

	data := models.Registration{
		Key:       wgKey,
		InstallID: "",
		FcmToken:  "",
		Tos:       internal.TimeAsCfString(time.Now()),
		Model:     model,
		Serial:    serial,
		OsVersion: "",
		KeyType:   internal.KeyTypeWg,
		TunType:   internal.TunTypeWg,
		Locale:    locale,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest("POST", internal.ApiUrl+"/"+internal.ApiVersion+"/reg", bytes.NewBuffer(jsonData))
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}

	if jwt != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return models.AccountData{}, fmt.Errorf("failed to register: %v", resp.Status)
	}

	var accountData models.AccountData
	if err := json.NewDecoder(resp.Body).Decode(&accountData); err != nil {
		return models.AccountData{}, fmt.Errorf("failed to decode response: %v", err)
	}

	return accountData, nil
}

// EnrollKey updates an existing user account with a new MASQUE public key.
//
// This function sends a PATCH request to update the user's account with a new key.
//
// Parameters:
//   - accountData: models.AccountData - The account data of the user being updated.
//   - pubKey: []byte - The new MASQUE public key in binary format.
//   - deviceName: string - The name of the device to enroll. (optional)
//
// Returns:
//   - models.AccountData: The updated account data.
//   - error:              An error if the update process fails.
//
// Example:
//
//	updatedAccount, apiErr, err := EnrollKey(account, pubKey, "PC")
//	if err != nil {
//	    log.Fatalf("Key enrollment failed: %v", err)
//	}
func EnrollKey(accountData models.AccountData, pubKey []byte, deviceName string) (models.AccountData, *models.APIError, error) {
	deviceUpdate := models.DeviceUpdate{
		Key:     base64.StdEncoding.EncodeToString(pubKey),
		KeyType: internal.KeyTypeMasque,
		TunType: internal.TunTypeMasque,
	}

	if deviceName != "" {
		deviceUpdate.Name = deviceName
	}

	jsonData, err := json.Marshal(deviceUpdate)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest("PATCH", internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+accountData.ID, bytes.NewBuffer(jsonData))
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountData.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return models.AccountData{}, nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return models.AccountData{}, &apiErr, fmt.Errorf("failed to update: %s", resp.Status)
	}

	if err := json.Unmarshal(body, &accountData); err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return accountData, nil, nil
}

// ApplyLicense updates the Cloudflare account with a user-provided WARP+ license.
//
// Parameters:
//   - accountData: models.AccountData - Must contain ID and Token.
//   - license: string - WARP+ license key.
//
// Returns:
//   - models.AccountData: Updated account data from API.
//   - *models.APIError: Parsed API error when status code is non-2xx.
//   - error: Transport/parsing error.
func ApplyLicense(accountData models.AccountData, license string) (models.AccountData, *models.APIError, error) {
	payload := struct {
		License string `json:"license"`
	}{
		License: license,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest(
		"PATCH",
		internal.ApiUrl+"/"+internal.ApiVersion+"/reg/"+accountData.ID+"/account",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountData.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr models.APIError
		if err := json.Unmarshal(body, &apiErr); err != nil {
			return models.AccountData{}, nil, fmt.Errorf("failed to parse error response: %v", err)
		}
		return models.AccountData{}, &apiErr, fmt.Errorf("failed to apply license: %s", resp.Status)
	}

	var updatedAccount models.AccountData
	if err := json.Unmarshal(body, &updatedAccount); err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// Token is usually only returned by /reg.
	if updatedAccount.Token == "" {
		updatedAccount.Token = accountData.Token
	}
	if updatedAccount.ID == "" {
		updatedAccount.ID = accountData.ID
	}

	return updatedAccount, nil, nil
}
