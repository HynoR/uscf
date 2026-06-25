package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/HynoR/uscf/internal"
	"github.com/HynoR/uscf/models"
)

var (
	cloudflareAPIBaseURL = internal.ApiUrl
	cloudflareHTTPClient = http.DefaultClient
)

func parseAPIError(body []byte) *models.APIError {
	var apiErr models.APIError
	if err := json.Unmarshal(body, &apiErr); err != nil {
		return nil
	}
	if len(apiErr.Errors) == 0 && len(apiErr.Messages) == 0 && apiErr.Result == nil {
		return nil
	}
	return &apiErr
}

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

	req, err := http.NewRequest("POST", cloudflareAPIBaseURL+"/"+internal.ApiVersion+"/reg", bytes.NewBuffer(jsonData))
	if err != nil {
		return models.AccountData{}, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}

	if jwt != "" {
		req.Header.Set("CF-Access-Jwt-Assertion", jwt)
	}

	resp, err := cloudflareHTTPClient.Do(req)
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

	req, err := http.NewRequest("PATCH", cloudflareAPIBaseURL+"/"+internal.ApiVersion+"/reg/"+accountData.ID, bytes.NewBuffer(jsonData))
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountData.Token)

	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		apiErr := parseAPIError(body)
		if apiErr != nil {
			return models.AccountData{}, apiErr, fmt.Errorf("failed to update: %s", resp.Status)
		}
		return models.AccountData{}, nil, fmt.Errorf("failed to update: %s", resp.Status)
	}

	if err := json.Unmarshal(body, &accountData); err != nil {
		return models.AccountData{}, nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return accountData, nil, nil
}

// GetAccount fetches account information for the current source device.
func GetAccount(accountData models.AccountData) (models.Account, *models.APIError, error) {
	req, err := http.NewRequest(
		"GET",
		cloudflareAPIBaseURL+"/"+internal.ApiVersion+"/reg/"+accountData.ID+"/account",
		nil,
	)
	if err != nil {
		return models.Account{}, nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountData.Token)

	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return models.Account{}, nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.Account{}, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := parseAPIError(body)
		if apiErr != nil {
			return models.Account{}, apiErr, fmt.Errorf("failed to fetch account: %s", resp.Status)
		}
		return models.Account{}, nil, fmt.Errorf("failed to fetch account: %s", resp.Status)
	}

	var account models.Account
	if err := json.Unmarshal(body, &account); err != nil {
		return models.Account{}, nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return account, nil, nil
}

func updateAccountLicensePut(accountData models.AccountData, license string) (*models.APIError, error) {
	payload := struct {
		License string `json:"license"`
	}{
		License: license,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %v", err)
	}

	req, err := http.NewRequest(
		"PUT",
		cloudflareAPIBaseURL+"/"+internal.ApiVersion+"/reg/"+accountData.ID+"/account",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	for k, v := range internal.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", "Bearer "+accountData.Token)

	resp, err := cloudflareHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := parseAPIError(body)
		if apiErr != nil {
			return apiErr, fmt.Errorf("failed to apply license: %s", resp.Status)
		}
		return nil, fmt.Errorf("failed to apply license: %s", resp.Status)
	}

	return nil, nil
}

// RebindLicense updates account license with wgcf-compatible flow:
// GetAccount -> optional PUT UpdateAccount -> GetAccount.
func RebindLicense(accountData models.AccountData, target string) (models.Account, bool, *models.APIError, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return models.Account{}, false, nil, fmt.Errorf("target license is empty")
	}

	current, apiErr, err := GetAccount(accountData)
	if err != nil {
		return models.Account{}, false, apiErr, err
	}
	if current.License == target {
		return current, false, nil, nil
	}

	apiErr, err = updateAccountLicensePut(accountData, target)
	if err != nil {
		return models.Account{}, false, apiErr, err
	}

	finalAccount, apiErr, err := GetAccount(accountData)
	if err != nil {
		return models.Account{}, false, apiErr, err
	}

	return finalAccount, true, nil, nil
}
