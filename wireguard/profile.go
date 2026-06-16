package wireguard

import (
	"bytes"
	"fmt"
	"os"
	"text/template"
)

var profileTemplate = `[Interface]
PrivateKey = {{ .PrivateKey }}
Address = {{ .Address1 }}/32, {{ .Address2 }}/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280
[Peer]
PublicKey = {{ .PublicKey }}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{ .Endpoint }}
PersistentKeepalive = 25
`

type Profile struct {
	profileString string
}

type ProfileData struct {
	PrivateKey string
	Address1   string
	Address2   string
	PublicKey  string
	Endpoint   string
}

func NewProfile(data *ProfileData) (*Profile, error) {
	profileString, err := generateProfile(data)
	if err != nil {
		return nil, err
	}
	return &Profile{profileString: profileString}, nil
}

func generateProfile(data *ProfileData) (string, error) {
	tmpl, err := template.New("wg-profile").Parse(profileTemplate)
	if err != nil {
		return "", fmt.Errorf("parse profile template: %w", err)
	}

	var result bytes.Buffer
	if err := tmpl.Execute(&result, data); err != nil {
		return "", fmt.Errorf("render profile template: %w", err)
	}

	return result.String(), nil
}

func (p *Profile) Save(profileFile string) error {
	if err := os.WriteFile(profileFile, []byte(p.profileString), 0o600); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}
	if err := os.Chmod(profileFile, 0o600); err != nil {
		return fmt.Errorf("chmod profile: %w", err)
	}
	return nil
}
