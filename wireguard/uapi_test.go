package wireguard

import (
	"strings"
	"testing"
)

func TestKeyHexStringMatchesBase64Decode(t *testing.T) {
	var k Key
	for i := range k {
		k[i] = byte(i)
	}
	const want = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if got := k.HexString(); got != want {
		t.Fatalf("HexString() = %q, want %q", got, want)
	}
}

func TestKeyHexStringRoundTripsBase64(t *testing.T) {
	// A key parsed from base64 (the on-disk form) must hex-encode to the same
	// bytes — this is the base64->hex bridge the UAPI builder relies on.
	priv, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}
	reparsed, err := NewKey(priv.String())
	if err != nil {
		t.Fatalf("NewKey(base64) error = %v", err)
	}
	if priv.HexString() != reparsed.HexString() {
		t.Fatalf("hex mismatch after base64 round trip: %q vs %q", priv.HexString(), reparsed.HexString())
	}
	if len(priv.HexString()) != KeyLength*2 {
		t.Fatalf("hex length = %d, want %d", len(priv.HexString()), KeyLength*2)
	}
}

func TestBuildUAPIConfig(t *testing.T) {
	priv, _ := NewPrivateKey()
	peer, _ := NewPrivateKey()
	peerPub := peer.Public()

	out, err := BuildUAPIConfig(UAPIParams{
		PrivateKey:          priv,
		PublicKey:           peerPub,
		Endpoint:            "162.159.192.1:2408",
		PersistentKeepalive: 25,
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		ListenPort:          51820,
	})
	if err != nil {
		t.Fatalf("BuildUAPIConfig() error = %v", err)
	}

	wantLines := []string{
		"private_key=" + priv.HexString(),
		"listen_port=51820",
		"replace_peers=true",
		"public_key=" + peerPub.HexString(),
		"endpoint=162.159.192.1:2408",
		"persistent_keepalive_interval=25",
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
	}
	for _, line := range wantLines {
		if !strings.Contains(out, line+"\n") {
			t.Fatalf("uapi missing line %q in:\n%s", line, out)
		}
	}

	// replace_peers must precede the peer's public_key, and public_key must
	// precede its endpoint/allowed_ip block.
	if idx := strings.Index(out, "replace_peers=true"); idx < 0 || idx > strings.Index(out, "public_key=") {
		t.Fatalf("replace_peers must come before public_key:\n%s", out)
	}
	if strings.Index(out, "public_key=") > strings.Index(out, "endpoint=") {
		t.Fatalf("public_key must come before endpoint:\n%s", out)
	}
}

func TestBuildUAPIConfigDefaultsAllowedIPs(t *testing.T) {
	priv, _ := NewPrivateKey()
	peer, _ := NewPrivateKey()

	out, err := BuildUAPIConfig(UAPIParams{
		PrivateKey: priv,
		PublicKey:  peer.Public(),
		Endpoint:   "1.2.3.4:2408",
	})
	if err != nil {
		t.Fatalf("BuildUAPIConfig() error = %v", err)
	}
	if !strings.Contains(out, "allowed_ip=0.0.0.0/0\n") || !strings.Contains(out, "allowed_ip=::/0\n") {
		t.Fatalf("expected default full-tunnel allowed ips, got:\n%s", out)
	}
	// ListenPort 0 must be omitted (random port), keepalive 0 must be omitted.
	if strings.Contains(out, "listen_port=") {
		t.Fatalf("listen_port should be omitted when 0:\n%s", out)
	}
	if strings.Contains(out, "persistent_keepalive_interval=") {
		t.Fatalf("keepalive should be omitted when 0:\n%s", out)
	}
}

func TestBuildUAPIConfigRejectsHostnameEndpoint(t *testing.T) {
	priv, _ := NewPrivateKey()
	peer, _ := NewPrivateKey()

	_, err := BuildUAPIConfig(UAPIParams{
		PrivateKey: priv,
		PublicKey:  peer.Public(),
		Endpoint:   "engage.cloudflareclient.com:2408",
	})
	if err == nil {
		t.Fatal("expected error for hostname endpoint, got nil")
	}
}

func TestBuildUAPIConfigErrors(t *testing.T) {
	priv, _ := NewPrivateKey()
	peer, _ := NewPrivateKey()
	good := UAPIParams{PrivateKey: priv, PublicKey: peer.Public(), Endpoint: "1.2.3.4:2408"}

	cases := map[string]func(p UAPIParams) UAPIParams{
		"nil private key": func(p UAPIParams) UAPIParams { p.PrivateKey = nil; return p },
		"nil public key":  func(p UAPIParams) UAPIParams { p.PublicKey = nil; return p },
		"empty endpoint":  func(p UAPIParams) UAPIParams { p.Endpoint = ""; return p },
		"bad allowed ip":  func(p UAPIParams) UAPIParams { p.AllowedIPs = []string{"not-a-cidr"}; return p },
		"bad listen port": func(p UAPIParams) UAPIParams { p.ListenPort = 70000; return p },
		"bad keepalive":   func(p UAPIParams) UAPIParams { p.PersistentKeepalive = -5; return p },
	}
	for name, mutate := range cases {
		if _, err := BuildUAPIConfig(mutate(good)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
