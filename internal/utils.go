package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

// GenerateRandomAndroidSerial generates a random 8-byte Android-like device identifier
// and returns it as a hexadecimal string.
//
// Returns:
//   - string: A randomly generated 16-character hexadecimal serial number.
//   - error:  An error if random data generation fails.
func GenerateRandomAndroidSerial() (string, error) {
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return "", err
	}
	return hex.EncodeToString(serial), nil
}

// GenerateRandomWgPubkey generates a random 32-byte WireGuard like public key
// and returns it as a base64-encoded string.
//
// Returns:
//   - string: A randomly generated WireGuard like public key in base64 format.
//   - error:  An error if random data generation fails.
func GenerateRandomWgPubkey() (string, error) {
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

// TimeAsCfString formats a given time.Time into a Cloudflare-compatible string format.
//
// The format follows the standard: "YYYY-MM-DDTHH:MM:SS.sss-07:00".
//
// Parameters:
//   - t: time.Time to format.
//
// Returns:
//   - string: The formatted time string.
func TimeAsCfString(t time.Time) string {
	return t.Format("2006-01-02T15:04:05.000-07:00")
}

// GenerateEcKeyPair generates a new ECDSA key pair using the P-256 curve.
//
// Returns:
//   - []byte: The marshalled private key in ASN.1 DER format.
//   - []byte: The marshalled public key in PKIX format.
//   - error:  An error if key generation or marshalling fails.
func GenerateEcKeyPair() ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	marshalledPrivKey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	marshalledPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return marshalledPrivKey, marshalledPubKey, nil
}

// GenerateCert creates a self-signed certificate using the provided ECDSA private and public keys.
//
// The certificate is valid for 24 hours.
//
// Parameters:
//   - privKey: *ecdsa.PrivateKey - The private key to sign the certificate.
//   - pubKey: *ecdsa.PublicKey - The public key to include in the certificate.
//
// Returns:
//   - [][]byte: A slice containing the certificate in DER format.
//   - error:    An error if certificate generation fails.
func GenerateCert(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([][]byte, error) {
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 24 * time.Hour),
	}, &x509.Certificate{}, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return [][]byte{cert}, nil
}

// DefaultQuicConfig returns a MASQUE compatible default QUIC configuration with specified keep-alive period and initial packet size.
//
// Parameters:
//   - keepalivePeriod: time.Duration - The duration for sending QUIC keep-alive packets.
//   - initialPacketSize: uint16 - The initial size of QUIC packets. (1242 seems used by the original implementation)
//
// Returns:
//   - *quic.Config: A pointer to a configured QUIC configuration object.
func DefaultQuicConfig(keepalivePeriod time.Duration, initialPacketSize uint16) *quic.Config {
	return &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: initialPacketSize,
		KeepAlivePeriod:   keepalivePeriod,
	}
}
