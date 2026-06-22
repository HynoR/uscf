package internal

const (
	ApiUrl     = "https://api.cloudflareclient.com"
	ApiVersion = "v0a4471"
	ConnectSNI = "consumer-masque.cloudflareclient.com"
	// L4ConnectSNI is the SNI for Cloudflare's MASQUE *proxy* endpoint used by L4
	// (HTTP/3 CONNECT-stream) mode. It is a different service from ConnectSNI
	// (the connect-ip/L3 tunnel) but reuses the same endpoint IPs and enrollment.
	L4ConnectSNI = "consumer-masque-proxy.cloudflareclient.com"
	// unused for now
	ZeroTierSNI   = "zt-masque.cloudflareclient.com"
	ConnectURI    = "https://cloudflareaccess.com"
	DefaultModel  = "PC"
	KeyTypeWg     = "curve25519"
	TunTypeWg     = "wireguard"
	KeyTypeMasque = "secp256r1"
	TunTypeMasque = "masque"
	DefaultLocale = "en_US"
)

var Headers = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
	"Connection":        "Keep-Alive",
}
