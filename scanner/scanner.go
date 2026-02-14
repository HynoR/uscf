package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

type Result struct {
	Endpoint  string
	OK        bool
	Err       string
	Elapsed   time.Duration
	Transport string // "quic" or "tcp-tls"
}

type ProbeFunc func(ctx context.Context, endpoint string, o Options) error

type Options struct {
	PerIPTimeout time.Duration
	UseQUIC      bool
	TLSConfig    *tls.Config
	QUICConfig   *quic.Config
	Probe        ProbeFunc
	Rand         *rand.Rand
}

type Option func(*Options)

func WithPerIPTimeout(d time.Duration) Option { return func(o *Options) { o.PerIPTimeout = d } }
func WithQUIC(enabled bool) Option            { return func(o *Options) { o.UseQUIC = enabled } }
func WithTLSConfig(c *tls.Config) Option      { return func(o *Options) { o.TLSConfig = c } }
func WithQUICConfig(c *quic.Config) Option    { return func(o *Options) { o.QUICConfig = c } }
func WithProbe(probe ProbeFunc) Option        { return func(o *Options) { o.Probe = probe } }
func WithRand(r *rand.Rand) Option            { return func(o *Options) { o.Rand = r } }

func isHandshakeErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "handshake") ||
		strings.Contains(s, "crypto_error") ||
		strings.Contains(s, "tls: handshake") ||
		strings.Contains(s, "remote error") ||
		strings.Contains(s, "quic:") ||
		strings.Contains(s, "alert") ||
		strings.Contains(s, "bad certificate")
}

func ScanEndpoints(endpoints []string, opts ...Option) []Result {
	o := Options{
		PerIPTimeout: DefaultScanPerIPTimeout,
		UseQUIC:      true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true, // scan only
			NextProtos:         []string{"h3", "h3-29", "h3-32", "h3-34"},
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: DefaultScanPerIPTimeout,
			MaxIdleTimeout:       DefaultScanPerIPTimeout,
			KeepAlivePeriod:      0,
		},
		Probe: defaultProbe,
		Rand:  rand.New(rand.NewSource(rand.Int63())),
	}

	for _, f := range opts {
		f(&o)
	}
	if o.PerIPTimeout <= 0 {
		o.PerIPTimeout = DefaultScanPerIPTimeout
	}
	if o.QUICConfig != nil {
		o.QUICConfig.HandshakeIdleTimeout = o.PerIPTimeout
		o.QUICConfig.MaxIdleTimeout = o.PerIPTimeout
	}
	if o.Probe == nil {
		o.Probe = defaultProbe
	}
	if o.Rand == nil {
		o.Rand = rand.New(rand.NewSource(rand.Int63()))
	}

	results := make([]Result, 0, len(endpoints))
	for _, ep := range endpoints {
		start := time.Now()
		success, err := tryEndpointScan(ep, o)
		elapsed := time.Since(start)

		if err != nil {
			resultErr := err.Error()
			switch {
			case isHandshakeErr(err):
				resultErr = fmt.Sprintf("handshake failed: %s", resultErr)
			case errors.Is(err, context.DeadlineExceeded):
				resultErr = fmt.Sprintf("timeout after %s", o.PerIPTimeout)
			}
			results = append(results, Result{
				Endpoint:  ep,
				OK:        false,
				Err:       resultErr,
				Elapsed:   elapsed,
				Transport: transportName(o),
			})
			continue
		}

		results = append(results, Result{
			Endpoint:  ep,
			OK:        success,
			Err:       "",
			Elapsed:   elapsed,
			Transport: transportName(o),
		})
	}

	return results
}

func PickRandomHealthy(results []Result, rnd *rand.Rand) (string, error) {
	healthy := make([]string, 0)
	for _, r := range results {
		if r.OK {
			healthy = append(healthy, r.Endpoint)
		}
	}
	if len(healthy) == 0 {
		return "", fmt.Errorf("no healthy endpoints found")
	}
	if rnd == nil {
		rnd = rand.New(rand.NewSource(rand.Int63()))
	}
	return healthy[rnd.Intn(len(healthy))], nil
}

func transportName(o Options) string {
	if o.UseQUIC {
		return "quic"
	}
	return "tcp-tls"
}

func tryEndpointScan(ep string, o Options) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.PerIPTimeout)
	defer cancel()

	if o.Probe != nil {
		if err := o.Probe(ctx, ep, o); err != nil {
			return false, err
		}
		return true, nil
	}

	if err := defaultProbe(ctx, ep, o); err != nil {
		return false, err
	}
	return true, nil
}

func defaultProbe(ctx context.Context, ep string, o Options) error {
	if o.UseQUIC {
		tconf := cloneTLS(o.TLSConfig)

		if isHostPort(ep) {
			host, _ := splitHostPort(ep)
			if net.ParseIP(host) == nil && tconf.ServerName == "" {
				tconf.ServerName = host
			}
		}

		sess, err := quic.DialAddr(ctx, ep, tconf, o.QUICConfig)
		if err != nil {
			return err
		}
		_ = sess.CloseWithError(0, "")
		return nil
	}

	d := &net.Dialer{Timeout: o.PerIPTimeout}
	conn, err := tls.DialWithDialer(d, "tcp", ep, o.TLSConfig)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func isHostPort(s string) bool {
	_, _, err := net.SplitHostPort(s)
	return err == nil
}

func splitHostPort(s string) (string, string) {
	h, p, _ := net.SplitHostPort(s)
	return h, p
}

func cloneTLS(c *tls.Config) *tls.Config {
	if c == nil {
		return &tls.Config{}
	}
	cp := *c
	return &cp
}
