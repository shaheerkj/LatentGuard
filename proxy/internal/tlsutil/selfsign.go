// Package tlsutil provides certificate loading for the proxy's HTTPS listener.
//
// Module 1 / FE-2 (TLS termination): the proxy must terminate TLS so it can
// inspect the plaintext request before forwarding to the upstream. We support
// two paths:
//
//  1. Operator-supplied cert + key via PROXY_TLS_CERT / PROXY_TLS_KEY env vars.
//     Used in production where a real CA-signed cert is mounted into the
//     container.
//
//  2. Self-signed in-memory cert generated at boot. Used for the FYP demo so
//     the panel can connect over HTTPS without any setup step. The cert is
//     valid for `localhost` and `127.0.0.1` only and lives for 24 hours,
//     which is plenty for a demo and avoids accidentally leaving a long-lived
//     self-signed cert on disk.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// Load returns a tls.Certificate from the supplied cert/key file paths if both
// are non-empty and exist on disk. Otherwise it generates a fresh self-signed
// cert in memory.
func Load(certFile, keyFile string) (tls.Certificate, string, error) {
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			if _, err := os.Stat(keyFile); err == nil {
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					return tls.Certificate{}, "", fmt.Errorf("load %s/%s: %w", certFile, keyFile, err)
				}
				return cert, "operator-supplied", nil
			}
		}
	}
	cert, err := selfSign()
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("self-sign: %w", err)
	}
	return cert, "self-signed (demo)", nil
}

func selfSign() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"LatentGuard FYP demo"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}
