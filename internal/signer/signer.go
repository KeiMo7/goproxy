// Package signer creates short-lived leaf certificates for intercepted TLS
// targets, signed by the proxy CA.
//
// Entropy for both the leaf key and the serial number is drawn from a
// deterministic, CA-key-derived stream (CounterEncryptorRand), rather than the
// process-global random source. The serial number is therefore reproducible
// for a fixed (CA, hosts) pair.
//
// Reproducibility of the leaf private key additionally depends on the
// platform: starting with Go 1.26, rsa/ecdsa/ed25519 key generation ignores a
// caller-supplied entropy reader unless GODEBUG=cryptocustomrand=1 is set.
// When that flag is not set, leaf keys are random even though serial numbers
// stay deterministic. In all configurations the certificate cache guarantees
// that within a process every handshake for a target reuses the single issued
// certificate, which is what fingerprint and serial pinning observes.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"sort"
	"strings"
	"time"
)

const _goproxySignerVersion = ":goproxy3"

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha256.New()
	h.Write([]byte(strings.Join(c, ",")))
	return h.Sum(nil)
}

func SignHost(ca tls.Certificate, hosts []string) (cert *tls.Certificate, err error) {
	// Use the provided CA for certificate generation.
	// Use already parsed Leaf certificate when present.
	x509ca := ca.Leaf
	if x509ca == nil {
		if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
			return nil, err
		}
	}

	now := time.Now()
	start := now.Add(-30 * 24 * time.Hour) // -30 days
	end := now.Add(365 * 24 * time.Hour)   // 365 days

	hash := hashSorted(append(hosts, _goproxySignerVersion, ":"+runtime.Version()))
	var csprng CounterEncryptorRand
	if csprng, err = NewCounterEncryptorRandFromKey(ca.PrivateKey, hash); err != nil {
		return nil, err
	}

	// Derive the serial number from the same deterministic, key-derived
	// stream used for the leaf key, instead of the global math/rand source.
	// For a fixed (CA, hosts) pair the serial and the leaf key are therefore
	// stable across calls, so repeated handshakes present an identical
	// certificate to clients that pin the fingerprint or serial number.
	// Always generate a positive int value
	// (Two complement is not enabled when the first bit is 0)
	serialBytes := make([]byte, 8)
	if _, err = io.ReadFull(&csprng, serialBytes); err != nil {
		return nil, err
	}
	serialBytes[0] &= 0x7f

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes),
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization: []string{"GoProxy untrusted MITM proxy Inc"},
		},
		NotBefore: start,
		NotAfter:  end,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.Subject.CommonName = h
		}
	}

	var certpriv crypto.Signer
	switch ca.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if certpriv, err = rsa.GenerateKey(&csprng, 2048); err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		if certpriv, err = ecdsa.GenerateKey(elliptic.P256(), &csprng); err != nil {
			return nil, err
		}
	case ed25519.PrivateKey:
		if _, certpriv, err = ed25519.GenerateKey(&csprng); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported key type %T", ca.PrivateKey)
	}

	derBytes, err := x509.CreateCertificate(&csprng, &template, x509ca, certpriv.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Save an already parsed leaf certificate to use less CPU
	// when it will be used
	leafCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	certBytes := make([][]byte, 1+len(ca.Certificate))
	certBytes[0] = derBytes
	for i, singleCertBytes := range ca.Certificate {
		certBytes[i+1] = singleCertBytes
	}

	return &tls.Certificate{
		Certificate: certBytes,
		PrivateKey:  certpriv,
		Leaf:        leafCert,
	}, nil
}
