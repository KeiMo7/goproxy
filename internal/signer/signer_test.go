package signer_test

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/internal/signer"
)

func orFatal(t *testing.T, msg string, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(msg, err)
	}
}

type ConstantHanlder string

func (h ConstantHanlder) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, string(h))
}

func testSignerX509(t *testing.T, ca tls.Certificate) {
	t.Helper()
	cert, err := signer.SignHost(ca, []string{"example.com", "1.1.1.1", "localhost"})
	orFatal(t, "singHost", err)
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	orFatal(t, "ParseCertificate", err)
	certpool := x509.NewCertPool()
	certpool.AddCert(ca.Leaf)
	orFatal(t, "VerifyHostname", cert.Leaf.VerifyHostname("example.com"))
	orFatal(t, "CheckSignatureFrom", cert.Leaf.CheckSignatureFrom(ca.Leaf))
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   certpool,
	})
	orFatal(t, "Verify", err)
}

func testSignerTLS(t *testing.T, ca tls.Certificate) {
	t.Helper()
	cert, err := signer.SignHost(ca, []string{"example.com", "1.1.1.1", "localhost"})
	orFatal(t, "singHost", err)
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	orFatal(t, "ParseCertificate", err)
	expected := "key verifies with Go"
	server := httptest.NewUnstartedServer(ConstantHanlder(expected))
	defer server.Close()
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert, ca},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	certpool := x509.NewCertPool()
	certpool.AddCert(ca.Leaf)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certpool},
	}
	asLocalhost := strings.ReplaceAll(server.URL, "127.0.0.1", "localhost")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, asLocalhost, nil)
	orFatal(t, "NewRequest", err)
	resp, err := tr.RoundTrip(req)
	orFatal(t, "RoundTrip", err)
	txt, err := io.ReadAll(resp.Body)
	orFatal(t, "io.ReadAll", err)
	if string(txt) != expected {
		t.Errorf("Expected '%s' got '%s'", expected, string(txt))
	}
}

func TestSignerRsaTls(t *testing.T) {
	testSignerTLS(t, goproxy.GoproxyCa)
}

func TestSignerRsaX509(t *testing.T) {
	testSignerX509(t, goproxy.GoproxyCa)
}

// TestSignHostSerialDeterministic locks the contract that the serial number
// is derived from the CA-derived CSPRNG rather than the global random source,
// so it is stable for a fixed (CA, hosts) pair and distinct across hosts.
//
// Full leaf-key determinism additionally requires GODEBUG=cryptocustomrand=1:
// since Go 1.26, rsa/ecdsa/ed25519 key generation ignores a custom entropy
// reader by default. The cert cache still guarantees that within a process
// every handshake for a target reuses the one issued certificate, which is
// what fingerprint pinning actually observes. See TestSignHostFullyDeterministic
// for the GODEBUG-enabled path.
func TestSignHostSerialDeterministic(t *testing.T) {
	for name, ca := range map[string]tls.Certificate{"rsa": goproxy.GoproxyCa, "ecdsa": EcdsaCa} {
		t.Run(name, func(t *testing.T) {
			first, err := signer.SignHost(ca, []string{"deterministic.example"})
			orFatal(t, "first SignHost", err)
			second, err := signer.SignHost(ca, []string{"deterministic.example"})
			orFatal(t, "second SignHost", err)
			if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
				t.Fatalf("%s serial differs: %v vs %v", name,
					first.Leaf.SerialNumber, second.Leaf.SerialNumber)
			}
			if first.Leaf.Subject.CommonName != "deterministic.example" {
				t.Fatalf("unexpected CN: %q", first.Leaf.Subject.CommonName)
			}
			other, err := signer.SignHost(ca, []string{"other.example"})
			orFatal(t, "other SignHost", err)
			if other.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
				t.Fatal("distinct hosts produced the same serial number")
			}
		})
	}
}

// TestSignHostFullyDeterministic runs only when the platform honors a custom
// entropy reader (GODEBUG=cryptocustomrand=1), asserting both the serial and
// the leaf key are reproducible for a fixed (CA, hosts) pair.
func TestSignHostFullyDeterministic(t *testing.T) {
	if os.Getenv("GODEBUG_DETERMINISTIC") != "1" {
		t.Skip("set GODEBUG_DETERMINISTIC=1 together with GODEBUG=cryptocustomrand=1 to run")
	}
	ca := goproxy.GoproxyCa
	first, err := signer.SignHost(ca, []string{"deterministic.example"})
	orFatal(t, "first SignHost", err)
	second, err := signer.SignHost(ca, []string{"deterministic.example"})
	orFatal(t, "second SignHost", err)
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatalf("serial differs: %v vs %v",
			first.Leaf.SerialNumber, second.Leaf.SerialNumber)
	}
	if !first.Leaf.PublicKey.(interface{ Equal(x crypto.PublicKey) bool }).
		Equal(second.Leaf.PublicKey) {
		t.Fatal("leaf public key differs despite cryptocustomrand=1")
	}
}

func TestSignerEcdsaTls(t *testing.T) {
	testSignerTLS(t, EcdsaCa)
}

func TestSignerEcdsaX509(t *testing.T) {
	testSignerX509(t, EcdsaCa)
}

func BenchmarkSignRsa(b *testing.B) {
	var cert *tls.Certificate
	var err error
	for n := 0; n < b.N; n++ {
		cert, err = signer.SignHost(goproxy.GoproxyCa, []string{"example.com", "1.1.1.1", "localhost"})
	}
	_ = cert
	_ = err
}

func BenchmarkSignEcdsa(b *testing.B) {
	var cert *tls.Certificate
	var err error
	for n := 0; n < b.N; n++ {
		cert, err = signer.SignHost(EcdsaCa, []string{"example.com", "1.1.1.1", "localhost"})
	}
	_ = cert
	_ = err
}

//
// Eliptic Curve certificate and key for testing
//

var EcdsaCaCert = []byte(`-----BEGIN CERTIFICATE-----
MIICGDCCAb8CFEkSgqYhlT0+Yyr9anQNJgtclTL0MAoGCCqGSM49BAMDMIGOMQsw
CQYDVQQGEwJJTDEPMA0GA1UECAwGQ2VudGVyMQwwCgYDVQQHDANMb2QxEDAOBgNV
BAoMB0dvUHJveHkxEDAOBgNVBAsMB0dvUHJveHkxGjAYBgNVBAMMEWdvcHJveHku
Z2l0aHViLmlvMSAwHgYJKoZIhvcNAQkBFhFlbGF6YXJsQGdtYWlsLmNvbTAeFw0x
OTA1MDcxMTUwMThaFw0zOTA1MDIxMTUwMThaMIGOMQswCQYDVQQGEwJJTDEPMA0G
A1UECAwGQ2VudGVyMQwwCgYDVQQHDANMb2QxEDAOBgNVBAoMB0dvUHJveHkxEDAO
BgNVBAsMB0dvUHJveHkxGjAYBgNVBAMMEWdvcHJveHkuZ2l0aHViLmlvMSAwHgYJ
KoZIhvcNAQkBFhFlbGF6YXJsQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABDlH4YrdukPFAjbO8x+gR9F8ID7eCU8Orhba/MIblSRrRVedpj08lK+2
svyoAcrcDsynClO9aQtsC9ivZ+Pmr3MwCgYIKoZIzj0EAwMDRwAwRAIgGRSSJVSE
1b1KVU0+w+SRtnR5Wb7jkwnaDNxQ3c3FXoICIBJV/l1hFM7mbd68Oi5zLq/4ZsrL
98Bb3nddk2xys6a9
-----END CERTIFICATE-----`)

var EcdsaCaKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEsc8m+2aZfagnesg
qMgXe8ph4LtVu2VOUYhHttuEDsChRANCAAQ5R+GK3bpDxQI2zvMfoEfRfCA+3glP
Dq4W2vzCG5Uka0VXnaY9PJSvtrL8qAHK3A7MpwpTvWkLbAvYr2fj5q9z
-----END PRIVATE KEY-----`)

var EcdsaCa, ecdsaCaErr = tls.X509KeyPair(EcdsaCaCert, EcdsaCaKey)

func init() {
	if ecdsaCaErr != nil {
		panic("Error parsing ecdsa CA " + ecdsaCaErr.Error())
	}
	var err error
	if EcdsaCa.Leaf, err = x509.ParseCertificate(EcdsaCa.Certificate[0]); err != nil {
		panic("Error parsing ecdsa CA " + err.Error())
	}
}
