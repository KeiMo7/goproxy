package upstream

import (
	"crypto/x509"
	"testing"
)

// GoproxyCaForTest returns a fresh self-signed certificate usable as a root.
func GoproxyCaForTest(t *testing.T) *x509.Certificate {
	t.Helper()
	return generateTestCert(t, "root.example")
}
