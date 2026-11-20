package goproxy

import (
	"crypto/tls"

	"github.com/elazarl/goproxy/internal/signer"
)

// signHostShim invokes the internal signer through the exact code path used
// by TLSConfigFromCA. It exists only for package-internal tests.
func signHostShim(ca tls.Certificate, host string) (*tls.Certificate, error) {
	return signer.SignHost(ca, []string{host})
}
