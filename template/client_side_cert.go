package template

import (
	"crypto/x509"
	"math/big"
	"time"

	"github.com/gogap/p12gen"
)

type ClientSideAuthCertTmpl struct {
}

func NewClientSideAuthCertTmpl() (tmpl p12gen.CertTemplater, err error) {
	return &ClientSideAuthCertTmpl{}, nil
}

func (p *ClientSideAuthCertTmpl) Generate(opts ...p12gen.CertOption) (certTemplate *x509.Certificate, err error) {

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),

		BasicConstraintsValid: true,
		IsCA:        false,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,

		SignatureAlgorithm: x509.SHA512WithRSA,
	}

	for i := 0; i < len(opts); i++ {
		err = opts[i](cert)

		if err != nil {
			return
		}
	}

	certTemplate = cert

	return
}
