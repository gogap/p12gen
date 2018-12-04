package p12gen

import (
	"crypto/x509"
	"math/big"
	"net"
	"time"
)

type CertOption func(cert *x509.Certificate) (err error)

type CertTemplater interface {
	Generate(opts ...CertOption) (certTemplate *x509.Certificate, err error)
}

func NotAfter(t time.Time) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.NotAfter = t
		return
	}
}

func NotBefore(t time.Time) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.NotBefore = t
		return
	}
}

func SerialNumber(sn int64) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.SerialNumber = big.NewInt(sn)
		return
	}
}

func CommonName(cn string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.Subject.CommonName = cn
		return
	}
}

func EmailAddresses(emails ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.EmailAddresses = emails
		return
	}
}

func DNSNames(dnsNames ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.DNSNames = dnsNames
		return
	}
}

func Country(v ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.Subject.Country = v
		return
	}
}

func Organization(v ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.Subject.Organization = v
		return
	}
}

func OrganizationalUnit(v ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.Subject.OrganizationalUnit = v
		return
	}
}

func Province(v ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.Subject.Province = v
		return
	}
}

func CRLDistributionPoints(v ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.CRLDistributionPoints = v
		return
	}
}

func IssuingCertificateURL(v ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.IssuingCertificateURL = v
		return
	}
}

func SignatureAlgorithm(alog x509.SignatureAlgorithm) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.SignatureAlgorithm = alog
		return
	}
}

func Locality(v ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		c.Subject.Locality = v
		return
	}
}

func IPAddresses(ipAddresses ...string) CertOption {
	return func(c *x509.Certificate) (err error) {
		var ips []net.IP

		for _, ip := range ipAddresses {
			netIP := net.ParseIP(ip)
			ips = append(ips, netIP)
		}

		c.IPAddresses = ips

		return
	}
}
