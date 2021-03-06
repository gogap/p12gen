package p12gen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/chr4/pwgen"
	"github.com/gogap/p12gen/pkcs12"
)

type CA struct {
	name  string
	certs []*x509.Certificate
	key   []byte
}

type PasswordGenerateFunc func() string

type CallbackFunc func(err error, caName string, certTemplate *x509.Certificate, p12Data []byte, p12Password string)

func (p *CA) Count() int {
	return len(p.certs)
}

type P12Gen struct {
	caList map[string]*CA
	pwdGen PasswordGenerateFunc
}

func NewP12Gen() *P12Gen {
	return &P12Gen{
		caList: make(map[string]*CA),
		pwdGen: func() string { return pwgen.AlphaNum(20) },
	}
}

func (p *P12Gen) WithPwdGenerator(fn PasswordGenerateFunc) {
	p.pwdGen = fn
}

func (p *P12Gen) LoadCA(name string, certData, keyData []byte) (err error) {

	if _, exist := p.caList[name]; exist {
		err = fmt.Errorf("%s already loaded", name)
		return
	}

	certs, err := loadCerts(certData)

	if err != nil {
		return
	}

	ca := &CA{
		name:  name,
		certs: certs,
		key:   keyData,
	}

	if ca.Count() == 0 {
		err = fmt.Errorf("ca of %s's count is zero", name)
		return
	}

	p.caList[name] = ca

	return
}

func (p *P12Gen) CreateCertificate(caName, caPassword string, certTemplate *x509.Certificate) (p12Data []byte, p12Pwd string, err error) {

	ca, exist := p.caList[caName]

	if !exist {
		err = fmt.Errorf("ca of %s not exist", caName)
		return
	}

	pemBlock, _ := pem.Decode(ca.key)

	var keyData = pemBlock.Bytes

	if x509.IsEncryptedPEMBlock(pemBlock) {
		keyData, err = x509.DecryptPEMBlock(pemBlock, []byte(caPassword))

		if err != nil {
			return
		}
	}

	caKey, err := parsePrivateKey(keyData)
	if err != nil {
		return
	}

	if err != nil {
		return
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	cert, err := x509.CreateCertificate(rand.Reader, certTemplate, ca.certs[0], &certKey.PublicKey, caKey)
	if err != nil {
		return
	}

	x509Cert, err := x509.ParseCertificate(cert)

	if err != nil {
		return
	}

	pwd := ""

	if p.pwdGen != nil {
		pwd = p.pwdGen()
	}

	p12Data, err = pkcs12.Encode(rand.Reader, certKey, x509Cert, nil, pwd)

	if err != nil {
		return
	}

	p12Pwd = pwd

	return
}

func (p *P12Gen) CreateCertificateAsync(caName, caPassword string, certTemplate *x509.Certificate, callbacks ...CallbackFunc) {
	go func(caName, caPassword string, certTemplate *x509.Certificate, callbacks ...CallbackFunc) {

		p12Data, p12Password, err := p.CreateCertificate(caName, caPassword, certTemplate)

		for i := 0; i < len(callbacks); i++ {
			callbacks[i](err, caName, certTemplate, p12Data, p12Password)
		}

	}(caName, caPassword, certTemplate, callbacks...)
}

func PEMToP12(certData, keyData []byte, keyPassword, p12Password string) (p12Data []byte, err error) {

	certs, err := loadCerts(certData)
	if err != nil {
		return
	}

	if len(certs) == 0 {
		err = errors.New("none cert parsed")
		return
	}

	keyPEMBlock, _ := pem.Decode(keyData)

	if keyPEMBlock == nil || len(keyPEMBlock.Bytes) == 0 {
		err = errors.New("parse key file data failure")
		return
	}

	keyBytes := keyPEMBlock.Bytes

	if x509.IsEncryptedPEMBlock(keyPEMBlock) {
		keyBytes, err = x509.DecryptPEMBlock(keyPEMBlock, []byte(keyPassword))
		if err != nil {
			return
		}
	}

	privateKey, err := parsePrivateKey(keyBytes)
	if err != nil {
		return
	}

	p12Data, err = pkcs12.Encode(rand.Reader, privateKey, certs[0], nil, p12Password)

	if err != nil {
		return
	}

	return
}

func loadCerts(data []byte) (certs []*x509.Certificate, err error) {
	var pemDatas []byte

	for {

		block, rest := pem.Decode(data)

		pemDatas = append(pemDatas, block.Bytes...)

		if len(rest) == 0 {
			break
		}

		data = rest
	}

	parsedCerts, err := x509.ParseCertificates(pemDatas)
	if err != nil {
		return
	}

	certs = parsedCerts

	return
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("p12gen: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("p12gen: failed to parse private key")
}
