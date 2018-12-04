p12gen
======

### Example

```go
package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/gogap/p12gen"
	"github.com/gogap/p12gen/template"
)

func OnGenerateCallback(err error, caName string, certTemplate *x509.Certificate, p12Data []byte, p12Password string) {
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(p12Password)
	ioutil.WriteFile("zeal.p12", p12Data, 0644)
}

func main() {
	var err error

	defer func() {
		if err != nil {
			fmt.Println("ERR:", err)
			return
		}
	}()

	gen := p12gen.NewP12Gen()

	caFile, err := ioutil.ReadFile("ca-cert.pem")
	if err != nil {
		return
	}

	keyFile, err := ioutil.ReadFile("ca-cert.key")
	if err != nil {
		return
	}

	err = gen.LoadCA("gogap-ca-1", caFile, keyFile)

	if err != nil {
		return
	}

	tmpl, err := template.NewClientSideAuthCertTmpl()

	if err != nil {
		return
	}

	certTmpl, err := tmpl.Generate(
		p12gen.CommonName("zeal"),
		p12gen.Country("CN"),
		p12gen.Organization("GoGap"),
		p12gen.OrganizationalUnit("GoGap R&D Center"),
		p12gen.Province("Beijing"),
		p12gen.Locality("Beijing"),
	)

	if err != nil {
		return
	}

	gen.CreateCertificateAsync("gogap-ca-1", "123456", certTmpl, OnGenerateCallback)

	time.Sleep(time.Second)
}


```


### Tips

**Add password for rsa key**

```bash
$ openssl rsa -des -in ca-cert-nopassword.key -out ca-cert.key
```

**Remove password for encryped private key**

```bash
$ openssl rsa -in ca-cert.key -out ca-cert-nopassword.key
```


#### packages forked

`pkcs12` is forked from `https://github.com/SSLMate/go-pkcs12`
