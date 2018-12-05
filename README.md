p12gen
======

### Examples


#### Generate private p12 cert and sign by ca cert

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


#### Combine pem cert and key into p12

```
package main

import (
	"fmt"
	"io/ioutil"

	"github.com/gogap/p12gen"
)

func main() {
	var err error

	defer func() {
		if err != nil {
			fmt.Println("ERR:", err)
			return
		}
	}()

	certData, err := ioutil.ReadFile("zeal.crt")
	if err != nil {
		return
	}

	keyData, err := ioutil.ReadFile("zeal.key")
	if err != nil {
		return
	}

	p12Data, err := p12gen.PEMToP12(certData, keyData, "111111", "123456")
	if err != nil {
		return
	}

	ioutil.WriteFile("zeal.p12", p12Data, 0644)
}

```


### Tips

if your key file have password, it should be looks like:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-CBC,4A831344AE3B61AF

NIa85byEwKQ4QZSJOWMNe8SMbqXLPCVAGbWIOgMQZ/OjWF3A/ZzD0C4JlmUpuDM+
b7+UGuh//obxPJEEn9W93g0zDJnmXCv1co5xbBgZ/zK0vpiQTCsNWOz9vl6u5Wzs
......
-----END RSA PRIVATE KEY-----
```

> It must be have headers

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
