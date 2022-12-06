package internal

import (
	"fmt"
	"os"

	"github.com/infotecs-go-cryptohsm/pkg"
	"github.com/miekg/pkcs11"
)

func ImportPrivKey(session pkcs11.SessionHandle, p *pkcs11.Ctx) {
	cert, err := pkg.LoadCert("./out/localhost.crt")
	if err != nil {
		panic(err)
	}

	keyBytes, err := os.ReadFile("PrivateKey.der")
	if err != nil {
		panic(err)
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "wrappriv1"), // temp label
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_ID, cert.SubjectKeyId),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, keyBytes),
	}

	oh, err := p.CreateObject(session, privateKeyTemplate)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Object created: %v", oh)
}
