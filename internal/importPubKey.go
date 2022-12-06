package internal

import (
	"fmt"
	"os"

	"github.com/infotecs-go-cryptohsm/pkg"
	"github.com/miekg/pkcs11"
)

func ImportPubKey(session pkcs11.SessionHandle, p *pkcs11.Ctx) {
	publicKey := pkg.LoadPubKey("localhostPub.key")

	cert, err := pkg.LoadCert("./out/localhost.crt")
	if err != nil {
		panic(err)
	}

	keyBytes, err := os.ReadFile("PublicKey.der")
	if err != nil {
		panic(err)
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, publicKey.Size()),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "wrappub1"),     // temp label
		pkcs11.NewAttribute(pkcs11.CKA_ID, cert.SubjectKeyId), // temp id
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, keyBytes),
	}

	oh, err := p.CreateObject(session, publicKeyTemplate)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Object created: %v %x\n", oh, cert.SubjectKeyId)
}
