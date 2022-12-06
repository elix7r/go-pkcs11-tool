package internal

import (
	"fmt"
	"os"

	"github.com/infotecs-go-cryptohsm/pkg"
	"github.com/miekg/pkcs11"
)

func ImportCert(session pkcs11.SessionHandle, p *pkcs11.Ctx) {
	cert, err := pkg.LoadCert("./out/localhost.crt")
	if err != nil {
		panic(err)
	}

	certBytes, err := os.ReadFile("Certificate.der")
	if err != nil {
		panic(err)
	}

	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),      // класс - сертификат
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509), // certyficate type - X.509
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),                        // Сертификат является объектом токена
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, certBytes),                   // Значение сертификата (заполняется в процессе работы)
		pkcs11.NewAttribute(pkcs11.CKA_ID, cert.SubjectKeyId),
		// pkcs11.NewAttribute(pkcs11.CKA_ID, "12345243"),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.Subject.String()),
	}

	oh, err := p.CreateObject(session, certTemplate)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Object created: %x %x\n", oh, cert.SubjectKeyId)
}
