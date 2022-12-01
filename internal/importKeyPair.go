package internal

import (
	"github.com/infotecs-go-cryptohsm/internal/config"
	"github.com/miekg/pkcs11"
)

func ImportKeyPair(session pkcs11.SessionHandle, p *pkcs11.Ctx, config config.Config) {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, config.RSAsise),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{3}),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, config.KeyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, config.KeyID),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, "/CN=Harald Wagener"),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, config.KeyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, config.KeyID),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, "/CN=Harald Wagener"),
	}

	p.CreateObject(session, publicKeyTemplate)
	p.CreateObject(session, privateKeyTemplate)
}
