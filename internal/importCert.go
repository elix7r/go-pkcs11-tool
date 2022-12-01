package internal

import (
	"github.com/miekg/pkcs11"
)

func ImportCert(session pkcs11.SessionHandle, p *pkcs11.Ctx) {
	certificateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),                             // Значение сертификата (заполняется в процессе работы)
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),          // класс - сертификат
		pkcs11.NewAttribute(pkcs11.CKA_ID, pkcs11.CKK_RSA),                     // Идентификатор сертификата (совпадает с идентификатором соотвествующего ключа)
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),                            // Сертификат является объектом токена
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),                         // Сертификат доступен без аутентификации
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKM_RSA_X_509), // тип сертификата x.509
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_CATEGORY, 1),                // категория сертификата - пользовательский
	}

	_, err := p.CreateObject(session, certificateTemplate)
	if err != nil {
		panic(err)
	}
}
