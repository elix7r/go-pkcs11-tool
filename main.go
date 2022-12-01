package main

import (
	"fmt"
	// "log"
	// "os"

	"github.com/infotecs-go-cryptohsm/internal"
	"github.com/infotecs-go-cryptohsm/internal/config"
	"github.com/miekg/pkcs11"
)

func main() {
	p := pkcs11.New(config.GetConfig().Module)
	err := p.Initialize()
	if err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil {
		panic(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, config.GetConfig().UserPin)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	info, err := p.GetInfo()
	if err != nil {
		panic(err)
	}
	fmt.Printf("CryptokiVersion.Major %v\n", info.CryptokiVersion.Major)

	// cert, err := os.ReadFile("./out/localhost.crt")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// internal.ImportCert(session, p, cert)
	// fmt.Printf("Certificate has been created successfully\n")
	internal.ImportKeyPair(session, p, config.GetConfig())
	fmt.Println("Objects created")
}
