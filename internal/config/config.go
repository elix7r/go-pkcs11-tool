package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/infotecs-go-cryptohsm/pkg"
)

type Config struct {
	Module    string
	SlotID   uint
	UserPin  string
	KeyLabel string
	KeyID    string
	RSAsise  uint
}

func GetConfig() (config Config) {
	random_id, _ := pkg.RandomKeyID()
	config = Config{"/usr/lib/softhsm/libsofthsm.so", //module
		0,                     //slot_id
		"1234",                //user_pin
		"pkcs11keypair_label", //key_label
		random_id,             //key_id
		2048,                  //rsa_size
	}

	if len(os.Getenv("HSM_MODULE")) > 0 {
		config.Module = os.Getenv("HSM_MODULE")
	}

	if len(os.Getenv("HSM_SLOT_ID")) > 0 {
		env_slot_id, _ := strconv.ParseUint(os.Getenv("HSM_SLOT_ID"), 10, 0)
		config.SlotID = uint(env_slot_id)
	}

	if len(os.Getenv("USER_PIN")) > 0 {
		config.UserPin = os.Getenv("USER_PIN")
	}

	if len(os.Getenv("KEY_LABEL")) > 0 {
		config.KeyLabel = os.Getenv("KEY_LABEL")
	}

	if len(os.Getenv("KEY_ID")) > 0 {
		config.KeyID = os.Getenv("KEY_ID")
	}

	if len(os.Getenv("RSA_SIZE")) > 0 {
		env_rsa_size, _ := strconv.ParseUint(os.Getenv("RSA_SIZE"), 10, 0)
		config.RSAsise = uint(env_rsa_size)
	}
	fmt.Printf("Using module %s, ", config.Module)
	fmt.Printf("slot ID %v, ", config.SlotID)
	fmt.Printf("user PIN %v, ", config.UserPin)
	fmt.Printf("key id '%v', ", config.KeyID)
	fmt.Printf("key label '%s', ", config.KeyLabel)
	fmt.Printf("rsa bit size %v.\n", config.RSAsise)

	if config.RSAsise < 1024 {
		fmt.Printf("RSA size insecure, choose 1024 or more.\n")
		os.Exit(1)
	}
	return config
}
