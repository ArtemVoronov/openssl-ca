package main

import (
	"fmt"

	"github.com/ArtemVoronov/openssl-ca/internal/openssl"
)

func main() {
	caPath := "/Users/voronov/Temp/openssl_testing/test_ca"
	password := "password"
	subject := "/CN=Example Root CA"
	err := openssl.InitCa(caPath, password, subject)
	if err != nil {
		fmt.Printf("error: %v", err)
	}
}
