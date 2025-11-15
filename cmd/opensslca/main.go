package main

import (
	"fmt"

	"github.com/ArtemVoronov/openssl-ca/internal/openssl"
)

func main() {
	err := openssl.InitCa("/Users/voronov/Temp/openssl_testing/ca1")
	if err != nil {
		fmt.Printf("error: %v", err)
	}
}
