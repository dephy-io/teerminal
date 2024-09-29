package main

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func main() {
	// Generate 256bit secp256k1 key
	privateKey, _ := secp256k1.GeneratePrivateKey()
	// Print private key in hex format without 0x prefix
	fmt.Printf("%x", privateKey.Serialize())
}
