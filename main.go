package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
)

func main() {
	fmt.Println("Hello, World!")
	fmt.Println(ecc.BN254.String())
}
